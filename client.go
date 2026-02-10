package main

import (
    "bufio"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "net"
    "os"
    "strings"
    "sync"
    "syscall"

    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/hkdf"
    "golang.org/x/crypto/ssh/terminal"
)

type Message struct {
    Type            string `json:"type"`
    Username        string `json:"username,omitempty"`
    Target          string `json:"target,omitempty"`
    Content         string `json:"content,omitempty"`
    PubKey          string `json:"public_key,omitempty"`
    ServerPassword  string `json:"server_password,omitempty"`
    EphemeralPubKey string `json:"ephemeral_pub_key,omitempty"`
    Nonce           string `json:"nonce,omitempty"`
    Ciphertext      string `json:"ciphertext,omitempty"`
}

type User struct {
    Username string `json:"username"`
    Key      string `json:"key"`
}

type UserList struct {
    Type  string `json:"type"`
    Users []User `json:"users"`
}

type Identity struct {
    PrivKey string `json:"priv_key"`
    PubKey  string `json:"pub_key"`
}

var (
    privKey         [32]byte
    pubKey          [32]byte
    knownKeys       = make(map[string][32]byte)
    keysMtx         sync.RWMutex
    serverConn      net.Conn
    FINGERPRINT_FILE = "known_hosts.txt"
    IDENTITY_FILE    = "identity.json"
)

func selfDestruct(reason string) {
    fmt.Printf("\n[!!! %s !!!]\n", reason)
    os.Remove(IDENTITY_FILE)
    os.Remove(FINGERPRINT_FILE)
    keysMtx.Lock()
    knownKeys = nil
    keysMtx.Unlock()
    if serverConn != nil {
        serverConn.Close()
    }
    fmt.Println("[CLIENT] Securely shutdown")
    os.Exit(1)
}

func loadOrGenerateKeys() error {
    if _, err := os.Stat(IDENTITY_FILE); err == nil {
        data, err := os.ReadFile(IDENTITY_FILE)
        if err != nil {
            return err
        }
        var id Identity
        if err := json.Unmarshal(data, &id); err != nil {
            return err
        }
        privBytes, _ := base64.StdEncoding.DecodeString(id.PrivKey)
        pubBytes, _ := base64.StdEncoding.DecodeString(id.PubKey)
        if len(privBytes) != 32 || len(pubBytes) != 32 {
            return fmt.Errorf("invalid key length")
        }
        copy(privKey[:], privBytes)
        copy(pubKey[:], pubBytes)
        fmt.Println("[SYSTEM] Loaded X25519 keys from identity.json")
        return nil
    }

    fmt.Println("[SYSTEM] No identity found. Generating new X25519 keys...")
    rand.Read(privKey[:])
    curve25519.ScalarBaseMult(&pubKey, &privKey)

    id := Identity{
        PrivKey: base64.StdEncoding.EncodeToString(privKey[:]),
        PubKey:  base64.StdEncoding.EncodeToString(pubKey[:]),
    }
    data, _ := json.MarshalIndent(id, "", "  ")
    return os.WriteFile(IDENTITY_FILE, data, 0600)
}

func encryptMessage(msg string, recipientPubKey [32]byte) (*Message, error) {
    var ephemeralPriv, ephemeralPub [32]byte
    rand.Read(ephemeralPriv[:])
    curve25519.ScalarBaseMult(&ephemeralPub, &ephemeralPriv)

    var sharedSecret [32]byte
    // FIX: ScalarMult does not return a value, it writes directly to the first argument
    curve25519.ScalarMult(&sharedSecret, &ephemeralPriv, &recipientPubKey)

    hkdfInput := append(append(sharedSecret[:], ephemeralPub[:]...), recipientPubKey[:]...)
    hkdfReader := hkdf.New(sha256.New, hkdfInput, nil, []byte("X25519-AES-GCM"))
    aesKey := make([]byte, 32)
    if _, err := hkdfReader.Read(aesKey); err != nil {
        return nil, fmt.Errorf("HKDF failed: %v", err)
    }

    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)
    ciphertext := gcm.Seal(nil, nonce, []byte(msg), nil)

    return &Message{
        Type:            "encrypted_msg",
        EphemeralPubKey: base64.StdEncoding.EncodeToString(ephemeralPub[:]),
        Nonce:           base64.StdEncoding.EncodeToString(nonce),
        Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
    }, nil
}

func decryptMessage(msg *Message, senderPubKey [32]byte) (string, error) {
    ephemeralPubBytes, _ := base64.StdEncoding.DecodeString(msg.EphemeralPubKey)
    if len(ephemeralPubBytes) != 32 {
        return "", fmt.Errorf("invalid ephemeral key length")
    }
    var ephemeralPub [32]byte
    copy(ephemeralPub[:], ephemeralPubBytes)

    var sharedSecret [32]byte
    // FIX: ScalarMult does not return a value, it writes directly to the first argument
    curve25519.ScalarMult(&sharedSecret, &privKey, &ephemeralPub)

    hkdfInput := append(append(sharedSecret[:], ephemeralPub[:]...), senderPubKey[:]...)
    hkdfReader := hkdf.New(sha256.New, hkdfInput, nil, []byte("X25519-AES-GCM"))
    aesKey := make([]byte, 32)
    if _, err := hkdfReader.Read(aesKey); err != nil {
        return "", fmt.Errorf("HKDF failed: %v", err)
    }

    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce, _ := base64.StdEncoding.DecodeString(msg.Nonce)
    ciphertext, _ := base64.StdEncoding.DecodeString(msg.Ciphertext)
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", fmt.Errorf("decryption failed: %v", err)
    }
    return string(plaintext), nil
}

func getFingerprint(pubKeyBytes [32]byte) string {
    h := sha256.Sum256(pubKeyBytes[:])
    return hex.EncodeToString(h[:])[:16]
}

func verifyFingerprint(username string, pubKeyBytes [32]byte) {
    fp := getFingerprint(pubKeyBytes)
    var lines []string
    var storedFP string
    if data, err := os.ReadFile(FINGERPRINT_FILE); err == nil {
        lines = strings.Split(string(data), "\n")
        for i, line := range lines {
            if strings.HasPrefix(line, username+":") {
                storedFP = strings.TrimPrefix(line, username+":")
                lines = append(lines[:i], lines[i+1:]...)
                break
            }
        }
    }

    if storedFP == "" {
        fmt.Printf("[SECURITY] New key for '%s'. Fingerprint: %s\n", username, fp)
        lines = append(lines, fmt.Sprintf("%s:%s", username, fp))
        writeFingerprintFile(lines)
    } else if storedFP != fp {
        fmt.Printf("\n[!!! WARNING !!!] KEY MISMATCH FOR '%s' !!!\n", username)
        fmt.Printf("[!!! WARNING !!!] Previous: %s\n", storedFP)
        fmt.Printf("[!!! WARNING !!!] Current:  %s\n", fp)
        fmt.Printf("[SECURITY] Updating stored fingerprint...\n")
        lines = append(lines, fmt.Sprintf("%s:%s", username, fp))
        writeFingerprintFile(lines)
    }
}

func writeFingerprintFile(lines []string) {
    f, _ := os.OpenFile(FINGERPRINT_FILE, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
    defer f.Close()
    for _, line := range lines {
        if strings.TrimSpace(line) != "" {
            f.WriteString(line + "\n")
        }
    }
}

func receiveMessages(conn net.Conn, myUsername string) {
    scanner := bufio.NewScanner(conn)
    for scanner.Scan() {
        data := scanner.Bytes()
        var raw map[string]interface{}
        if err := json.Unmarshal(data, &raw); err != nil {
            continue
        }
        msgType, _ := raw["type"].(string)
        if msgType == "SERVER_PANIC" {
            selfDestruct("SERVER PANIC")
        } else if msgType == "SERVER_RESTART" {
            reason, _ := raw["content"].(string)
            fmt.Printf("\n[!!! SERVER RESTART !!!] %s\n", reason)
            fmt.Println("[CLIENT] Disconnecting... Server will restart automatically.")
            fmt.Println("[CLIENT] Reconnect in 5 seconds to join fresh session.")
            conn.Close()
            os.Exit(0)
        } else if msgType == "auth_success" {
            fmt.Printf("\n[SYSTEM] Authentication successful.\n")
        } else if msgType == "auth_failed" {
            reason, _ := raw["content"].(string)
            fmt.Printf("\n[ACCESS DENIED] %s\n", reason)
            os.Exit(1)
        } else if msgType == "user_list" {
            fmt.Println("\n[SYSTEM] Online Users:")
            var ul UserList
            json.Unmarshal(data, &ul)
            for _, u := range ul.Users {
                fmt.Printf(" - %s\n", u.Username)
                pubBytes, _ := base64.StdEncoding.DecodeString(u.Key)
                if len(pubBytes) == 32 {
                    var pubKey [32]byte
                    copy(pubKey[:], pubBytes)
                    verifyFingerprint(u.Username, pubKey)
                    keysMtx.Lock()
                    knownKeys[u.Username] = pubKey
                    keysMtx.Unlock()
                }
            }
        } else if msgType == "user_joined" {
            user, _ := raw["username"].(string)
            pkStr, _ := raw["public_key"].(string)
            pubBytes, _ := base64.StdEncoding.DecodeString(pkStr)
            if len(pubBytes) == 32 {
                var pubKey [32]byte
                copy(pubKey[:], pubBytes)
                verifyFingerprint(user, pubKey)
                fmt.Printf("\n[SYSTEM] %s joined.\n", user)
                keysMtx.Lock()
                knownKeys[user] = pubKey
                keysMtx.Unlock()
            }
        } else if msgType == "user_left" {
            user, _ := raw["username"].(string)
            fmt.Printf("\n[SYSTEM] %s left.\n", user)
            keysMtx.Lock()
            delete(knownKeys, user)
            keysMtx.Unlock()
        } else if msgType == "encrypted_msg" {
            var msg Message
            json.Unmarshal(data, &msg)
            sender := msg.Username

            keysMtx.RLock()
            senderPubKey, exists := knownKeys[sender]
            keysMtx.RUnlock()

            if !exists {
                fmt.Printf("\n[ERROR] Received message from untrusted user %s\n", sender)
                continue
            }

            txt, err := decryptMessage(&msg, senderPubKey)
            if err != nil {
                fmt.Printf("\n[ERROR] Decryption failed: %v\n", err)
            } else {
                fmt.Printf("\n[Secure Msg from %s]: %s\n", sender, txt)
            }
        }

        fmt.Printf("[%s]: ", myUsername)
    }
}

func main() {
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Enter Server IP:Port (e.g., 127.0.0.1:8443): ")
    hostStr, _ := reader.ReadString('\n')
    hostStr = strings.TrimSpace(hostStr)

    fmt.Print("Enter SERVER PASSWORD (shared secret): ")
    byteServerPwd, _ := terminal.ReadPassword(int(syscall.Stdin))
    fmt.Println()
    serverPassword := string(byteServerPwd)

    fmt.Print("Enter your username: ")
    username, _ := reader.ReadString('\n')
    username = strings.TrimSpace(username)

    err := loadOrGenerateKeys()
    if err != nil {
        panic(fmt.Sprintf("Key error: %v", err))
    }

    conn, err := net.Dial("tcp", hostStr)
    if err != nil {
        fmt.Printf("Could not connect: %v\n", err)
        return
    }
    serverConn = conn
    defer conn.Close()

    loginMsg := Message{
        Type:           "login",
        Username:       username,
        PubKey:         base64.StdEncoding.EncodeToString(pubKey[:]),
        ServerPassword: serverPassword,
    }
    loginData, _ := json.Marshal(loginMsg)
    fmt.Fprintln(conn, string(loginData))

    go receiveMessages(conn, username)

    fmt.Println("\nConnected! Commands:")
    fmt.Println("  @username message  - Send encrypted message")
	fmt.Println("  Type 'panic' in console to wipe SESSION data (users/hosts)")
    fmt.Println("  /restart           - Restart server (fresh session for everyone)")
    fmt.Println("  /quit              - Disconnect")
    fmt.Println()

    for {
        fmt.Printf("[%s]: ", username)
        text, _ := reader.ReadString('\n')
        text = strings.TrimSpace(text)

        if text == "/quit" {
            break
        }
        if text == "" {
            continue
        }

        if text == "/restart" {
            restartMsg := Message{
                Type:    "msg",
                Content: "/restart",
            }
            payload, _ := json.Marshal(restartMsg)
            fmt.Fprintln(conn, string(payload))
            fmt.Println("[CMD] Sent restart request to server...")
            continue
        }

        if strings.HasPrefix(text, "@") {
            parts := strings.SplitN(text[1:], " ", 2)
            if len(parts) < 2 {
                fmt.Println("Usage: @username message")
                continue
            }

            target := strings.TrimSpace(parts[0])
            body := parts[1]

            keysMtx.RLock()
            targetPubKey, exists := knownKeys[target]
            keysMtx.RUnlock()

            if !exists {
                fmt.Printf("[ERROR] Key for %s not found. Wait for them to appear online.\n", target)
                continue
            }

            encryptedMsg, err := encryptMessage(body, targetPubKey)
            if err != nil {
                fmt.Printf("[ERROR] Encryption failed: %v\n", err)
                continue
            }

            encryptedMsg.Target = target
            encryptedMsg.Username = username

            payload, _ := json.Marshal(encryptedMsg)
            fmt.Fprintln(conn, string(payload))
        } else {
            plainMsg := Message{
                Type:     "msg",
                Content:  text,
                Username: username,
            }
            payload, _ := json.Marshal(plainMsg)
            fmt.Fprintln(conn, string(payload))
        }
    }
}