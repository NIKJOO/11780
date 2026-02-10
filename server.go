package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	HOST        = "127.0.0.1"
	PORT        = "8443"
	USERS_FILE  = "users.json"
	SECRET_FILE = "secret.dat"
	KNOWN_HOSTS = "known_hosts.txt"
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

type Client struct {
	Username string
	PubKey   string
	Conn     net.Conn
}

type User struct {
	Username string `json:"username"`
	Key      string `json:"key"`
}

type UserList struct {
	Type  string `json:"type"`
	Users []User `json:"users"`
}

type ServerSecret struct {
	Salt string `json:"salt"`
	Hash string `json:"hash"`
}

var (
	clients      = make(map[string]*Client)
	serverSecret *ServerSecret
	clientsMx    sync.RWMutex
	serverListener net.Listener
	restarting   bool
	restartMx    sync.Mutex
)

func loadOrPromptServerPassword() error {
	if _, err := os.Stat(SECRET_FILE); os.IsNotExist(err) {
		fmt.Print("\n[SECURITY]  FIRST RUN: Enter SERVER PASSWORD (shared secret for all users): ")
		bytePwd, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read password: %v", err)
		}
		pwd := string(bytePwd)
		if len(pwd) < 8 {
			return fmt.Errorf("password too short (min 8 characters required)")
		}

		salt := make([]byte, 16)
		rand.Read(salt)
		hash := argon2.IDKey([]byte(pwd), salt, 1, 64*1024, 4, 32)

		serverSecret = &ServerSecret{
			Salt: base64.StdEncoding.EncodeToString(salt),
			Hash: base64.StdEncoding.EncodeToString(hash),
		}

		data, _ := json.MarshalIndent(serverSecret, "", "  ")
		if err := os.WriteFile(SECRET_FILE, data, 0600); err != nil {
			return fmt.Errorf("failed to save server password: %v", err)
		}

		fmt.Printf("[SECURITY]  Server password set and saved to %s\n", SECRET_FILE)
		fmt.Println("[SECURITY]  This password will persist across ALL restarts/panics")
		return nil
	}

	data, err := os.ReadFile(SECRET_FILE)
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", SECRET_FILE, err)
	}
	serverSecret = &ServerSecret{}
	if err := json.Unmarshal(data, serverSecret); err != nil {
		return fmt.Errorf("invalid %s format: %v", SECRET_FILE, err)
	}
	fmt.Printf("[SECURITY]  Loaded server password hash from %s\n", SECRET_FILE)
	return nil
}

func verifyServerPassword(password string) bool {
	salt, _ := base64.StdEncoding.DecodeString(serverSecret.Salt)
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	storedHash, _ := base64.StdEncoding.DecodeString(serverSecret.Hash)
	return string(hash) == string(storedHash)
}

func secureWipe(filepath string) {
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return
	}
	tempPath := fmt.Sprintf("%s.tmp_wipe%d", filepath, time.Now().UnixNano())
	if err := os.Rename(filepath, tempPath); err == nil {
		os.Remove(tempPath)
	} else {
		os.Remove(filepath)
	}
}

func performRestart(initiator string) {
	restartMx.Lock()
	if restarting {
		restartMx.Unlock()
		fmt.Println("[RESTART] Already restarting - ignoring duplicate request")
		return
	}
	restarting = true
	restartMx.Unlock()
	fmt.Printf("\n[!!! RESTART !!!] Initiated by user: %s\n", initiator)

	clientsMx.Lock()
	restartMsg := Message{Type: "SERVER_RESTART", Content: "Server restarting - please reconnect in 5 seconds"}
	data, _ := json.Marshal(restartMsg)
	data = append(data, '\n')

	for _, client := range clients {
		if client.Conn != nil {
			client.Conn.Write(data)
			client.Conn.Close()
		}
	}
	clients = nil
	clientsMx.Unlock()

	secureWipe(USERS_FILE)
	secureWipe(KNOWN_HOSTS)

	fmt.Println("[RESTART] All clients disconnected. Spawning new server instance...")

	cmd := exec.Command(os.Args[0])
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		fmt.Printf("[RESTART] FAILED to spawn new process: %v\n", err)
		fmt.Println("[RESTART] Exiting without restart...")
		os.Exit(1)
	}

	fmt.Printf("[RESTART] New instance PID: %d\n", cmd.Process.Pid)
	fmt.Println("[RESTART] Current instance shutting down...")

	if serverListener != nil {
		serverListener.Close()
	}

	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}

func performPanic() {
	fmt.Println("\n[!!! PANIC !!!] SHUTTING DOWN...")
	clientsMx.Lock()

	secureWipe(USERS_FILE)
	secureWipe(KNOWN_HOSTS)

	panicMsg := Message{Type: "SERVER_PANIC"}
	data, _ := json.Marshal(panicMsg)
	data = append(data, '\n')

	for _, client := range clients {
		if client.Conn != nil {
			client.Conn.Write(data)
			client.Conn.Close()
		}
	}
	clients = nil

	clientsMx.Unlock()

	fmt.Println("[WIPE] Session data wiped. Shutting down...")

	if serverListener != nil {
		serverListener.Close()
	}

	time.Sleep(100 * time.Millisecond)
	os.Exit(0)
}

func listenForAdminCommands() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("[ADMIN] Commands:")
	fmt.Println("  'panic'   - Shutdown server and wipe SESSION data (users/hosts)")
	fmt.Println("  'restart' - Restart server with fresh session")
	for {
		text, _ := reader.ReadString('\n')
		cmd := strings.TrimSpace(text)
		if cmd == "panic" {
			performPanic()
		} else if cmd == "restart" {
			performRestart("console")
		}
	}
}

func saveOnlineUsers() {
	clientsMx.RLock()
	defer clientsMx.RUnlock()
	users := make([]User, 0, len(clients))
	for _, client := range clients {
		users = append(users, User{Username: client.Username, Key: client.PubKey})
	}
	data, _ := json.MarshalIndent(users, "", "  ")
	os.WriteFile(USERS_FILE, data, 0600)
}

func broadcastToAll(msg interface{}, excludeConn net.Conn) {
	data, _ := json.Marshal(msg)
	clientsMx.RLock()
	defer clientsMx.RUnlock()
	if clients == nil {
		return
	}
	for _, client := range clients {
		if client.Conn != excludeConn && client.Conn != nil {
			client.Conn.Write(data)
			client.Conn.Write([]byte("\n"))
		}
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}
	var loginMsg Message
	if err := json.Unmarshal(scanner.Bytes(), &loginMsg); err != nil {
		return
	}

	if !verifyServerPassword(loginMsg.ServerPassword) {
		resp, _ := json.Marshal(Message{Type: "auth_failed", Content: "invalid_server_password"})
		conn.Write(append(resp, '\n'))
		fmt.Printf("[AUTH FAILED] %s (invalid server password)\n", loginMsg.Username)
		return
	}

	resp, _ := json.Marshal(Message{Type: "auth_success"})
	conn.Write(append(resp, '\n'))

	username := loginMsg.Username
	pubKey := loginMsg.PubKey

	clientsMx.Lock()
	clients[username] = &Client{Username: username, PubKey: pubKey, Conn: conn}
	clientsMx.Unlock()

	fmt.Printf("[AUTH OK] %s authenticated via server password.\n", username)

	var onlineUsers []User
	clientsMx.RLock()
	for u, c := range clients {
		if u != username {
			onlineUsers = append(onlineUsers, User{Username: u, Key: c.PubKey})
		}
	}
	clientsMx.RUnlock()

	welcomeMsg := UserList{Type: "user_list", Users: onlineUsers}
	welcomeData, _ := json.Marshal(welcomeMsg)
	conn.Write(append(welcomeData, '\n'))

	broadcastToAll(Message{
		Type:     "user_joined",
		Username: username,
		PubKey:   pubKey,
	}, conn)

	for scanner.Scan() {
		var msg Message
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			continue
		}

		if msg.Type == "panic" || (msg.Type == "msg" && strings.TrimSpace(msg.Content) == "/panic") {
			fmt.Printf("[!!!] GLOBAL PANIC triggered by user: %s\n", username)
			performPanic()
			return
		}

		if msg.Type == "msg" && strings.TrimSpace(msg.Content) == "/restart" {
			fmt.Printf("[!!!] RESTART triggered by user: %s\n", username)
			performRestart(username)
			return
		}

		if msg.Type == "user_panic" {
			target := msg.Target
			clientsMx.RLock()
			if client, exists := clients[target]; exists {
				panicMsg := Message{Type: "SERVER_PANIC"}
				data, _ := json.Marshal(panicMsg)
				client.Conn.Write(append(data, '\n'))
				fmt.Printf("[CMD] %s triggered PANIC on %s\n", username, target)
			} else {
				fmt.Printf("[CMD] Failed to panic %s: User offline\n", target)
			}
			clientsMx.RUnlock()
			continue
		}

		if msg.Type == "encrypted_msg" {
			target := msg.Target
			clientsMx.RLock()
			if client, exists := clients[target]; exists {
				payload, _ := json.Marshal(msg)
				client.Conn.Write(append(payload, '\n'))
				fmt.Printf("[MSG] %s -> %s\n", username, target)
			}
			clientsMx.RUnlock()
		}
	}

	clientsMx.Lock()
	delete(clients, username)
	clientsMx.Unlock()

	fmt.Printf("[DISCONNECT] %s left.\n", username)
	broadcastToAll(Message{Type: "user_left", Username: username}, nil)
	saveOnlineUsers()
}

func main() {
	if err := loadOrPromptServerPassword(); err != nil {
		panic(fmt.Sprintf("Server password setup failed: %v", err))
	}

	fmt.Println("[STARTUP] Starting fresh session (user sessions only)...")
	secureWipe(USERS_FILE)
	secureWipe(KNOWN_HOSTS)

	var err error
	serverListener, err = net.Listen("tcp", HOST+":"+PORT)
	if err != nil {
		panic(err)
	}

	fmt.Printf("[SERVER] Listening on %s:%s (PID: %d)\n", HOST, PORT, os.Getpid())
	fmt.Println("[SERVER] ANY user can type '/restart' to restart server with fresh session")
	fmt.Println("[SERVER] Type 'panic' in console to wipe SESSION data (users/hosts)")

	go listenForAdminCommands()

	for {
		conn, err := serverListener.Accept()
		if err != nil {
			break
		}
		go handleConnection(conn)
	}
}