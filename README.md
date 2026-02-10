# 🛡️ SecureE2E | [فارسی](https://github.com/NIKJOO/11780/blob/main/README_fa.md).


> [!NOTE] 
> **This project is dedicated to all those who lost their lives during the Iranian National Revolution; those whose names we will remember forever, those whose names will never be spoken, and especially the Unknown Martyr No. 11780**.



# 📖 About
SecureE2E is a client-server chat application where the server acts as a neutral relay. It ensures that even if the server is compromised, your message content remains private.

## This project implements a custom cryptographic protocol featuring:
- Double Ratchet Algorithm: Provides Forward Secrecy and Future Secrecy. Every message uses a unique encryption key.
- Asymmetric Handshake: Uses **Ed25519** for identity signing and **Curve25519** for key exchange.
- Separation of Duties: The Server Password protects access to the network, while the E2E keys protect the content of your messages.

#
# ✨ Features
- 🔒 True End-to-End Encryption: Messages are encrypted on your device and only decrypted on the recipient's device. The server cannot read them.
- 🔄 Perfect Forward Secrecy: Compromising a long-term key does not decrypt past messages.
- 🆔 Identity Verification: Each user generates a unique fingerprint. Verify this out-of-band to ensure you aren't being Man-in-the-Middled (MitM).
- 🛡️ Secure Transport: The connection to the server is secured using **AES-256-GCM**, derived via Scrypt.
- 🚫 No Self-Messaging: Logic prevents routing loops and errors by blocking messages sent to oneself.
- 📜 Message Queuing: If you start typing before the cryptographic handshake is finished, messages are safely queued and sent automatically once the channel is secure.
#
# 🔐 Security Architecture
The security model operates in two distinct layers:

1. Transport Layer (Client ↔ Server) :
    + _Purpose: Prevents unauthorized users from connecting to the chat server._
    + _Mechanism: Scrypt Key Derivation + AES-256-GCM._
    + _Key: Derived from the Server Password._
2. Application Layer (Client ↔ Client) :
    + _Purpose: Ensures only the intended recipient can read the message content._
    + _Mechanism: Double Ratchet (X3DH inspired)._
3. Keys :
    + _Identity Key: Ed25519._
    + _Ephemeral Key: Curve25519._
    + _The Ratchet: Both sides maintain a chain key. Sending a message advances the sending chain and derives a unique message key._

#
# 📦 Installation
> Omptimized for windows OS ( both clien/server ) you need modify it for Linux environments.

Prerequisites
  + Go 1.21+ installed.
  + Terminal access.

1. Clone the Repository
<pre>    git clone https://github.com/yourusername/SecureE2E-Go.gitcd SecureE2E-Go </pre>
2. Install Dependencies
<pre>
    go get golang.org/x/crypto/curve25519
    go get golang.org/x/crypto/ed25519
    go get golang.org/x/crypto/hkdf
    go get golang.org/x/crypto/scrypt
    golang.org/x/crypto/ssh/terminal
    golang.org/x/crypto/argon2
</pre>
3. Build
<pre>
    # Build Server
    go build -o server server.go
    
    # Build Client
    go build -o client client.go
</pre>
#
# 🚀 Usage
 Download Video ( can't preview on web ) : ([Link](https://github.com/user-attachments/assets/e6c4155e-8701-4228-87a4-0c989255ba3f)).







## Follow Me

- **X (Twitter):** [https://x.com/N_Nikjoo](https://x.com/N_Nikjoo)  
- **LinkedIn:** [https://www.linkedin.com/in/nimanikjoo/](https://www.linkedin.com/in/nimanikjoo/)  
- **Telegram Channel:** [https://t.me/VSEC_academy](https://t.me/VSEC_academy)

#
📄 License
Distributed under the MIT License.

