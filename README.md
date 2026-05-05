# WhisperBox — End-to-End Encrypted Messaging

A secure messaging application where the server **never sees plaintext**. All encryption and decryption happens on the client using the Web Crypto API.

---

## Live Demo

Open `index.html` in any modern browser (Chrome 89+, Firefox 93+, Safari 15+, Edge 89+).

> **Note:** Must be served over `https://` or `localhost` — the Web Crypto API is restricted to secure contexts.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          CLIENT (Browser)                               │
│                                                                         │
│  ┌─────────────┐    ┌──────────────────┐    ┌────────────────────────┐ │
│  │   index.html │    │  src/crypto/     │    │  src/api/client.js     │ │
│  │  (UI / App)  │───▶│  e2ee.js         │    │                        │ │
│  │             │    │                  │    │  REST + WebSocket       │ │
│  │  Auth flow  │    │  generateKeyPair │    │  Token management       │ │
│  │  Chat UI    │    │  encryptMessage  │    │  Auto-refresh (14 min)  │ │
│  │  Key modal  │    │  decryptMessage  │    │  WS reconnect backoff   │ │
│  └─────────────┘    │  wrapPrivateKey  │    └────────────┬───────────┘ │
│         │           │  unwrapPrivateKey│                 │             │
│         │           │  deriveWrapping  │                 │             │
│         └──────────▶│  Key (PBKDF2)   │                 │             │
│                     └──────────────────┘                 │             │
│                                                          │             │
│  IN-MEMORY ONLY:                                         │             │
│  • RSA-OAEP private key (CryptoKey)                     │             │
│  • RSA-OAEP public key (CryptoKey)                      │             │
│  • Decrypted message cache                               │             │
└──────────────────────────────────────────────────────────┼─────────────┘
                                                           │ HTTPS / WSS
                                                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    WhisperBox Backend (koyeb.app)                       │
│                                                                         │
│   Stores ONLY:                                                          │
│   • username / display_name                                             │
│   • public_key        (base64 RSA-OAEP SPKI — not secret)              │
│   • wrapped_private_key (AES-KW encrypted blob — server cannot read)   │
│   • pbkdf2_salt        (random 128-bit salt — not secret)              │
│   • Message payloads:  { ciphertext, iv, encryptedKey,                 │
│                          encryptedKeyForSelf }  ← all encrypted        │
│                                                                         │
│   Server NEVER has:                                                     │
│   ✗ RSA private key in plaintext                                        │
│   ✗ AES session keys                                                    │
│   ✗ Message plaintext                                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Encryption Flow

### 1. Registration — Key Setup

```
Browser                                         Server
───────                                         ──────

1. Generate RSA-OAEP 2048-bit keypair
   (retried until PKCS8 length is a multiple of 8 — required by AES-KW RFC 3394)

2. Generate random 128-bit PBKDF2 salt

3. Derive AES-KW wrapping key:
   PBKDF2(password, salt, 310000 rounds, SHA-256)
   → wrappingKey (AES-KW 256-bit)

4. Wrap private key:
   AES-KW.wrap(privateKey, wrappingKey)
   → wrappedPrivateKey (opaque blob)

5. Export public key → base64 (SPKI format)

6. POST /auth/register ─────────────────────────▶ Store:
   {                                               • username
     username,                                     • public_key (public)
     password,          (hashed server-side)       • wrapped_private_key
     public_key,                                   • pbkdf2_salt
     wrapped_private_key,
     pbkdf2_salt
   }

7. Store keys in memory ONLY (never localStorage)

8. **AES-KW alignment requirement** — RFC 3394 (AES-KW) requires input to be a multiple of 8 bytes. RSA-2048 PKCS8 export length varies per key generation (~1215–1218 bytes). The implementation retries key generation until a compatible key is produced (average ~4 attempts, imperceptible to users).
```

### 2. Login — Key Restoration

```
Browser                                         Server
───────                                         ──────

1. POST /auth/login ─────────────────────────▶
   { username, password }

                            ◀─────────────────── 200 OK
                                                  { access_token,
                                                    refresh_token,
                                                    user: {
                                                      public_key,
                                                      wrapped_private_key,
                                                      pbkdf2_salt
                                                    }
                                                  }

2. Re-derive AES-KW wrapping key:
   PBKDF2(password, pbkdf2_salt, 310000 rounds)
   → wrappingKey

3. Unwrap private key:
   AES-KW.unwrap(wrapped_private_key, wrappingKey)
   → privateKey (CryptoKey, in-memory only)

4. Import public key:
   importKey("spki", base64Decode(public_key))
   → publicKey (CryptoKey)

5. Keys ready — WebSocket connected
```

### 3. Sending a Message

```
Sender (Alice)                                  Recipient (Bob)
──────────────                                  ───────────────

1. GET /users/{bobId}/public-key
   → bobPublicKey (import as CryptoKey)

2. Generate ephemeral AES-GCM-256 key (random)
   Generate random 96-bit IV

3. Encrypt plaintext:
   AES-GCM.encrypt(plaintext, iv, aesKey)
   → ciphertext

4. Export raw AES key bytes

5. Encrypt AES key for Bob:
   RSA-OAEP.encrypt(rawAesKey, bobPublicKey)
   → encryptedKey

6. Encrypt AES key for self (to read sent messages):
   RSA-OAEP.encrypt(rawAesKey, alicePublicKey)
   → encryptedKeyForSelf

7. Send via WebSocket:
   {
     event: "message.send",
     to: bobId,
     payload: {
       ciphertext,       ← AES-GCM encrypted body
       iv,               ← random nonce
       encryptedKey,     ← AES key wrapped with Bob's RSA key
       encryptedKeyForSelf  ← AES key wrapped with Alice's RSA key
     }
   }
                            ─── Server stores payload ──▶  WebSocket push
                                (never decrypts)           {
                                                             event: "message.receive",
                                                             payload: { ciphertext, iv,
                                                                        encryptedKey, ... }
                                                           }

                                                  8. RSA-OAEP.decrypt(encryptedKey, bobPrivateKey)
                                                     → rawAesKey

                                                  9. AES-GCM.decrypt(ciphertext, iv, aesKey)
                                                     → plaintext ✓
```

---

## Key Management

| Material | Where Stored | Who Can Read |
|---|---|---|
| RSA public key | Server + client memory | Anyone (public by design) |
| RSA private key (wrapped) | Server | Nobody — server stores encrypted blob |
| RSA private key (unwrapped) | **Memory only** | Only the logged-in user |
| AES-KW wrapping key | **Memory only during login** | Only the user (derived from password) |
| PBKDF2 salt | Server | Anyone (it's a salt, not a secret) |
| AES-GCM session keys | **Never persisted** | Generated fresh per-message |
| Message payloads | Server | Nobody — server sees only ciphertext |

### Why PBKDF2 with 310,000 iterations?
OWASP 2023 recommends ≥ 310,000 iterations of PBKDF2-SHA256 to make brute-force attacks computationally expensive. This slows login slightly (~200ms) but makes password cracking infeasible.

### Why RSA-OAEP + AES-GCM hybrid?
RSA can only encrypt ~190 bytes at 2048-bit modulus. We encrypt the message with a random AES-256-GCM key (fast, unlimited size), then encrypt only the small AES key with RSA. This is standard hybrid encryption (used by TLS, PGP, Signal).

### `encryptedKeyForSelf`
When Alice sends a message, she encrypts the AES session key twice: once with Bob's public key (so Bob can read it) and once with her own public key (so she can read her own sent messages). The server stores both blobs.

---

## Security Trade-offs

| Decision | Trade-off |
|---|---|
| RSA-OAEP 2048-bit | Industry standard. 4096-bit would be stronger but key generation/operations ~4x slower. |
| Keys in JS memory (not IndexedDB) | Simpler, no storage side-channel. Cleared on page close/logout. Requires re-login per session. |
| Wrapped key stored on server | Enables multi-device login. Risk: if server is compromised AND attacker has password, they can unwrap the key. Alternative: device-only storage (breaks multi-device). |
| PBKDF2 (not Argon2) | Web Crypto API has native PBKDF2 support. Argon2 is stronger but requires WASM, adding complexity and a supply-chain dependency. |
| No forward secrecy by default | RSA key reuse means compromising the private key exposes all past messages. Signal's Double Ratchet provides per-message forward secrecy at the cost of significant protocol complexity. |
| Access tokens expire in 15 min | Short window limits damage from stolen tokens. Refresh tokens are revocable via `POST /auth/logout`. |

---

## Known Limitations

1. **No forward secrecy** — Compromising a private key exposes all stored messages encrypted to that key. A Signal-style Double Ratchet protocol would address this.

2. **Single device key** — The same keypair is used across devices/sessions. No key rotation implemented.

3. **No message deletion** — The API and client do not implement message or conversation deletion.

4. **Trust on first use (TOFU)** — There is no built-in mechanism to verify that the public key retrieved from the server belongs to the claimed user. Out-of-band fingerprint verification (shown in the key modal) is the current mitigation.

5. **In-memory key storage** — Keys are lost on page refresh or tab close. Users must log in again each session. This is a deliberate security-usability trade-off.

6. **No message pagination UI** — The client loads the 50 most recent messages. Scroll-to-load-more is not implemented.

7. **No replay protection** — The server does not implement message sequence numbers or anti-replay tokens.

---

## File Structure

```
whisperbox/
├── index.html              — Main app (auth + chat UI)
├── src/
│   ├── crypto/
│   │   └── e2ee.js         — All Web Crypto API operations
│   ├── api/
│   │   └── client.js       — WhisperBox REST + WebSocket client
│   └── store/
│       └── session.js      — Session state (reference module)
└── README.md
```

---

## Browser Requirements

- **Web Crypto API** — Chrome 37+, Firefox 34+, Safari 11+, Edge 79+
- **WebSocket** — Universal
- **ES Modules** — Chrome 61+, Firefox 60+, Safari 10.1+, Edge 16+

Must be served over **HTTPS** or **localhost** (Web Crypto API requirement).

---

## API Quick Reference

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/auth/register` | No | Create account + upload key material |
| POST | `/auth/login` | No | Login + receive wrapped key blobs |
| GET | `/auth/me` | Yes | Current user profile |
| POST | `/auth/refresh` | No | Refresh access token |
| POST | `/auth/logout` | Yes | Revoke refresh token |
| GET | `/users/search?q=` | Yes | Search users |
| GET | `/users/{id}/public-key` | Yes | Fetch RSA public key |
| GET | `/conversations` | Yes | List conversations |
| GET | `/conversations/{id}/messages` | Yes | Paginated history |
| POST | `/messages` | Yes | Send message (HTTP fallback) |
| WS | `/ws?token=` | Yes | Real-time messaging |

---

## Security Checklist

- [x] Private key never stored in plaintext
- [x] No sensitive data in `localStorage` or `sessionStorage`
- [x] AES-GCM with random IV per message (no IV reuse)
- [x] PBKDF2 with 310,000 iterations (OWASP 2023)
- [x] Access tokens expire in 15 minutes
- [x] Refresh tokens are revocable
- [x] WebSocket reconnects with fresh token on `4001`
- [x] Decryption failures handled gracefully (shown in UI)
- [x] No hardcoded keys or secrets
- [x] Key fingerprint UI for out-of-band verification
- [x] `encryptedKeyForSelf` for sender to read own messages
- [ ] Forward secrecy (known limitation)
- [ ] Anti-replay (known limitation)
