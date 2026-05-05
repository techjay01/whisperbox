/**
 * WhisperBox E2EE Crypto Module
 * All cryptographic operations happen here — zero plaintext leaves the client.
 *
 * Scheme:
 *   Key Exchange  → RSA-OAEP 2048-bit
 *   Message Enc   → AES-GCM 256-bit with random 96-bit IV per message
 *   Key Wrapping  → PBKDF2 → AES-KW (private key never stored raw)
 */

const PBKDF2_ITERATIONS = 310_000; // OWASP 2023 recommendation
const RSA_MODULUS_LENGTH = 2048;

// ─── Key Generation ───────────────────────────────────────────────────────────

/**
 * Generate a fresh RSA-OAEP keypair for this user.
 * @returns {{ publicKey: CryptoKey, privateKey: CryptoKey }}
 */
export async function generateKeyPair() {
  // AES-KW (RFC 3394) requires input to be a multiple of 8 bytes.
  // RSA-2048 PKCS8 exports vary between ~1215-1218 bytes and only satisfy
  // this ~1 in 4 times, so we retry until we get a compatible key.
  // Average ~4 attempts, imperceptible to the user during registration.
  while (true) {
    const keypair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: RSA_MODULUS_LENGTH,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true, // extractable so we can wrap/export
      ["encrypt", "decrypt"]
    );
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", keypair.privateKey);
    if (pkcs8.byteLength % 8 === 0) return keypair;
  }
}

// ─── Key Wrapping (private key protection) ───────────────────────────────────

/**
 * Derive an AES-KW wrapping key from the user's password + salt via PBKDF2.
 * @param {string} password
 * @param {Uint8Array} salt
 * @returns {CryptoKey}
 */
export async function deriveWrappingKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"]
  );
}

/**
 * Wrap (encrypt) a private key using AES-KW so it can be stored on the server.
 * @param {CryptoKey} privateKey
 * @param {CryptoKey} wrappingKey
 * @returns {ArrayBuffer}
 */
export async function wrapPrivateKey(privateKey, wrappingKey) {
  return await crypto.subtle.wrapKey("pkcs8", privateKey, wrappingKey, {
    name: "AES-KW",
  });
}

/**
 * Unwrap (decrypt) the private key from server storage using the derived wrapping key.
 * @param {ArrayBuffer} wrappedKey
 * @param {CryptoKey} wrappingKey
 * @returns {CryptoKey}
 */
export async function unwrapPrivateKey(wrappedKey, wrappingKey) {
  return await crypto.subtle.unwrapKey(
    "pkcs8",
    new Uint8Array(wrappedKey),
    wrappingKey,
    { name: "AES-KW" },
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
}

// ─── Public Key Import/Export ─────────────────────────────────────────────────

/**
 * Export RSA public key as base64 string for server storage.
 * @param {CryptoKey} publicKey
 * @returns {string} base64
 */
export async function exportPublicKey(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return arrayBufferToBase64(spki);
}

/**
 * Import a base64 RSA-OAEP public key (from server) into a CryptoKey.
 * @param {string} base64
 * @returns {CryptoKey}
 */
export async function importPublicKey(base64) {
  const spki = base64ToArrayBuffer(base64);
  return await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}

// ─── Message Encryption ───────────────────────────────────────────────────────

/**
 * Encrypt a plaintext message for a recipient.
 * Also encrypts the AES key for the sender so sent messages are readable.
 *
 * @param {string} plaintext
 * @param {CryptoKey} recipientPublicKey
 * @param {CryptoKey} senderPublicKey
 * @returns {{ ciphertext: string, iv: string, encryptedKey: string, encryptedKeyForSelf: string }}
 */
export async function encryptMessage(plaintext, recipientPublicKey, senderPublicKey) {
  // 1. Generate ephemeral AES-GCM-256 key
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  // 2. Generate random 96-bit IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // 3. Encrypt plaintext with AES-GCM
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    enc.encode(plaintext)
  );

  // 4. Export raw AES key for wrapping
  const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);

  // 5. Encrypt AES key with recipient's RSA-OAEP public key
  const encryptedKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPublicKey,
    rawAesKey
  );

  // 6. Encrypt AES key with sender's own RSA-OAEP public key (to read sent messages)
  const encryptedKeyForSelf = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    senderPublicKey,
    rawAesKey
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
    encryptedKey: arrayBufferToBase64(encryptedKey),
    encryptedKeyForSelf: arrayBufferToBase64(encryptedKeyForSelf),
  };
}

/**
 * Decrypt an incoming message payload using the current user's private key.
 *
 * @param {{ ciphertext: string, iv: string, encryptedKey: string, encryptedKeyForSelf: string }} payload
 * @param {CryptoKey} privateKey
 * @param {boolean} isSentByMe - use encryptedKeyForSelf when true
 * @returns {string} plaintext
 */
export async function decryptMessage(payload, privateKey, isSentByMe = false) {
  // 1. Decrypt the AES key using our RSA private key
  const encKeyBuf = base64ToArrayBuffer(
    isSentByMe ? payload.encryptedKeyForSelf : payload.encryptedKey
  );
  const rawAesKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encKeyBuf
  );

  // 2. Import the raw AES key
  const aesKey = await crypto.subtle.importKey(
    "raw",
    rawAesKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  // 3. Decrypt the ciphertext
  const iv = base64ToArrayBuffer(payload.iv);
  const ciphertext = base64ToArrayBuffer(payload.ciphertext);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) },
    aesKey,
    ciphertext
  );

  return new TextDecoder().decode(plaintext);
}

// ─── Salt Generation ──────────────────────────────────────────────────────────

/**
 * Generate a cryptographically random 128-bit PBKDF2 salt.
 * @returns {Uint8Array}
 */
export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

// ─── Encoding Utilities ───────────────────────────────────────────────────────

export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
