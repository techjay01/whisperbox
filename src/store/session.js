/**
 * WhisperBox Session Store
 *
 * Manages runtime state: user profile, decrypted crypto keys (in-memory only),
 * conversation list, and message cache.
 *
 * SECURITY: Private keys are NEVER written to localStorage or IndexedDB in plaintext.
 * They live only in this module's memory and are cleared on logout.
 */

import { api } from "../api/client.js";
import {
  generateKeyPair,
  generateSalt,
  deriveWrappingKey,
  wrapPrivateKey,
  unwrapPrivateKey,
  exportPublicKey,
  importPublicKey,
  encryptMessage,
  decryptMessage,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from "../crypto/e2ee.js";

class SessionStore {
  constructor() {
    // User profile
    this.currentUser = null;

    // In-memory crypto keys — never persisted raw
    this.privateKey = null;   // CryptoKey (RSA-OAEP, decrypt)
    this.publicKey = null;    // CryptoKey (RSA-OAEP, encrypt)

    // Public key cache: userId → CryptoKey
    this.publicKeyCache = new Map();

    // Conversations: userId → { user, messages: [] }
    this.conversations = new Map();

    // Active conversation userId
    this.activeConversationId = null;

    // Presence: userId → 'online' | 'offline'
    this.onlineUsers = new Set();

    // UI event listeners
    this._listeners = [];

    // Bind WS events
    api.on("message.receive", (msg) => this._onMessageReceive(msg));
    api.on("user.online", ({ user_id }) => {
      this.onlineUsers.add(user_id);
      this._notify("presence", { userId: user_id, status: "online" });
    });
    api.on("user.offline", ({ user_id }) => {
      this.onlineUsers.delete(user_id);
      this._notify("presence", { userId: user_id, status: "offline" });
    });
    api.on("session.expired", () => {
      this.clear();
      this._notify("session.expired", {});
    });
    api.on("ws.connected", () => this._notify("ws.connected", {}));
    api.on("ws.disconnected", (d) => this._notify("ws.disconnected", d));
  }

  // ─── Auth ──────────────────────────────────────────────────────────────────

  async register(username, password) {
    // 1. Generate RSA-OAEP keypair
    const keypair = await generateKeyPair();

    // 2. Generate PBKDF2 salt
    const salt = generateSalt();

    // 3. Derive AES-KW wrapping key from password + salt
    const wrappingKey = await deriveWrappingKey(password, salt);

    // 4. Wrap private key so server can store it (encrypted blob)
    const wrappedPrivateKeyBuf = await wrapPrivateKey(keypair.privateKey, wrappingKey);

    // 5. Export public key as base64 for server
    const publicKeyB64 = await exportPublicKey(keypair.publicKey);

    // 6. Register with server
    const data = await api.register({
      username,
      password,
      publicKey: publicKeyB64,
      wrappedPrivateKey: arrayBufferToBase64(wrappedPrivateKeyBuf),
      pbkdf2Salt: arrayBufferToBase64(salt),
    });

    // 7. Store keys in memory
    this.privateKey = keypair.privateKey;
    this.publicKey = keypair.publicKey;
    this.currentUser = data.user;

    await this._afterAuth();
    return data.user;
  }

  async login(username, password) {
    // 1. Get tokens + key material from server
    const data = await api.login({ username, password });
    const user = data.user;

    // 2. Re-derive AES-KW wrapping key from password + server-stored salt
    const salt = base64ToArrayBuffer(user.pbkdf2_salt);
    const wrappingKey = await deriveWrappingKey(password, new Uint8Array(salt));

    // 3. Unwrap private key into memory
    const wrappedPrivBuf = base64ToArrayBuffer(user.wrapped_private_key);
    this.privateKey = await unwrapPrivateKey(wrappedPrivBuf, wrappingKey);

    // 4. Import public key into memory
    this.publicKey = await importPublicKey(user.public_key);

    this.currentUser = user;
    await this._afterAuth();
    return user;
  }

  async _afterAuth() {
    // Cache own public key
    this.publicKeyCache.set(this.currentUser.id, this.publicKey);

    // Load conversation list
    await this.loadConversations();

    // Connect WebSocket
    api.connectWS();
  }

  async logout() {
    await api.logout();
    this.clear();
  }

  clear() {
    this.currentUser = null;
    this.privateKey = null;
    this.publicKey = null;
    this.publicKeyCache.clear();
    this.conversations.clear();
    this.activeConversationId = null;
    this.onlineUsers.clear();
  }

  get isAuthenticated() {
    return !!this.currentUser && !!this.privateKey;
  }

  // ─── Conversations ─────────────────────────────────────────────────────────

  async loadConversations() {
    const convos = await api.getConversations();
    for (const c of convos) {
      if (!this.conversations.has(c.user_id)) {
        this.conversations.set(c.user_id, {
          user: { id: c.user_id, username: c.username, display_name: c.display_name },
          messages: [],
          loaded: false,
          lastMessageAt: c.last_message_at,
        });
      }
    }
    this._notify("conversations.updated", {});
    return this.conversations;
  }

  async openConversation(userId) {
    // Ensure conversation entry exists
    if (!this.conversations.has(userId)) {
      this.conversations.set(userId, {
        user: { id: userId },
        messages: [],
        loaded: false,
        lastMessageAt: null,
      });
    }

    this.activeConversationId = userId;

    // Load messages if not yet fetched
    const convo = this.conversations.get(userId);
    if (!convo.loaded) {
      await this.loadMessages(userId);
    }

    this._notify("conversation.opened", { userId });
    return convo;
  }

  // ─── Messages ──────────────────────────────────────────────────────────────

  async loadMessages(userId, { before = null } = {}) {
    const raw = await api.getMessages(userId, { limit: 50, before });
    const convo = this.conversations.get(userId);
    if (!convo) return;

    // Messages come newest-first; reverse for chronological display
    const reversed = [...raw].reverse();

    const decrypted = await Promise.all(
      reversed.map((msg) => this._decryptMsg(msg))
    );

    if (before) {
      // Prepend older messages
      convo.messages = [...decrypted, ...convo.messages];
    } else {
      convo.messages = decrypted;
      convo.loaded = true;
    }

    this._notify("messages.updated", { userId });
    return decrypted;
  }

  async sendMessage(recipientId, plaintext) {
    // 1. Get/cache recipient's public key
    const recipientPubKey = await this._getPublicKey(recipientId);

    // 2. Encrypt the message
    const payload = await encryptMessage(plaintext, recipientPubKey, this.publicKey);

    // 3. Send via WS (preferred) or HTTP fallback
    let sentMsg;
    if (api.isWSConnected) {
      api.sendMessageWS({ to: recipientId, payload });
      // Optimistically add to local state
      sentMsg = {
        id: `local-${Date.now()}`,
        from_user_id: this.currentUser.id,
        to_user_id: recipientId,
        payload,
        created_at: new Date().toISOString(),
        _plaintext: plaintext,
        _status: "sent",
      };
    } else {
      // HTTP fallback
      sentMsg = await api.sendMessageHTTP({ to: recipientId, payload });
      sentMsg._plaintext = plaintext;
      sentMsg._status = "sent";
    }

    // Add to conversation
    const convo = this.conversations.get(recipientId);
    if (convo) {
      convo.messages.push(sentMsg);
      convo.lastMessageAt = sentMsg.created_at;
    }

    this._notify("messages.updated", { userId: recipientId });
    this._notify("conversations.updated", {});
    return sentMsg;
  }

  async _onMessageReceive(msg) {
    const fromId = msg.from_user_id;

    // Decrypt
    const decrypted = await this._decryptMsg(msg);

    // Ensure conversation exists
    if (!this.conversations.has(fromId)) {
      // Unknown sender — try to get their info via search
      this.conversations.set(fromId, {
        user: { id: fromId, username: fromId, display_name: fromId },
        messages: [],
        loaded: true,
        lastMessageAt: msg.created_at,
      });
      await this.loadConversations(); // refresh to get display info
    }

    const convo = this.conversations.get(fromId);
    convo.messages.push(decrypted);
    convo.lastMessageAt = msg.created_at;

    this._notify("message.received", { userId: fromId, message: decrypted });
    this._notify("messages.updated", { userId: fromId });
    this._notify("conversations.updated", {});
  }

  async _decryptMsg(msg) {
    const isSentByMe = msg.from_user_id === this.currentUser.id;
    try {
      const plaintext = await decryptMessage(msg.payload, this.privateKey, isSentByMe);
      return { ...msg, _plaintext: plaintext, _decryptError: false };
    } catch (err) {
      console.error("[Decrypt failed]", err);
      return { ...msg, _plaintext: null, _decryptError: true };
    }
  }

  // ─── Public Key Cache ──────────────────────────────────────────────────────

  async _getPublicKey(userId) {
    if (this.publicKeyCache.has(userId)) return this.publicKeyCache.get(userId);
    const { public_key } = await api.getUserPublicKey(userId);
    const key = await importPublicKey(public_key);
    this.publicKeyCache.set(userId, key);
    return key;
  }

  async getPublicKeyFingerprint(userId) {
    try {
      const key = await this._getPublicKey(userId);
      const exported = await crypto.subtle.exportKey("spki", key);
      const hashBuf = await crypto.subtle.digest("SHA-256", exported);
      const hex = Array.from(new Uint8Array(hashBuf))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      // Return as grouped fingerprint (e.g. Signal-style)
      return hex.match(/.{1,4}/g).join(" ").toUpperCase();
    } catch {
      return "unavailable";
    }
  }

  // ─── User Search ───────────────────────────────────────────────────────────

  async searchUsers(query) {
    return api.searchUsers(query);
  }

  async startConversation(user) {
    if (!this.conversations.has(user.id)) {
      this.conversations.set(user.id, {
        user,
        messages: [],
        loaded: true,
        lastMessageAt: null,
      });
    } else {
      // Update user info in case it was stale
      const existing = this.conversations.get(user.id);
      existing.user = { ...existing.user, ...user };
    }
    this._notify("conversations.updated", {});
    await this.openConversation(user.id);
  }

  // ─── Event Emitter ─────────────────────────────────────────────────────────

  subscribe(callback) {
    this._listeners.push(callback);
    return () => {
      this._listeners = this._listeners.filter((l) => l !== callback);
    };
  }

  _notify(event, data) {
    this._listeners.forEach((cb) => cb(event, data));
  }
}

export const session = new SessionStore();
