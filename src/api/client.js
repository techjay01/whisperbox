/**
 * WhisperBox API Client
 * Handles all communication with the WhisperBox backend.
 * Manages token lifecycle: auto-refresh before expiry, reconnect on WS close codes.
 */

const BASE_URL = "https://whisperbox.koyeb.app";
const WS_URL = "wss://whisperbox.koyeb.app/ws";
const TOKEN_REFRESH_MARGIN_MS = 60_000; // refresh 1 min before expiry

class WhisperBoxAPI {
  constructor() {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiresAt = null;
    this.ws = null;
    this.wsListeners = new Map(); // event → [callbacks]
    this.refreshTimer = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
  }

  // ─── Token Management ───────────────────────────────────────────────────────

  setTokens(accessToken, refreshToken, expiresIn) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.tokenExpiresAt = Date.now() + expiresIn * 1000;
    this._scheduleRefresh(expiresIn);
  }

  _scheduleRefresh(expiresIn) {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    const delay = Math.max(0, expiresIn * 1000 - TOKEN_REFRESH_MARGIN_MS);
    this.refreshTimer = setTimeout(() => this._doRefresh(), delay);
  }

  async _doRefresh() {
    if (!this.refreshToken) return;
    try {
      const data = await this.refreshAccessToken();
      // Reconnect WS with new token if connected
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this._reconnectWS();
      }
      return data;
    } catch {
      // Refresh failed → tokens expired, app should redirect to login
      this._emit("session.expired", {});
    }
  }

  clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiresAt = null;
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
  }

  // ─── HTTP Helpers ───────────────────────────────────────────────────────────

  async _request(method, path, body = null, requiresAuth = true) {
    const headers = { "Content-Type": "application/json" };
    if (requiresAuth && this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }

    const res = await fetch(`${BASE_URL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : null,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      // FastAPI validation errors return detail as an array of {loc, msg, type} objects
      let detail = err.detail;
      if (Array.isArray(detail)) {
        detail = detail.map(e => e.msg || JSON.stringify(e)).join(', ');
      } else if (typeof detail === 'object' && detail !== null) {
        detail = JSON.stringify(detail);
      }
      const error = new Error(detail || `HTTP ${res.status}`);
      error.status = res.status;
      throw error;
    }

    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }

  // ─── Auth Endpoints ─────────────────────────────────────────────────────────

  async register({ username, displayName, password, publicKey, wrappedPrivateKey, pbkdf2Salt }) {
    const data = await this._request("POST", "/auth/register", {
      username,
      display_name: displayName,
      password,
      public_key: publicKey,
      wrapped_private_key: wrappedPrivateKey,
      pbkdf2_salt: pbkdf2Salt,
    }, false);
    this.setTokens(data.access_token, data.refresh_token, data.expires_in);
    return data;
  }

  async login({ username, password }) {
    const data = await this._request("POST", "/auth/login", { username, password }, false);
    this.setTokens(data.access_token, data.refresh_token, data.expires_in);
    return data;
  }

  async getMe() {
    return this._request("GET", "/auth/me");
  }

  async refreshAccessToken() {
    const data = await this._request("POST", "/auth/refresh", {
      refresh_token: this.refreshToken,
    }, false);
    this.setTokens(data.access_token, this.refreshToken, data.expires_in);
    return data;
  }

  async logout() {
    if (!this.refreshToken) return;
    try {
      await this._request("POST", "/auth/logout", { refresh_token: this.refreshToken });
    } catch { /* best effort */ }
    this.clearTokens();
    this.disconnectWS();
  }

  // ─── User Endpoints ─────────────────────────────────────────────────────────

  async searchUsers(query) {
    return this._request("GET", `/users/search?q=${encodeURIComponent(query)}`);
  }

  async getUserPublicKey(userId) {
    return this._request("GET", `/users/${userId}/public-key`);
  }

  // ─── Message Endpoints ──────────────────────────────────────────────────────

  async getConversations() {
    return this._request("GET", "/conversations");
  }

  async getMessages(userId, { limit = 50, before = null } = {}) {
    let path = `/conversations/${userId}/messages?limit=${limit}`;
    if (before) path += `&before=${encodeURIComponent(before)}`;
    return this._request("GET", path);
  }

  async sendMessageHTTP({ to, payload }) {
    return this._request("POST", "/messages", { to, payload });
  }

  // ─── WebSocket ──────────────────────────────────────────────────────────────

  connectWS() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) return;
    if (!this.accessToken) throw new Error("No access token");

    this.ws = new WebSocket(`${WS_URL}?token=${this.accessToken}`);

    this.ws.addEventListener("open", () => {
      this.reconnectAttempts = 0;
      this._emit("ws.connected", {});
    });

    this.ws.addEventListener("message", (event) => {
      try {
        const msg = JSON.parse(event.data);
        this._emit(msg.event, msg);
      } catch {
        console.warn("[WS] Non-JSON frame:", event.data);
      }
    });

    this.ws.addEventListener("close", (event) => {
      this._emit("ws.disconnected", { code: event.code });
      if (event.code === 4001) {
        // Token expired → refresh and reconnect
        this._doRefresh().then(() => this._reconnectWS());
      } else if (event.code === 4003) {
        // Invalid token → back to login
        this._emit("session.expired", {});
      } else if (this.reconnectAttempts < this.maxReconnectAttempts) {
        // Network blip → exponential backoff
        const delay = Math.min(1000 * 2 ** this.reconnectAttempts, 30000);
        this.reconnectAttempts++;
        setTimeout(() => this._reconnectWS(), delay);
      }
    });

    this.ws.addEventListener("error", () => {
      this._emit("ws.error", {});
    });
  }

  _reconnectWS() {
    if (this.ws) {
      this.ws.onclose = null; // prevent loop
      this.ws.close();
    }
    this.connectWS();
  }

  disconnectWS() {
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.close();
      this.ws = null;
    }
  }

  sendWS(data) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket not connected");
    }
    this.ws.send(JSON.stringify(data));
  }

  sendMessageWS({ to, payload }) {
    this.sendWS({ event: "message.send", to, payload });
  }

  // ─── Event Bus ──────────────────────────────────────────────────────────────

  on(event, callback) {
    if (!this.wsListeners.has(event)) this.wsListeners.set(event, []);
    this.wsListeners.get(event).push(callback);
    return () => this.off(event, callback); // returns unsubscribe fn
  }

  off(event, callback) {
    const listeners = this.wsListeners.get(event) || [];
    this.wsListeners.set(event, listeners.filter((l) => l !== callback));
  }

  _emit(event, data) {
    (this.wsListeners.get(event) || []).forEach((cb) => cb(data));
  }

  get isWSConnected() {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

export const api = new WhisperBoxAPI();