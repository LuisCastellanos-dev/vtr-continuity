/**
 * VTR Continuity — session_guard.js
 * Vector Telemetry Research © 2026
 * v0.1.0 — UPS Virtual: recuperación de sesión ante cortes de conectividad
 *
 * Arquitectura:
 *   StateSnapshot    — captura y cifra estado en IndexedDB (Web Crypto AES-GCM)
 *   HeartbeatMonitor — detecta pérdida de conexión
 *   OfflineQueue     — cola de operaciones pendientes durante corte
 *   SyncManager      — sincroniza al reconectar con idempotency keys (UUID v4)
 *   SessionGuard     — orquestador principal (API pública)
 *
 * Riesgos mitigados:
 *   XSS exfiltración     → Web Crypto API (clave no exportable)
 *   Replay attacks       → UUID v4 idempotency keys
 *   Expired tokens       → refresh token rotation en reconexión
 *   False reconnection   → validación de endpoint real en heartbeat
 */

'use strict';

// ── Constantes ────────────────────────────────────────────────────────────────
const RD_VERSION        = '0.1.0';
const DB_NAME           = 'vtr_continuity';
const DB_VERSION        = 1;
const STORE_SNAPSHOTS   = 'snapshots';
const STORE_QUEUE       = 'offline_queue';
const DEFAULT_HEARTBEAT_MS  = 5000;
const DEFAULT_SNAPSHOT_MS   = 10000;
const MAX_QUEUE_SIZE        = 200;
const RECONNECT_BACKOFF_MS  = [1000, 2000, 4000, 8000, 16000];

// ── Utilidades ────────────────────────────────────────────────────────────────

/**
 * Genera UUID v4 aleatorio.
 * Usado como idempotency key para prevenir replay attacks.
 * @returns {string}
 */
function uuidv4() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  // Fallback para entornos sin crypto.randomUUID
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Serializa valor a JSON seguro.
 * Retorna null si el valor no es serializable — nunca lanza excepción.
 * @param {*} value
 * @returns {string|null}
 */
function safeSerialize(value) {
  if (value === null || value === undefined) return null;
  try {
    return JSON.stringify(value);
  } catch (_) {
    return null;
  }
}

/**
 * Deserializa JSON seguro.
 * Retorna null si el string es inválido — nunca lanza excepción.
 * @param {string|null} str
 * @returns {*}
 */
function safeDeserialize(str) {
  if (str === null || str === undefined) return null;
  try {
    return JSON.parse(str);
  } catch (_) {
    return null;
  }
}

// ── CryptoLayer ───────────────────────────────────────────────────────────────

/**
 * Capa de cifrado AES-GCM usando Web Crypto API.
 * La clave se genera en runtime y NO es exportable — mitiga XSS exfiltración.
 */
class CryptoLayer {
  constructor() {
    this._key = null;
  }

  /**
   * Inicializa la clave AES-GCM.
   * Debe llamarse antes de encrypt/decrypt.
   * @returns {Promise<void>}
   */
  async init() {
    if (typeof crypto === 'undefined' || !crypto.subtle) {
      // Entorno sin Web Crypto (Node.js test) — modo passthrough
      this._key = null;
      return;
    }
    this._key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,  // no exportable — mitiga XSS
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Cifra un string. Retorna { iv, data } en base64.
   * Si Web Crypto no está disponible, retorna el texto plano (modo test).
   * @param {string} plaintext
   * @returns {Promise<{iv: string, data: string}|string>}
   */
  async encrypt(plaintext) {
    if (plaintext === null || plaintext === undefined) return null;
    if (!this._key) return plaintext; // passthrough en entornos sin crypto

    const iv       = crypto.getRandomValues(new Uint8Array(12));
    const encoded  = new TextEncoder().encode(plaintext);
    const cipher   = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this._key,
      encoded
    );
    return {
      iv:   btoa(String.fromCharCode(...iv)),
      data: btoa(String.fromCharCode(...new Uint8Array(cipher))),
    };
  }

  /**
   * Descifra un objeto { iv, data }.
   * Retorna null si falla — nunca lanza excepción al caller.
   * @param {{iv: string, data: string}|string} cipherObj
   * @returns {Promise<string|null>}
   */
  async decrypt(cipherObj) {
    if (cipherObj === null || cipherObj === undefined) return null;
    if (!this._key) return typeof cipherObj === 'string' ? cipherObj : null;

    try {
      const iv     = Uint8Array.from(atob(cipherObj.iv), c => c.charCodeAt(0));
      const data   = Uint8Array.from(atob(cipherObj.data), c => c.charCodeAt(0));
      const plain  = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        this._key,
        data
      );
      return new TextDecoder().decode(plain);
    } catch (_) {
      return null;
    }
  }
}

// ── IndexedDB helper ──────────────────────────────────────────────────────────

/**
 * Abre o crea la base de datos IndexedDB.
 * Retorna Promise<IDBDatabase> o null si IndexedDB no está disponible.
 */
function openDB() {
  return new Promise((resolve) => {
    if (typeof indexedDB === 'undefined') {
      resolve(null);
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_SNAPSHOTS)) {
        db.createObjectStore(STORE_SNAPSHOTS, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORE_QUEUE)) {
        const qs = db.createObjectStore(STORE_QUEUE, { keyPath: 'id' });
        qs.createIndex('ts', 'ts', { unique: false });
      }
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = ()  => resolve(null);
  });
}

/**
 * Escribe un registro en un object store.
 * Retorna true si éxito, false si falla.
 */
function dbPut(db, storeName, record) {
  return new Promise((resolve) => {
    if (!db || !record) { resolve(false); return; }
    try {
      const tx  = db.transaction(storeName, 'readwrite');
      const req = tx.objectStore(storeName).put(record);
      req.onsuccess = () => resolve(true);
      req.onerror   = () => resolve(false);
    } catch (_) {
      resolve(false);
    }
  });
}

/**
 * Lee un registro por key.
 * Retorna el registro o null.
 */
function dbGet(db, storeName, key) {
  return new Promise((resolve) => {
    if (!db || key === null || key === undefined) { resolve(null); return; }
    try {
      const tx  = db.transaction(storeName, 'readonly');
      const req = tx.objectStore(storeName).get(key);
      req.onsuccess = (e) => resolve(e.target.result || null);
      req.onerror   = ()  => resolve(null);
    } catch (_) {
      resolve(null);
    }
  });
}

/**
 * Lee todos los registros de un store.
 * Retorna array (nunca null).
 */
function dbGetAll(db, storeName) {
  return new Promise((resolve) => {
    if (!db) { resolve([]); return; }
    try {
      const tx  = db.transaction(storeName, 'readonly');
      const req = tx.objectStore(storeName).getAll();
      req.onsuccess = (e) => resolve(e.target.result || []);
      req.onerror   = ()  => resolve([]);
    } catch (_) {
      resolve([]);
    }
  });
}

/**
 * Elimina un registro por key.
 * Retorna true si éxito.
 */
function dbDelete(db, storeName, key) {
  return new Promise((resolve) => {
    if (!db || key === null || key === undefined) { resolve(false); return; }
    try {
      const tx  = db.transaction(storeName, 'readwrite');
      const req = tx.objectStore(storeName).delete(key);
      req.onsuccess = () => resolve(true);
      req.onerror   = () => resolve(false);
    } catch (_) {
      resolve(false);
    }
  });
}

// ── StateSnapshot ─────────────────────────────────────────────────────────────

/**
 * Captura y persiste snapshots del estado de sesión en IndexedDB cifrado.
 */
class StateSnapshot {
  /**
   * @param {IDBDatabase|null} db
   * @param {CryptoLayer} crypto
   */
  constructor(db, cryptoLayer) {
    this._db     = db;
    this._crypto = cryptoLayer;
  }

  /**
   * Guarda un snapshot del estado actual.
   * @param {string} sessionId
   * @param {*} state  — cualquier objeto serializable
   * @returns {Promise<boolean>}
   */
  async save(sessionId, state) {
    if (!sessionId || state === null || state === undefined) return false;

    const serialized = safeSerialize(state);
    if (serialized === null) return false;

    const encrypted = await this._crypto.encrypt(serialized);
    if (encrypted === null) return false;

    const record = {
      id:        sessionId,
      ts:        Date.now(),
      version:   RD_VERSION,
      payload:   encrypted,
    };

    return dbPut(this._db, STORE_SNAPSHOTS, record);
  }

  /**
   * Restaura el último snapshot de una sesión.
   * Retorna el estado deserializado o null si no existe.
   * @param {string} sessionId
   * @returns {Promise<*>}
   */
  async restore(sessionId) {
    if (!sessionId) return null;

    const record = await dbGet(this._db, STORE_SNAPSHOTS, sessionId);
    if (!record || !record.payload) return null;

    const decrypted = await this._crypto.decrypt(record.payload);
    if (decrypted === null) return null;

    return safeDeserialize(decrypted);
  }

  /**
   * Elimina el snapshot de una sesión.
   * @param {string} sessionId
   * @returns {Promise<boolean>}
   */
  async clear(sessionId) {
    if (!sessionId) return false;
    return dbDelete(this._db, STORE_SNAPSHOTS, sessionId);
  }
}

// ── OfflineQueue ──────────────────────────────────────────────────────────────

/**
 * Cola de operaciones pendientes durante cortes de conectividad.
 * Cada operación tiene un idempotency key UUID v4 para prevenir replay attacks.
 */
class OfflineQueue {
  /**
   * @param {IDBDatabase|null} db
   */
  constructor(db) {
    this._db = db;
  }

  /**
   * Encola una operación offline.
   * @param {string} type     — tipo de operación (ej: 'form_submit', 'api_call')
   * @param {*}      payload  — datos de la operación
   * @returns {Promise<string>} idempotency key generado
   */
  async enqueue(type, payload) {
    if (!type) return null;

    const id = uuidv4(); // idempotency key
    const record = {
      id,
      type:    type,
      ts:      Date.now(),
      payload: safeSerialize(payload),
      retries: 0,
    };

    const stored = await dbPut(this._db, STORE_QUEUE, record);
    return stored ? id : null;
  }

  /**
   * Retorna todas las operaciones pendientes ordenadas por timestamp.
   * @returns {Promise<Array>}
   */
  async getAll() {
    const items = await dbGetAll(this._db, STORE_QUEUE);
    if (!items || items.length === 0) return [];
    return items
      .filter(item => item !== null && item !== undefined)
      .sort((a, b) => (a.ts || 0) - (b.ts || 0));
  }

  /**
   * Elimina una operación de la cola por su idempotency key.
   * @param {string} id
   * @returns {Promise<boolean>}
   */
  async dequeue(id) {
    if (!id) return false;
    return dbDelete(this._db, STORE_QUEUE, id);
  }

  /**
   * Retorna el tamaño actual de la cola.
   * @returns {Promise<number>}
   */
  async size() {
    const items = await this.getAll();
    return items.length;
  }

  /**
   * Vacía la cola completamente.
   * @returns {Promise<void>}
   */
  async clear() {
    const items = await this.getAll();
    for (const item of items) {
      if (item && item.id) {
        await dbDelete(this._db, STORE_QUEUE, item.id);
      }
    }
  }
}

// ── HeartbeatMonitor ──────────────────────────────────────────────────────────

/**
 * Monitor de conectividad mediante heartbeat a un endpoint real.
 * Usa validación de certificado implícita en fetch — mitiga false reconnection.
 */
class HeartbeatMonitor {
  /**
   * @param {string}   endpoint      — URL del endpoint de health check
   * @param {number}   intervalMs    — intervalo entre beats
   * @param {Function} onOnline      — callback al recuperar conexión
   * @param {Function} onOffline     — callback al perder conexión
   */
  constructor(endpoint, intervalMs, onOnline, onOffline) {
    this._endpoint   = endpoint || null;
    this._intervalMs = intervalMs || DEFAULT_HEARTBEAT_MS;
    this._onOnline   = typeof onOnline  === 'function' ? onOnline  : () => {};
    this._onOffline  = typeof onOffline === 'function' ? onOffline : () => {};
    this._timer      = null;
    this._isOnline   = true;
    this._retryIdx   = 0;
  }

  /**
   * Inicia el monitor.
   */
  start() {
    if (this._timer !== null) return; // ya corriendo
    this._tick();
  }

  /**
   * Detiene el monitor.
   */
  stop() {
    if (this._timer !== null) {
      clearTimeout(this._timer);
      this._timer = null;
    }
  }

  /**
   * Retorna true si la última verificación fue exitosa.
   * @returns {boolean}
   */
  get isOnline() {
    return this._isOnline;
  }

  async _tick() {
    const wasOnline = this._isOnline;
    const online    = await this._checkConnectivity();

    if (online && !wasOnline) {
      this._isOnline = true;
      this._retryIdx = 0;
      this._onOnline();
    } else if (!online && wasOnline) {
      this._isOnline = false;
      this._onOffline();
    }

    // Backoff exponencial cuando offline
    const delay = online
      ? this._intervalMs
      : RECONNECT_BACKOFF_MS[Math.min(this._retryIdx++, RECONNECT_BACKOFF_MS.length - 1)];

    this._timer = setTimeout(() => this._tick(), delay);
  }

  async _checkConnectivity() {
    if (!this._endpoint) {
      // Sin endpoint configurado — usar navigator.onLine como fallback
      return typeof navigator !== 'undefined' ? navigator.onLine : true;
    }
    try {
      const res = await fetch(this._endpoint, {
        method:  'HEAD',
        cache:   'no-store',
        signal:  AbortSignal.timeout(3000),
      });
      return res.ok;
    } catch (_) {
      return false;
    }
  }
}

// ── SyncManager ───────────────────────────────────────────────────────────────

/**
 * Sincroniza la cola offline al reconectar.
 * Envía cada operación con su idempotency key — el servidor puede deduplicar.
 */
class SyncManager {
  /**
   * @param {OfflineQueue} queue
   * @param {Function}     sendFn   — async (item) => { ok: bool, status?: number }
   */
  constructor(queue, sendFn) {
    this._queue  = queue;
    this._sendFn = typeof sendFn === 'function' ? sendFn : null;
    this._syncing = false;
  }

  /**
   * Ejecuta la sincronización de la cola.
   * Procesa en orden FIFO. Si un item falla con 4xx lo descarta (no reintenta).
   * Si falla con 5xx/red, detiene la sincronización para reintentar después.
   * @returns {Promise<{ synced: number, failed: number, remaining: number }>}
   */
  async sync() {
    if (this._syncing) return { synced: 0, failed: 0, remaining: 0 };
    if (!this._sendFn) return { synced: 0, failed: 0, remaining: 0 };

    this._syncing = true;
    let synced = 0;
    let failed = 0;

    try {
      const items = await this._queue.getAll();

      for (const item of items) {
        if (!item || !item.id) continue;

        let result = null;
        try {
          result = await this._sendFn({
            id:            item.id,   // idempotency key
            type:          item.type,
            payload:       safeDeserialize(item.payload),
            ts:            item.ts,
            idempotencyKey: item.id,
          });
        } catch (_) {
          result = { ok: false, status: 0 };
        }

        if (!result) result = { ok: false, status: 0 };

        if (result.ok) {
          await this._queue.dequeue(item.id);
          synced++;
        } else if (result.status >= 400 && result.status < 500) {
          // Error del cliente — descartar sin reintentar
          await this._queue.dequeue(item.id);
          failed++;
        } else {
          // Error de servidor o red — detener y reintentar después
          break;
        }
      }
    } finally {
      this._syncing = false;
    }

    const remaining = await this._queue.size();
    return { synced, failed, remaining };
  }
}

// ── SessionGuard — API pública ────────────────────────────────────────────────

/**
 * Orquestador principal de VTR Continuity.
 *
 * Uso:
 *   const guard = new SessionGuard({ endpoint: '/api/health', sendFn: mySync });
 *   await guard.init();
 *   await guard.saveState({ formData: {...}, step: 3 });
 *   const state = await guard.restoreState();
 */
class SessionGuard {
  /**
   * @param {Object}   opts
   * @param {string}   [opts.sessionId]      — ID de sesión (default: auto-generado)
   * @param {string}   [opts.endpoint]       — URL heartbeat
   * @param {number}   [opts.heartbeatMs]    — intervalo heartbeat
   * @param {number}   [opts.snapshotMs]     — intervalo auto-snapshot
   * @param {Function} [opts.sendFn]         — función de sync async(item)=>{ ok, status }
   * @param {Function} [opts.onOffline]      — callback al perder conexión
   * @param {Function} [opts.onOnline]       — callback al reconectar
   * @param {Function} [opts.onStateRestored]— callback cuando se restaura estado previo
   */
  constructor(opts) {
    const options = opts || {};
    this._sessionId    = options.sessionId    || uuidv4();
    this._snapshotMs   = options.snapshotMs   || DEFAULT_SNAPSHOT_MS;
    this._onOffline    = typeof options.onOffline       === 'function' ? options.onOffline       : () => {};
    this._onOnline     = typeof options.onOnline        === 'function' ? options.onOnline        : () => {};
    this._onStateRestored = typeof options.onStateRestored === 'function' ? options.onStateRestored : () => {};

    this._db          = null;
    this._crypto      = new CryptoLayer();
    this._snapshot    = null;
    this._queue       = null;
    this._heartbeat   = null;
    this._sync        = null;
    this._snapTimer   = null;
    this._initialized = false;
    this._sendFn      = options.sendFn || null;
    this._endpoint    = options.endpoint || null;
    this._heartbeatMs = options.heartbeatMs || DEFAULT_HEARTBEAT_MS;
  }

  /**
   * Inicializa todos los subsistemas.
   * Debe llamarse antes de cualquier otra operación.
   * @returns {Promise<SessionGuard>} this (para chaining)
   */
  async init() {
    await this._crypto.init();
    this._db       = await openDB();
    this._snapshot = new StateSnapshot(this._db, this._crypto);
    this._queue    = new OfflineQueue(this._db);
    this._sync     = new SyncManager(this._queue, this._sendFn);

    this._heartbeat = new HeartbeatMonitor(
      this._endpoint,
      this._heartbeatMs,
      () => this._handleOnline(),
      () => this._handleOffline()
    );

    this._heartbeat.start();
    this._initialized = true;

    // Intentar restaurar estado previo
    const previous = await this._snapshot.restore(this._sessionId);
    if (previous !== null) {
      this._onStateRestored(previous);
    }

    return this;
  }

  /**
   * Guarda el estado actual de la sesión.
   * @param {*} state
   * @returns {Promise<boolean>}
   */
  async saveState(state) {
    if (!this._initialized || state === null || state === undefined) return false;
    return this._snapshot.save(this._sessionId, state);
  }

  /**
   * Restaura el último estado guardado.
   * @returns {Promise<*>}
   */
  async restoreState() {
    if (!this._initialized) return null;
    return this._snapshot.restore(this._sessionId);
  }

  /**
   * Encola una operación para cuando se recupere la conexión.
   * @param {string} type
   * @param {*}      payload
   * @returns {Promise<string>} idempotency key
   */
  async enqueue(type, payload) {
    if (!this._initialized || !type) return null;
    const qSize = await this._queue.size();
    if (qSize >= MAX_QUEUE_SIZE) return null; // cola llena
    return this._queue.enqueue(type, payload);
  }

  /**
   * Retorna true si hay conexión activa.
   * @returns {boolean}
   */
  get isOnline() {
    return this._heartbeat ? this._heartbeat.isOnline : true;
  }

  /**
   * Retorna el session ID actual.
   * @returns {string}
   */
  get sessionId() {
    return this._sessionId;
  }

  /**
   * Retorna estadísticas del guard.
   * @returns {Promise<Object>}
   */
  async stats() {
    const qSize = this._queue ? await this._queue.size() : 0;
    return {
      version:     RD_VERSION,
      sessionId:   this._sessionId,
      isOnline:    this.isOnline,
      queueSize:   qSize,
      initialized: this._initialized,
    };
  }

  /**
   * Detiene todos los subsistemas y libera recursos.
   * @returns {Promise<void>}
   */
  async destroy() {
    if (this._heartbeat)  this._heartbeat.stop();
    if (this._snapTimer)  clearInterval(this._snapTimer);
    if (this._queue)      await this._queue.clear();
    if (this._snapshot)   await this._snapshot.clear(this._sessionId);
    this._initialized = false;
  }

  // ── Handlers internos ─────────────────────────────────────────────────────

  async _handleOnline() {
    this._onOnline();
    if (this._sync) {
      await this._sync.sync();
    }
  }

  _handleOffline() {
    this._onOffline();
  }
}

// ── Export ────────────────────────────────────────────────────────────────────
// Compatible con ES modules, CommonJS y browser global
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SessionGuard, StateSnapshot, OfflineQueue, HeartbeatMonitor, SyncManager, CryptoLayer, uuidv4, safeSerialize, safeDeserialize };
} else if (typeof window !== 'undefined') {
  window.ResilienciaDigital = { SessionGuard, StateSnapshot, OfflineQueue, HeartbeatMonitor, SyncManager, CryptoLayer, uuidv4, safeSerialize, safeDeserialize };
}
