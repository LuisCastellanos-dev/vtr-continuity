
const {
  uuidv4,
  safeSerialize,
  safeDeserialize,
  OfflineQueue,
  StateSnapshot,
  SyncManager,
  CryptoLayer,
  SessionGuard,
} = require('../src/session_guard');

describe('uuidv4', () => {
  test('genera string con formato UUID v4', () => {
    const id = uuidv4();
    expect(typeof id).toBe('string');
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  test('genera IDs unicos en cada llamada', () => {
    const ids = new Set(Array.from({length: 100}, () => uuidv4()));
    expect(ids.size).toBe(100);
  });
});

describe('safeSerialize', () => {
  test('serializa objeto a JSON string', () => {
    const result = safeSerialize({ key: 'value', num: 42 });
    expect(result).toBe('{"key":"value","num":42}');
  });

  test('retorna null para valor null', () => {
    expect(safeSerialize(null)).toBeNull();
  });

  test('retorna null para undefined', () => {
    expect(safeSerialize(undefined)).toBeNull();
  });

  test('retorna null para objeto circular', () => {
    const obj = {};
    obj.self = obj;
    expect(safeSerialize(obj)).toBeNull();
  });

  test('serializa arrays correctamente', () => {
    const result = safeSerialize([1, 2, 3]);
    expect(result).toBe('[1,2,3]');
  });
});

describe('safeDeserialize', () => {
  test('deserializa JSON valido', () => {
    const result = safeDeserialize('{"key":"value"}');
    expect(result).toEqual({ key: 'value' });
  });

  test('retorna null para string invalido', () => {
    expect(safeDeserialize('no es json{')).toBeNull();
  });

  test('retorna null para null', () => {
    expect(safeDeserialize(null)).toBeNull();
  });

  test('retorna null para undefined', () => {
    expect(safeDeserialize(undefined)).toBeNull();
  });

  test('deserializa arrays', () => {
    expect(safeDeserialize('[1,2,3]')).toEqual([1, 2, 3]);
  });
});

describe('CryptoLayer (passthrough en Node.js)', () => {
  test('init no lanza excepcion', async () => {
    const c = new CryptoLayer();
    await expect(c.init()).resolves.toBeUndefined();
  });

  test('encrypt retorna objeto cifrado en Node.js 20', async () => {
    const c = new CryptoLayer();
    await c.init();
    const result = await c.encrypt('hola mundo');
    expect(result).not.toBeNull();
  });

  test('decrypt de encrypt retorna texto original en Node.js 20', async () => {
    const c = new CryptoLayer();
    await c.init();
    const encrypted = await c.encrypt('hola mundo');
    const result = await c.decrypt(encrypted);
    expect(result).toBe('hola mundo');
  });

  test('encrypt retorna null para null', async () => {
    const c = new CryptoLayer();
    await c.init();
    expect(await c.encrypt(null)).toBeNull();
  });

  test('decrypt retorna null para null', async () => {
    const c = new CryptoLayer();
    await c.init();
    expect(await c.decrypt(null)).toBeNull();
  });
});

describe('OfflineQueue (sin IndexedDB)', () => {
  test('enqueue retorna null sin DB', async () => {
    const q = new OfflineQueue(null);
    const id = await q.enqueue('test_op', { data: 1 });
    expect(id).toBeNull();
  });

  test('getAll retorna array vacio sin DB', async () => {
    const q = new OfflineQueue(null);
    const items = await q.getAll();
    expect(items).toEqual([]);
  });

  test('size retorna 0 sin DB', async () => {
    const q = new OfflineQueue(null);
    expect(await q.size()).toBe(0);
  });

  test('dequeue retorna false sin DB', async () => {
    const q = new OfflineQueue(null);
    expect(await q.dequeue('any-id')).toBe(false);
  });

  test('enqueue retorna null con type null', async () => {
    const q = new OfflineQueue(null);
    expect(await q.enqueue(null, {})).toBeNull();
  });
});

describe('StateSnapshot (sin IndexedDB)', () => {
  test('save retorna false sin DB', async () => {
    const c = new CryptoLayer();
    await c.init();
    const s = new StateSnapshot(null, c);
    expect(await s.save('sess-1', { step: 1 })).toBe(false);
  });

  test('restore retorna null sin DB', async () => {
    const c = new CryptoLayer();
    await c.init();
    const s = new StateSnapshot(null, c);
    expect(await s.restore('sess-1')).toBeNull();
  });

  test('save retorna false con sessionId null', async () => {
    const c = new CryptoLayer();
    await c.init();
    const s = new StateSnapshot(null, c);
    expect(await s.save(null, { step: 1 })).toBe(false);
  });

  test('save retorna false con state null', async () => {
    const c = new CryptoLayer();
    await c.init();
    const s = new StateSnapshot(null, c);
    expect(await s.save('sess-1', null)).toBe(false);
  });

  test('restore retorna null con sessionId null', async () => {
    const c = new CryptoLayer();
    await c.init();
    const s = new StateSnapshot(null, c);
    expect(await s.restore(null)).toBeNull();
  });
});

describe('SyncManager', () => {
  test('sync retorna ceros sin sendFn', async () => {
    const q = new OfflineQueue(null);
    const sm = new SyncManager(q, null);
    const result = await sm.sync();
    expect(result).toEqual({ synced: 0, failed: 0, remaining: 0 });
  });

  test('sync con cola vacia retorna ceros', async () => {
    const q = new OfflineQueue(null);
    const sm = new SyncManager(q, async () => ({ ok: true }));
    const result = await sm.sync();
    expect(result.synced).toBe(0);
    expect(result.remaining).toBe(0);
  });

  test('no ejecuta sync concurrente', async () => {
    const q = new OfflineQueue(null);
    let calls = 0;
    const slowSend = async () => { calls++; return { ok: true }; };
    const sm = new SyncManager(q, slowSend);
    await Promise.all([sm.sync(), sm.sync(), sm.sync()]);
    expect(calls).toBe(0);
  });
});

describe('SessionGuard', () => {
  test('init retorna instancia', async () => {
    const g = new SessionGuard({});
    const result = await g.init();
    expect(result).toBe(g);
    await g.destroy();
  });

  test('sessionId es string no vacio', async () => {
    const g = new SessionGuard({});
    await g.init();
    expect(typeof g.sessionId).toBe('string');
    expect(g.sessionId.length).toBeGreaterThan(0);
    await g.destroy();
  });

  test('sessionId personalizado se respeta', async () => {
    const g = new SessionGuard({ sessionId: 'mi-sesion-123' });
    await g.init();
    expect(g.sessionId).toBe('mi-sesion-123');
    await g.destroy();
  });

  test('saveState retorna false antes de init', async () => {
    const g = new SessionGuard({});
    expect(await g.saveState({ data: 1 })).toBe(false);
  });

  test('saveState retorna false con state null', async () => {
    const g = new SessionGuard({});
    await g.init();
    expect(await g.saveState(null)).toBe(false);
    await g.destroy();
  });

  test('restoreState retorna null antes de init', async () => {
    const g = new SessionGuard({});
    expect(await g.restoreState()).toBeNull();
  });

  test('enqueue retorna null antes de init', async () => {
    const g = new SessionGuard({});
    expect(await g.enqueue('op', {})).toBeNull();
  });

  test('enqueue retorna null con type null', async () => {
    const g = new SessionGuard({});
    await g.init();
    expect(await g.enqueue(null, {})).toBeNull();
    await g.destroy();
  });

  test('stats retorna objeto con campos esperados', async () => {
    const g = new SessionGuard({});
    await g.init();
    const s = await g.stats();
    expect(s).toHaveProperty('version');
    expect(s).toHaveProperty('sessionId');
    expect(s).toHaveProperty('isOnline');
    expect(s).toHaveProperty('queueSize');
    expect(s).toHaveProperty('initialized');
    await g.destroy();
  });

  test('destroy desactiva initialized', async () => {
    const g = new SessionGuard({});
    await g.init();
    await g.destroy();
    expect(g._initialized).toBe(false);
  });

  test('onStateRestored no se llama si no hay estado previo', async () => {
    let called = false;
    const g = new SessionGuard({ onStateRestored: () => { called = true; } });
    await g.init();
    expect(called).toBe(false);
    await g.destroy();
  });
});
