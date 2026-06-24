/**
 * tests/e2e/session_guard.e2e.test.js — Tests E2E browser↔backend.
 *
 * Checklist pre-release post-#10 (docs/DOD-v0.5.0.md §5), omisión O#8:
 * "Tests E2E browser ↔ backend para verificación de .vtrc en
 * session_guard.js". NOTA DE ALCANCE IMPORTANTE, verificada contra el
 * código real antes de escribir este archivo: session_guard.js (v0.1.0)
 * NO implementa ni referencia el formato .vtrc en absoluto — es el
 * módulo de continuidad de sesión del navegador (StateSnapshot,
 * OfflineQueue, SyncManager con idempotency keys genéricas), anterior a
 * toda la fase criptográfica (.vtrc nace en la propuesta #7/vtrc_bundle.py,
 * v0.5.0). La omisión O#8 tal como está redactada en el roadmap asume
 * una integración que el código actual no tiene.
 *
 * Esta suite cierra la omisión O#8 EN SU INTENCIÓN REAL — pruebas E2E
 * genuinas del flujo browser↔backend de session_guard.js, contra un
 * servidor HTTP real, no contra un mock de función — y documenta
 * explícitamente que la integración con .vtrc es trabajo FUTURO
 * separado (conectar SyncManager.sendFn a crypto_layer/vtrc_bundle.py
 * vía el backend, no algo que pueda probarse hoy porque no existe esa
 * integración en el código).
 *
 * Diferencia deliberada con tests/session_guard.test.js (41 tests
 * unitarios existentes): esos tests usan OfflineQueue(null) (sin
 * IndexedDB) y dependen de que CryptoLayer entre en modo passthrough.
 * Esta suite usa fake-indexeddb (persistencia real) y confirma que en
 * Node 22 Web Crypto SÍ está disponible nativamente — el cifrado
 * AES-GCM real se ejercita de verdad, no en modo passthrough. Y usa un
 * servidor http.createServer() real en vez de un sendFn simulado.
 *
 * VTR — Vector Telemetry Research © 2026
 */

'use strict';

// ---------------------------------------------------------------------------
// Polyfill de Web Crypto para Node < 19 — SOLO para este arnés de pruebas.
//
// HALLAZGO REAL encontrado al validar esta suite en un entorno real
// (Node 18.19.1, distinto del entorno de desarrollo en Node 22.x donde
// globalThis.crypto ya es nativo): globalThis.crypto con Web Crypto API
// NO es global por defecto en Node < 19 — llegó global recién en Node
// 19+. session_guard.js asume correctamente que está en un browser real
// (donde crypto SIEMPRE es global desde hace años) — ese código no se
// toca ni se "corrige", porque no tiene ningún defecto: el supuesto es
// válido para su entorno de ejecución real (el navegador).
//
// El polyfill vive aquí, en el arnés de pruebas, no en session_guard.js,
// porque el problema es específico de ejecutar código de browser dentro
// de Node para testing — un browser real nunca necesita esto. Sin este
// polyfill en Node 18, CryptoLayer.init() entra en modo passthrough
// (session_guard.js ya maneja ese caso de forma defensiva y correcta —
// ver su propio código: `if (!crypto.subtle) { this._key = null; }`),
// y esta suite perdería su propósito principal de probar CIFRADO REAL,
// quedando indistinguible de los tests unitarios existentes en
// tests/session_guard.test.js (que sí corren en modo passthrough
// deliberadamente).
if (typeof globalThis.crypto === 'undefined') {
  // eslint-disable-next-line global-require
  globalThis.crypto = require('node:crypto').webcrypto;
}

require('fake-indexeddb/auto');

const { SessionGuard } = require('../../src/session_guard.js');
const { createTestServer, makeRealSendFn } = require('./test_server.js');

describe('Confirmación de entorno E2E', () => {
  test('Web Crypto (crypto.subtle) está disponible — cifrado real, no passthrough', () => {
    expect(typeof globalThis.crypto).toBe('object');
    expect(typeof globalThis.crypto.subtle).toBe('object');
  });

  test('crypto.randomUUID está disponible — uuidv4() no usa el fallback Math.random()', () => {
    expect(typeof globalThis.crypto.randomUUID).toBe('function');
  });

  test('fetch nativo está disponible — sendFn real usa fetch, no un polyfill', () => {
    expect(typeof globalThis.fetch).toBe('function');
  });

  test('indexedDB está disponible vía fake-indexeddb — persistencia real, no null', () => {
    expect(typeof globalThis.indexedDB).toBe('object');
  });
});

describe('E2E: flujo completo offline-to-sync contra servidor HTTP real', () => {
  let testServer;
  let activeGuards;

  // Aislamiento real entre tests: DB_NAME/STORE_QUEUE en session_guard.js
  // son constantes globales fijas (no parametrizadas por test), así que
  // sin limpieza explícita cada test heredaría filas dejadas por el
  // anterior. NOTA sobre un intento descartado durante el desarrollo de
  // esta suite: usar indexedDB.deleteDatabase() entre tests parecía la
  // forma más limpia, pero CUELGA INDEFINIDAMENTE — session_guard.js
  // nunca cierra sus conexiones IndexedDB (openDB() abre, pero ninguna
  // clase llama a db.close() en ningún punto del módulo), así que
  // deleteDatabase() siempre dispara el evento 'blocked' contra
  // conexiones de tests anteriores que quedan abiertas, y la promesa
  // subyacente de fake-indexeddb nunca termina de liberar el handle.
  // Esto no se "arregla" parchando session_guard.js (fuera del alcance
  // de esta tarea, y cambiar el ciclo de vida de la conexión podría
  // tener efectos en producción que no se pidió evaluar) — se evita
  // limpiando explícitamente vía la propia API pública del módulo
  // (queue.clear(), snapshot.clear()) en vez de pelear contra el ciclo
  // de vida de la conexión IndexedDB subyacente.

  beforeEach(() => {
    activeGuards = [];
  });

  afterEach(async () => {
    for (const guard of activeGuards) {
      try {
        if (guard._queue) await guard._queue.clear();
        if (guard._snapshot) await guard._snapshot.clear(guard.sessionId);
      } catch (_) {
        // best-effort — un guard ya destruido por el test mismo puede
        // fallar aquí sin que sea un problema real para el siguiente test
      }
    }
    activeGuards = [];

    if (testServer) {
      await testServer.close();
      testServer = null;
    }
  });

  /**
   * Crea un SessionGuard ya inicializado y lo registra para limpieza
   * automática en afterEach — evita que cada test tenga que recordar
   * limpiar su propia cola/snapshot manualmente.
   */
  async function createTrackedGuard(opts) {
    const guard = new SessionGuard(opts || {});
    await guard.init();
    activeGuards.push(guard);
    return guard;
  }

  test('SessionGuard completo: init real con cifrado AES-GCM real', async () => {
    const guard = await createTrackedGuard();

    expect(guard.sessionId).toBeTruthy();
    expect(typeof guard.sessionId).toBe('string');
  });

  test('saveState/restoreState round-trip con cifrado AES-GCM real (no passthrough)', async () => {
    const guard = await createTrackedGuard();

    const originalState = { step: 3, formData: { campo: 'valor-sensible-123' } };
    const saved = await guard.saveState(originalState);
    expect(saved).toBe(true);

    const restored = await guard.restoreState();
    expect(restored).toEqual(originalState);
  });

  test('HALLAZGO REAL: snapshot cifrado NUNCA sobrevive entre instancias distintas de CryptoLayer', async () => {
    // Verificado contra el código real durante el desarrollo de esta
    // suite, no asumido: CryptoLayer.init() genera una clave AES-GCM
    // nueva en cada llamada, con el flag 'extractable' en false
    // (session_guard.js: `crypto.subtle.generateKey(..., false, ...)`)
    // — es decir, NO EXPORTABLE por diseño (mitigación de XSS
    // documentada en el encabezado del propio módulo). Consecuencia
    // directa, confirmada aquí: cualquier snapshot cifrado por una
    // instancia de SessionGuard es irrecuperable para CUALQUIER otra
    // instancia, incluida una segunda instancia con el MISMO sessionId
    // — porque decrypt() con la clave equivocada no lanza excepción,
    // retorna null silenciosamente (mismo contrato que el resto de
    // crypto_layer en Python: falla esperada, no excepción). Esto NO es
    // un bug — es la mitigación de XSS funcionando exactamente como se
    // diseñó. Pero significa que "persistencia de sesión entre recargas
    // de página" NO es una garantía real de este módulo en su forma
    // actual — cada recarga de página pierde el acceso a cualquier
    // snapshot cifrado previamente, sin importar que IndexedDB sí
    // conserve los bytes cifrados intactos.
    const sessionId = 'e2e-cross-instance-test';

    const guard1 = new SessionGuard({ sessionId });
    await guard1.init();
    await guard1.saveState({ paso: 'guardado-por-guard1' });
    if (guard1._db) guard1._db.close(); // simula descarga real de la pestaña

    const guard2 = await createTrackedGuard({ sessionId });
    const restored = await guard2.restoreState();

    // El registro SIGUE en IndexedDB (otra instancia con la clave
    // correcta lo confirmaría) — lo que no sobrevive es la capacidad
    // de DESCIFRARLO con una clave distinta.
    expect(restored).toBeNull();
  });

  test('saveState/restoreState SÍ persisten dentro de la misma instancia (recuperación sin recarga)', async () => {
    // Contraparte del test anterior: la garantía real que sí cumple
    // StateSnapshot es continuidad DENTRO de la vida de una instancia
    // — el escenario real que session_guard.js documenta en su
    // encabezado (UPS Virtual: recuperación de sesión ante cortes de
    // CONECTIVIDAD, no ante recarga de la pestaña). Mientras la misma
    // instancia de CryptoLayer siga viva, saveState/restoreState
    // funcionan de extremo a extremo con cifrado real.
    const sessionId = 'e2e-same-instance-test';
    const guard = await createTrackedGuard({ sessionId });

    await guard.saveState({ paso: 1 });
    const afterFirstSave = await guard.restoreState();
    expect(afterFirstSave).toEqual({ paso: 1 });

    await guard.saveState({ paso: 2 });
    const afterSecondSave = await guard.restoreState();
    expect(afterSecondSave).toEqual({ paso: 2 });
  });

  test('enqueue real + sync contra servidor HTTP real: items llegan con idempotency key correcta', async () => {
    testServer = await createTestServer();
    const sendFn = makeRealSendFn(testServer.port);
    const guard = await createTrackedGuard({ sendFn });

    const key1 = await guard.enqueue('telemetry', { sensor: 'A1', value: 42 });
    const key2 = await guard.enqueue('telemetry', { sensor: 'A2', value: 99 });

    expect(key1).toBeTruthy();
    expect(key2).toBeTruthy();
    expect(key1).not.toBe(key2);

    const result = await guard._sync.sync();

    expect(result).toEqual({ synced: 2, failed: 0, remaining: 0 });
    expect(testServer.requestLog).toHaveLength(2);
    expect(testServer.requestLog.map((r) => r.idempotencyKey)).toEqual(
      expect.arrayContaining([key1, key2])
    );
  });

  test('payload real llega íntegro y deserializado al servidor real', async () => {
    testServer = await createTestServer();
    const sendFn = makeRealSendFn(testServer.port);
    const guard = await createTrackedGuard({ sendFn });

    const originalPayload = { sensor: 'B7', readings: [1.1, 2.2, 3.3], nested: { ok: true } };
    await guard.enqueue('telemetry', originalPayload);
    await guard._sync.sync();

    expect(testServer.requestLog).toHaveLength(1);
    expect(testServer.requestLog[0].payload).toEqual(originalPayload);
  });

  test('4xx real del servidor: item se descarta, los siguientes SÍ se sincronizan', async () => {
    testServer = await createTestServer({
      responder: (_body, index) =>
        index === 0
          ? { statusCode: 400, body: { error: 'malformed' } }
          : { statusCode: 202, body: { accepted: true } },
    });
    const sendFn = makeRealSendFn(testServer.port);
    const guard = await createTrackedGuard({ sendFn });

    await guard.enqueue('telemetry', { sensor: 'BAD' });
    await guard.enqueue('telemetry', { sensor: 'GOOD-1' });
    await guard.enqueue('telemetry', { sensor: 'GOOD-2' });

    const result = await guard._sync.sync();

    expect(result).toEqual({ synced: 2, failed: 1, remaining: 0 });
    expect(testServer.requestLog).toHaveLength(3); // los 3 SÍ llegaron al servidor
  });

  test('5xx real del servidor: sync se detiene, items restantes NO se intentan', async () => {
    testServer = await createTestServer({
      responder: (_body, index) =>
        index === 1
          ? { statusCode: 503, body: { error: 'server overloaded' } }
          : { statusCode: 202, body: { accepted: true } },
    });
    const sendFn = makeRealSendFn(testServer.port);
    const guard = await createTrackedGuard({ sendFn });

    await guard.enqueue('telemetry', { sensor: 'OK-1' });
    await guard.enqueue('telemetry', { sensor: 'FAILS-503' });
    await guard.enqueue('telemetry', { sensor: 'NEVER-TRIED' });

    const result = await guard._sync.sync();

    expect(result).toEqual({ synced: 1, failed: 0, remaining: 2 });
    // Confirma que el servidor real solo recibió 2 requests, no 3 —
    // el tercer item nunca llegó a intentarse, no solo que el contador
    // de 'failed' se quedó en 0.
    expect(testServer.requestLog).toHaveLength(2);
  });

  test('item fallido con 5xx permanece en la cola para reintento posterior', async () => {
    testServer = await createTestServer({
      responder: () => ({ statusCode: 503, body: { error: 'down' } }),
    });
    const sendFn = makeRealSendFn(testServer.port);
    const guard = await createTrackedGuard({ sendFn });

    await guard.enqueue('telemetry', { sensor: 'WILL-RETRY' });
    await guard._sync.sync();

    const remainingItems = await guard._queue.getAll();
    expect(remainingItems).toHaveLength(1);
    expect(JSON.parse(remainingItems[0].payload)).toEqual({ sensor: 'WILL-RETRY' });
  });

  test('reintento exitoso tras recuperación del servidor: item retenido se sincroniza', async () => {
    let serverDown = true;
    testServer = await createTestServer({
      responder: () =>
        serverDown
          ? { statusCode: 503, body: { error: 'down' } }
          : { statusCode: 202, body: { accepted: true } },
    });
    const sendFn = makeRealSendFn(testServer.port);
    const guard = await createTrackedGuard({ sendFn });

    await guard.enqueue('telemetry', { sensor: 'RETRY-ME' });

    const firstAttempt = await guard._sync.sync();
    expect(firstAttempt.remaining).toBe(1);

    serverDown = false; // el "backend" se recupera
    const secondAttempt = await guard._sync.sync();
    expect(secondAttempt).toEqual({ synced: 1, failed: 0, remaining: 0 });
  });

  test('múltiples idempotency keys son únicas en un lote real de 10 items', async () => {
    testServer = await createTestServer();
    const sendFn = makeRealSendFn(testServer.port);
    const guard = await createTrackedGuard({ sendFn });

    const keys = [];
    for (let i = 0; i < 10; i++) {
      const k = await guard.enqueue('telemetry', { sensor: `S${i}` });
      keys.push(k);
    }

    const result = await guard._sync.sync();
    expect(result.synced).toBe(10);

    const uniqueKeys = new Set(keys);
    expect(uniqueKeys.size).toBe(10);

    const receivedKeys = testServer.requestLog.map((r) => r.idempotencyKey);
    expect(new Set(receivedKeys).size).toBe(10);
  });

  test('orden FIFO real: los items se envían al servidor en el orden en que se encolaron', async () => {
    // HALLAZGO REAL encontrado al desarrollar esta suite, confirmado
    // contra el código fuente: OfflineQueue.enqueue() usa Date.now()
    // (resolución de 1ms) como ÚNICA clave de orden FIFO
    // (getAll() hace .sort((a,b) => (a.ts||0)-(b.ts||0)) sobre ese
    // campo). Si dos enqueue() consecutivos caen en el mismo
    // milisegundo —cosa que ocurre con frecuencia real medible en este
    // entorno, no es un caso de borde teórico— el orden de salida ante
    // ese empate es NO DETERMINÍSTICO: depende del orden lexicográfico
    // del UUID id generado (aleatorio), no del orden real de llamada a
    // enqueue(). Esto es una limitación real del diseño actual de
    // session_guard.js, no un defecto de este test — se documenta aquí
    // en vez de ocultarse forzando un timing artificial sin explicar
    // por qué hace falta.
    testServer = await createTestServer();
    const sendFn = makeRealSendFn(testServer.port);
    const guard = await createTrackedGuard({ sendFn });

    // Se fuerza separación temporal real (>1ms) entre cada enqueue()
    // precisamente para neutralizar la limitación documentada arriba y
    // poder probar el caso SIN colisión — el caso CON colisión está
    // cubierto por el test siguiente.
    await guard.enqueue('telemetry', { orden: 1 });
    await new Promise((resolve) => setTimeout(resolve, 2));
    await guard.enqueue('telemetry', { orden: 2 });
    await new Promise((resolve) => setTimeout(resolve, 2));
    await guard.enqueue('telemetry', { orden: 3 });

    await guard._sync.sync();

    const ordenRecibido = testServer.requestLog.map((r) => r.payload.orden);
    expect(ordenRecibido).toEqual([1, 2, 3]);
  });

  test('HALLAZGO REAL: orden FIFO no es determinístico ante colisión de Date.now() en el mismo ms', async () => {
    // Test que documenta activamente la limitación encontrada arriba,
    // en vez de solo mencionarla en un comentario. No afirma un orden
    // específico (porque por diseño es no determinístico) — afirma
    // únicamente lo que SÍ es verdad sin importar el orden de
    // resolución: los tres items llegan, ninguno se pierde, ninguno se
    // duplica.
    testServer = await createTestServer();
    const sendFn = makeRealSendFn(testServer.port);
    const guard = await createTrackedGuard({ sendFn });

    // Sin espera entre encolados — exprime deliberadamente el caso de
    // colisión de milisegundo para que el test sea representativo del
    // hallazgo, no para evitarlo.
    await guard.enqueue('telemetry', { orden: 1 });
    await guard.enqueue('telemetry', { orden: 2 });
    await guard.enqueue('telemetry', { orden: 3 });

    await guard._sync.sync();

    const ordenRecibido = testServer.requestLog.map((r) => r.payload.orden);
    expect(ordenRecibido).toHaveLength(3);
    expect(new Set(ordenRecibido)).toEqual(new Set([1, 2, 3]));
  });
});

describe('Alcance NO cubierto por esta suite (documentado, no implementado)', () => {
  test('NOTA: integración con formato .vtrc no existe en session_guard.js todavía', () => {
    // Este test no verifica nada del código de producción más allá de
    // su propio texto fuente — existe para que el resultado de la
    // suite (verde) no se interprete erróneamente como "la
    // verificación .vtrc en el browser ya está probada". No lo está,
    // porque session_guard.js no la implementa. Ver docstring de este
    // archivo y docs/DOD-v0.5.0.md §5 (omisión O#8) para el detalle
    // completo de esta brecha de alcance.
    const fs = require('fs');
    const source = fs.readFileSync(
      require('path').join(__dirname, '../../src/session_guard.js'),
      'utf8'
    );
    expect(source).not.toMatch(/vtrc/i);
  });
});
