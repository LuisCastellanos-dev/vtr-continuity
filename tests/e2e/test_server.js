/**
 * tests/e2e/test_server.js — Servidor HTTP real para tests E2E.
 *
 * Checklist pre-release post-#10 (docs/DOD-v0.5.0.md §5), omisión O#8:
 * tests E2E browser↔backend para session_guard.js. Este módulo NO es un
 * mock de función (como los tests unitarios existentes en
 * tests/session_guard.test.js, que pasan un sendFn de juguete) — es un
 * servidor http.createServer() real, escuchando en un puerto real,
 * recibiendo requests HTTP reales desde SyncManager.sync().
 *
 * Simula el contrato de rpi/proxy.py POST /events (ver
 * docs/VTR-THREAT-001.md S-3/T-3/R-3/D-3/I-3 sobre ese endpoint real —
 * este servidor de prueba es deliberadamente más simple, solo lo
 * necesario para ejercitar SyncManager de verdad).
 *
 * VTR — Vector Telemetry Research © 2026
 */

'use strict';

const http = require('http');

/**
 * Crea un servidor HTTP real configurable por comportamiento de
 * respuesta. El servidor escucha en POST /events, igual que el
 * endpoint real de rpi/proxy.py.
 *
 * @param {Object} opts
 * @param {Function} [opts.responder] — (parsedBody, requestIndex) => { statusCode, body }
 *   Por defecto, acepta todo con 202 (comportamiento "happy path" de
 *   rpi/proxy.py: POST /events retorna 202 Accepted).
 * @param {Function} [opts.onRequest] — callback (parsedBody, requestIndex) llamado
 *   en cada request recibido, antes de responder — para que los tests
 *   puedan inspeccionar exactamente qué llegó al "servidor".
 * @returns {Promise<{server: http.Server, port: number, close: Function, requestLog: Array}>}
 */
function createTestServer(opts) {
  const options = opts || {};
  const responder =
    typeof options.responder === 'function'
      ? options.responder
      : () => ({ statusCode: 202, body: { accepted: true } });
  const onRequest = typeof options.onRequest === 'function' ? options.onRequest : () => {};

  const requestLog = [];

  const server = http.createServer((req, res) => {
    if (req.method !== 'POST' || req.url !== '/events') {
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }

    let rawBody = '';
    req.on('data', (chunk) => {
      rawBody += chunk;
    });
    req.on('end', () => {
      let parsed;
      try {
        parsed = JSON.parse(rawBody);
      } catch (_) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'invalid json' }));
        return;
      }

      const index = requestLog.length;
      requestLog.push(parsed);
      onRequest(parsed, index);

      const result = responder(parsed, index);
      res.writeHead(result.statusCode, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result.body || {}));
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        server,
        port,
        requestLog,
        close: () => new Promise((res) => server.close(res)),
      });
    });
  });
}

/**
 * Construye una función sendFn real que hace HTTP POST de verdad contra
 * el servidor de prueba — exactamente la forma en que un
 * SessionGuard/SyncManager real haría la petición desde un browser real
 * (fetch real, no un wrapper simulado).
 *
 * @param {number} port
 * @returns {Function} async (item) => { ok, status }
 */
function makeRealSendFn(port) {
  return async function sendFn(item) {
    const res = await fetch(`http://127.0.0.1:${port}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(item),
    });
    return { ok: res.status === 202, status: res.status };
  };
}

module.exports = { createTestServer, makeRealSendFn };
