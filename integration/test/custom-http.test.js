import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { connect, marker, callOk, historyMatching } from '../lib/session.js';
import { proxyInBurp, target } from '../lib/endpoints.js';

let client;
const m = marker('ch');
const T = target();
let sent;

before(async () => {
  client = await connect();
  // SEND_REQUEST routes through Burp's own proxy listener, which is what puts
  // it in proxy history. Name the listener as Burp sees it rather than relying
  // on the tool's 127.0.0.1:8080 default.
  //
  // The request line carries the scheme: without one the tool picks TLS for
  // any port but 80, and the mock server speaks plain HTTP on whatever port it
  // gets outside compose.
  const listener = proxyInBurp();
  sent = await callOk(client, 'burp_custom_http', {
    action: 'SEND_REQUEST',
    request: `GET ${T.base}/json?m=${m} HTTP/1.1\r\nHost: ${T.host}:${T.port}\r\nConnection: close\r\n\r\n`,
    proxy_host: listener.host,
    proxy_port: listener.port
  });
});
after(() => client?.stop());

test('SEND_REQUEST reaches the target through Burp', () => {
  assert.equal(sent.success, true);
  assert.equal(sent.routed_via_proxy, true);
  assert.equal(sent.request.url, `${T.base}/json?m=${m}`);
  assert.equal(sent.response.status_code, 200);
  assert.equal(JSON.parse(sent.response.body).service, 'integration-target');
});

test('the sent request appears in proxy history exactly once', async () => {
  const mine = await historyMatching(client, m);
  assert.equal(mine.length, 1);
  assert.equal(mine[0].status, 200);
});

test('the sent request appears in the site map', async () => {
  // `target` is a URL-prefix filter, so the run-unique URL matches only itself.
  const s = await callOk(client, 'burp_sitemap_analysis', {
    action: 'ANALYZE_STRUCTURE', target: `${T.base}/json?m=${m}`
  });
  assert.equal(s.success, true, s.message);
  assert.equal(s.totalEntries, 1);
});
