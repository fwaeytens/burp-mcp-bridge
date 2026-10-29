import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { connect, marker, callOk, historyMatching } from '../lib/session.js';
import { proxyGet } from '../lib/traffic.js';

let client;
let id;
const m = marker('ra');

before(async () => {
  client = await connect();
  await proxyGet(`/reflect?q=${m}`);
  [{ id }] = await historyMatching(client, m);
});
after(() => client?.stop());

test('reflection with proxyIds reports the reflected query parameter', async () => {
  const s = await callOk(client, 'burp_response_analyzer', { action: 'reflection', proxyIds: [id] });
  assert.equal(s.operation, 'reflection');
  assert.deepEqual(s.requestedProxyIds, [id]);
  assert.equal(s.entriesAnalyzed, 1);
  const point = s.reflectionPoints.find((p) => p.url.includes(m));
  assert.ok(point, `no reflection point for ${m}: ${JSON.stringify(s.reflectionPoints)}`);
  assert.deepEqual(point.reflections.q, ['URL parameter']);
  assert.equal(point.responseCode, 200);
});
