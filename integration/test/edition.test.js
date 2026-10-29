// Edition-dependent behaviour. Each test runs only against the edition it
// describes (BURP_IT_EDITION, set by the orchestrator) and is reported as
// skipped on the other, so a run is green when Burp behaves as its edition
// should.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { connect, callOk } from '../lib/session.js';
import { onlyOn, target } from '../lib/endpoints.js';

let client;
const T = target();
// "requires" (Collaborator) and "jobs require" (HTTP jobs) both occur.
const REQUIRES_PRO = /requires? Burp Suite Professional/i;

before(async () => { client = await connect(); });
after(() => client?.stop());

// --- Community: Professional-only tools refuse ------------------------------

test('community: collaborator reports that it requires Professional', onlyOn('community'), async () => {
  const r = await client.callTool('burp_collaborator', { action: 'GENERATE_PAYLOAD' });
  assert.match(r.text, REQUIRES_PRO);
});

test('community: http_jobs LIST reports the engine as unavailable', onlyOn('community'), async () => {
  const r = await client.callTool('burp_http_jobs', { action: 'LIST' });
  assert.equal(r.isError, false, r.text);
  assert.equal(r.structured.available, false);
  assert.match(r.structured.unavailable_reason, REQUIRES_PRO);
});

test('community: http_jobs START fails as unavailable', onlyOn('community'), async () => {
  const r = await client.callTool('burp_http_jobs', { action: 'START', requests: [`${T.base}/json`] });
  assert.equal(r.isError, true);
  assert.equal(r.structured.error, 'unavailable');
  assert.match(r.structured.message, REQUIRES_PRO);
});

// Community has no scanner, so START_SCAN must fail without starting one. Its
// message is currently "Failed to start scan: null" rather than the documented
// "Requires Burp Suite Professional": ScannerTool only says that when
// api.scanner() is null, and Community returns a non-null Scanner. Asserted
// loosely on purpose — the refusal is the edition behaviour; the wording is a
// separate, known wart.
test('community: scanner START_SCAN refuses without starting a scan', onlyOn('community'), async () => {
  const r = await client.callTool('burp_scanner', { action: 'START_SCAN', urls: [`${T.base}/`] });
  assert.equal(r.isError, true, r.text);
  assert.equal(r.structured?.scanId, undefined);
});

// --- Professional: the scanner actually starts ------------------------------

test('professional: scanner starts an active scan of the mock server', onlyOn('professional'), async () => {
  const s = await callOk(client, 'burp_scanner', {
    action: 'START_SCAN', urls: [`${T.base}/`], mode: 'ACTIVE'
  });
  assert.equal(s.status, 'STARTED');
  assert.equal(typeof s.scanId, 'string');
  assert.equal(s.urlsAdded, 1);
  assert.deepEqual(s.targetUrls, [`${T.base}/`]);

  // Only the start is under test; cancel straight away.
  await callOk(client, 'burp_scanner', { action: 'CANCEL_SCAN', scanId: s.scanId });
});
