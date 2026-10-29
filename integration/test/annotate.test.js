import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { connect, marker, callOk, historyMatching } from '../lib/session.js';
import { proxyGet } from '../lib/traffic.js';

let client;
let id;
const m = marker('an');

async function detail() {
  const s = await callOk(client, 'burp_proxy_history', { action: 'detail', entryIds: [id] });
  return s.entries[0];
}

before(async () => {
  client = await connect();
  await proxyGet(`/json?m=${m}`);
  [{ id }] = await historyMatching(client, m);
});
after(() => client?.stop());

test('annotating by entryId round-trips through proxy history', async () => {
  await callOk(client, 'burp_annotate', {
    action: 'ANNOTATE_PROXY', entryId: id, notes: `note-${m}`, highlightColor: 'RED'
  });
  const d = await detail();
  assert.equal(d.notes, `note-${m}`);
  assert.match(d.highlight, /^red$/i);
});

test('hasNotes filter finds the annotated entry', async () => {
  const s = await callOk(client, 'burp_proxy_history', { action: 'list', hasNotes: true, limit: 10000 });
  assert.ok(s.entries.some((e) => e.id === id));
});

test('clearing by entryId removes notes and highlight', async () => {
  await callOk(client, 'burp_annotate', { action: 'CLEAR_ANNOTATIONS', entryId: id });
  const d = await detail();
  assert.equal(d.notes, undefined);
  assert.equal(d.highlight, undefined);
});
