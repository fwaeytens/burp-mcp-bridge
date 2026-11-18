import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { connect, callOk } from '../lib/session.js';
import { target } from '../lib/endpoints.js';

let client;
const T = target();
const URL_IN = `${T.base}/reflect`;

async function inScope() {
  const s = await callOk(client, 'burp_scope', { action: 'check', url: URL_IN });
  return s.inScope;
}

before(async () => { client = await connect(); });
after(() => client?.stop());

// The steps depend on each other (fresh project -> add -> remove), so they run
// in order within one test rather than as independent tests.
test('add, check, and remove scope for the target', async () => {
  assert.equal(await inScope(), false, 'a fresh project has nothing in scope');

  const added = await callOk(client, 'burp_scope', { action: 'add', url: `${T.base}/` });
  assert.equal(added.success, true);
  assert.equal(await inScope(), true);

  await callOk(client, 'burp_scope', { action: 'remove', url: `${T.base}/` });
  assert.equal(await inScope(), false);
});
