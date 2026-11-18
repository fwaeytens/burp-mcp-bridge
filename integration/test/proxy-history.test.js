import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { connect, marker, callOk, historyMatching } from '../lib/session.js';
import { proxyGet } from '../lib/traffic.js';
import { onlyBundled, target } from '../lib/endpoints.js';
import { execInBurp } from '../lib/stack.js';

let client;
const m = marker('ph');
// A separate marker for the unanswered request, so the tests on m's three
// answered entries keep their counts and neighbours.
const nr = marker('nr');
const T = target();

before(async () => {
  client = await connect();
  await proxyGet(`/reflect?q=${m}a`);
  await proxyGet(`/json?m=${m}`);
  await proxyGet(`/status/418?m=${m}`);
  // The mock server drops this connection without a response. (curl still gets
  // a 200: Burp's own error page, which is not recorded as the response.)
  await proxyGet(`/hangup?m=${nr}`);
});
after(() => client?.stop());

test('list returns the captured target requests with methods and status codes', async () => {
  const mine = await historyMatching(client, m);
  assert.equal(mine.length, 3);
  assert.deepEqual(mine.map((e) => e.status), [200, 200, 418]);
  for (const e of mine) assert.equal(e.method, 'GET');
});

// On a history with no deletions, Burp's # runs 1..N, so ids must too. This
// cannot tell "id == #" apart from "id == list position" (they coincide when
// there are no gaps); the gap case stays a unit test with non-contiguous fakes.
test('entry ids run 1..total on a gap-free history', async () => {
  const s = await callOk(client, 'burp_proxy_history', { action: 'list', limit: 10000 });
  const ids = s.entries.map((e) => e.id).sort((a, b) => a - b);
  assert.equal(ids.length, s.total);
  assert.deepEqual(ids, Array.from({ length: s.total }, (_, i) => i + 1));
});

test('detail by id returns that entry with full request and response', async () => {
  const [e] = await historyMatching(client, `${m}a`);
  const s = await callOk(client, 'burp_proxy_history', { action: 'detail', entryIds: [e.id] });
  assert.equal(s.entries.length, 1);
  const d = s.entries[0];
  assert.equal(d.id, e.id);
  assert.equal(d.url, e.url);
  assert.equal(d.host, T.host);
  assert.equal(d.port, T.port);
  assert.equal(d.secure, false);
  assert.match(d.request, new RegExp(`^GET /reflect\\?q=${m}a HTTP/1\\.1`));
  assert.equal(d.response.statusCode, 200);
  assert.match(d.response.body, new RegExp(`reflected:\\[${m}a\\]`));
});

// BUG: iterate treats startAt as a 1-based position in the filtered list,
// reversed newest-first by default (recent=true), and reports that position as
// `entryNumber`. So its numbers are neither Burp's # nor the `id` that
// list/detail/annotate use — the same class of bug d5af19d fixed for
// list/detail. This test fails until iterate is fixed. Compared by URL so it
// does not prescribe the field name a fix should use.
test('iterate from startAt=<Burp #> walks the same entries list reports', async () => {
  const mine = await historyMatching(client, m);
  const s = await callOk(client, 'burp_proxy_history', {
    action: 'iterate', startAt: mine[0].id, count: 3
  });
  assert.deepEqual(s.entries.map((e) => e.url), mine.map((e) => e.url));
});

test('afterEntry / beforeEntry bound the list by entry id', async () => {
  const [first, mid, last] = await historyMatching(client, m);
  const s = await callOk(client, 'burp_proxy_history', {
    action: 'list', afterEntry: first.id, beforeEntry: last.id, limit: 10000
  });
  // Only this file's entries: a Burp you point the suite at may see other
  // traffic (e.g. a browser) land in between.
  assert.deepEqual(s.entries.filter((e) => e.url.includes(m)).map((e) => e.id), [mid.id]);
});

test('a request the server never answered is recorded without a response', async () => {
  const [e] = await historyMatching(client, nr);
  assert.ok(e, 'the unanswered /hangup request is in proxy history');
  assert.equal(e.status, null);

  const d = (await callOk(client, 'burp_proxy_history', { action: 'detail', entryIds: [e.id] })).entries[0];
  assert.equal(d.id, e.id);
  assert.match(d.request, new RegExp(`^GET /hangup\\?m=${nr} HTTP/1\\.1`));
  assert.equal(d.response, undefined);

  const s = await callOk(client, 'burp_proxy_history', { action: 'list', hasResponse: false, limit: 10000 });
  assert.ok(s.entries.some((x) => x.id === e.id), 'hasResponse:false finds it');
});

// CURRENT BEHAVIOUR, to be confirmed with the extension author: the statusCode
// filter only rejects entries whose response has a different code, so entries
// with no response at all pass it (ProxyHistoryTool.java, the statusCode check
// in applyFilters). The unanswered /hangup request therefore shows up when
// asking for 418s. If that is changed, flip the last assertion.
test('statusCode and hostname filters narrow the list; unanswered requests slip through', async () => {
  const s = await callOk(client, 'burp_proxy_history', {
    action: 'list', hostname: T.host, statusCode: 418, limit: 10000
  });
  assert.ok(s.entries.every((e) => e.url.startsWith(`${T.base}/`)), 'hostname filter');
  const answered = s.entries.filter((e) => e.status !== null);
  assert.ok(answered.every((e) => e.status === 418), 'answered entries all have the requested code');
  assert.ok(answered.some((e) => e.url.includes(m)), "this file's 418 is found");
  assert.ok(s.entries.some((e) => e.url.includes(nr) && e.status === null),
    'the unanswered request passes the statusCode filter');
});

// Commit d5af19d: ids are Burp's history numbers (the # column), not positions
// in api.proxy().history(). The two only differ once an entry is deleted, and
// the Montoya API cannot delete history, so this test deletes one through
// Burp's UI (burp/delete-history-row.sh) — hence bundled Burp only. Deliberately
// LAST in this file: everything above assumes a gap-free history.
//
// Against a build without the fix, the entry after the gap takes the deleted
// entry's number, so the subtests below fail.
//
// DISABLED: clicking Burp's UI by screen coordinates with xdotool is flaky (the
// same run deleted the row once and missed it the next time). To be replaced by
// a test-only helper extension that drives the Swing components from inside
// Burp's JVM by label instead of by pixel; then use onlyBundled() (or drop the
// restriction) again.
const DISABLED_UI_DELETION = { skip: 'disabled: xdotool UI deletion is flaky; see comment' };
test('after deleting an entry in Burp, ids stay Burp history numbers', DISABLED_UI_DELETION, async (t) => {
  const gp = marker('gp');
  for (const s of ['a', 'b', 'c']) await proxyGet(`/json?m=${gp}${s}`);
  const [a, b, c] = await historyMatching(client, gp);
  assert.deepEqual([a, b, c].map((e) => e.url.slice(-1)), ['a', 'b', 'c']);

  // The UI table is sorted by #, one row per entry; find b's row.
  const all = (await callOk(client, 'burp_proxy_history', { action: 'list', limit: 10000 })).entries;
  const row = all.map((e) => e.id).sort((x, y) => x - y).indexOf(b.id) + 1;
  assert.ok(row >= 1 && row <= 12, `entry is on UI row ${row}; the script only reaches rows 1-12 without scrolling`);
  execInBurp(['delete-history-row.sh', String(row)]);

  // Verify the deletion by URL, independently of ids: a mis-click must show up
  // as a UI failure, not as a pass or fail of the id fix.
  const urls = (await callOk(client, 'burp_proxy_history', { action: 'list', limit: 10000 })).entries.map((e) => e.url);
  assert.ok(!urls.includes(b.url), `UI deletion did not remove ${b.url} (row ${row}); screenshot the Burp display to recalibrate`);
  assert.ok(urls.includes(a.url) && urls.includes(c.url), 'UI deletion removed the wrong entry');

  await t.test('list keeps the surviving entries\' numbers', async () => {
    const after = await historyMatching(client, gp);
    assert.deepEqual(after.map((e) => [e.url, e.id]), [[a.url, a.id], [c.url, c.id]]);
  });

  await t.test('detail finds the entry after the gap by its number', async () => {
    const d = (await callOk(client, 'burp_proxy_history', { action: 'detail', entryIds: [c.id] })).entries[0];
    assert.equal(d.url, c.url);
  });

  await t.test('detail on the deleted number is not_found', async () => {
    const d = (await callOk(client, 'burp_proxy_history', { action: 'detail', entryIds: [b.id] })).entries[0];
    assert.equal(d.error, 'not_found', `got ${d.url ?? JSON.stringify(d)}`);
  });

  await t.test('annotate by number lands on the entry after the gap', async () => {
    await callOk(client, 'burp_annotate', { action: 'ANNOTATE_PROXY', entryId: c.id, notes: `gap-${gp}` });
    const noted = (await callOk(client, 'burp_proxy_history', { action: 'list', hasNotes: true, limit: 10000 }))
      .entries.filter((e) => e.url.includes(gp)).map((e) => e.url);
    await callOk(client, 'burp_annotate', { action: 'CLEAR_ANNOTATIONS', entryId: c.id });
    assert.deepEqual(noted, [c.url]);
  });
});
