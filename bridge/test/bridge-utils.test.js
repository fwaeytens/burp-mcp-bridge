import test from 'node:test';
import assert from 'node:assert/strict';

import {
  MAX_RESULT_CHARS,
  bracketIpv6,
  fixContentLength,
  hostHeaderToHostname,
  normalizeBareHostEntry,
  stripIpv6Brackets,
  toInt,
  truncateResult
} from '../lib/bridge-utils.js';

test('fixContentLength rewrites existing lengths using UTF-8 bytes', () => {
  const request = 'POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\nhello';
  assert.equal(
    fixContentLength(request),
    'POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello'
  );
});

test('fixContentLength adds a missing header and leaves empty bodies alone', () => {
  assert.equal(
    fixContentLength('POST / HTTP/1.1\r\nHost: example.test\r\n\r\nhello'),
    'POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello'
  );
  assert.equal(
    fixContentLength('GET / HTTP/1.1\r\nHost: example.test\r\n\r\n'),
    'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n'
  );
});

test('truncateResult preserves a schema-compatible structured fallback', () => {
  const result = {
    content: [{ type: 'text', text: 'short' }],
    structuredContent: { payload: 'x'.repeat(MAX_RESULT_CHARS) }
  };

  const truncated = truncateResult(result);
  assert.equal(truncated.structuredContent.truncated, true);
  assert.equal(truncated.structuredContent.limitChars, MAX_RESULT_CHARS);
  assert.match(truncated.structuredContent.text, /⚠️ Result truncated/);
  assert.deepEqual(truncated.content, result.content);
});

test('truncateResult bounds oversized text content', () => {
  const result = { content: [{ type: 'text', text: 'x'.repeat(MAX_RESULT_CHARS + 1000) }] };
  const truncated = truncateResult(result);
  assert.equal(truncated.content.length, 2);
  assert.match(truncated.content[1].text, /⚠️ Result truncated/);
  assert.equal(truncated.structuredContent.truncated, true);
  assert.ok(JSON.stringify(truncated).length <= MAX_RESULT_CHARS);
});

test('host helpers normalize IPv6 and parse integer environment values', () => {
  assert.equal(bracketIpv6('::1'), '[::1]');
  assert.equal(stripIpv6Brackets('[::1]'), '::1');
  assert.equal(hostHeaderToHostname('[::1]:3000'), '::1');
  assert.equal(normalizeBareHostEntry('[::1]:3000'), '::1:3000');
  assert.equal(toInt(' 8081 ', 1), 8081);
  assert.equal(toInt('', 8081), 8081);
});
