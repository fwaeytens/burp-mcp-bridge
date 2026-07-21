import test from 'node:test';
import assert from 'node:assert/strict';

import { prepareToolArguments } from '../lib/mcp-tool-handlers.js';

test('prepareToolArguments repairs normal custom HTTP requests', () => {
  const args = prepareToolArguments('burp_custom_http', {
    action: 'SEND_REQUEST',
    request: 'POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\nhello'
  });

  assert.match(args.request, /Content-Length: 5/);
});

test('prepareToolArguments preserves byte-exact and pipelined custom HTTP requests', () => {
  const rawRequest = 'POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\nhello';

  assert.equal(
    prepareToolArguments('burp_custom_http', { raw_request: true, request: rawRequest }).request,
    rawRequest
  );
  assert.deepEqual(
    prepareToolArguments('burp_custom_http', { action: 'SEND_PIPELINED', requests: [rawRequest] }).requests,
    [rawRequest]
  );
});
