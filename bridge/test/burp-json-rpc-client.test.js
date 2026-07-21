import test from 'node:test';
import assert from 'node:assert/strict';

import { BurpJsonRpcClient } from '../lib/burp-json-rpc-client.js';

test('BurpJsonRpcClient posts JSON-RPC requests with correlation headers', async () => {
  let seenUrl;
  let seenOptions;
  const client = new BurpJsonRpcClient({
    baseUrl: 'http://localhost:8081/',
    version: '2.8.1',
    requestTimeout: 1000,
    fetchImpl: async (url, options) => {
      seenUrl = url;
      seenOptions = options;
      return {
        ok: true,
        text: async () => JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } })
      };
    }
  });

  const response = await client.call('tools/list', {}, { rid: 'rid-1', toolName: 'burp_help' });

  assert.equal(seenUrl, 'http://localhost:8081/');
  assert.equal(seenOptions.method, 'POST');
  assert.equal(seenOptions.headers['User-Agent'], 'Burp-MCP-Bridge/2.8.1');
  assert.equal(seenOptions.headers['X-Request-Id'], 'rid-1');
  assert.equal(seenOptions.headers['X-Tool-Name'], 'burp_help');
  assert.equal(JSON.parse(seenOptions.body).method, 'tools/list');
  assert.deepEqual(response.result, { ok: true });
});

test('BurpJsonRpcClient rejects malformed JSON-RPC responses', async () => {
  const client = new BurpJsonRpcClient({
    baseUrl: 'http://localhost:8081/',
    version: '2.8.1',
    requestTimeout: 1000,
    fetchImpl: async () => ({
      ok: true,
      text: async () => JSON.stringify({ status: 'ok' })
    })
  });

  await assert.rejects(() => client.call('ping', {}), /Invalid JSON-RPC response/);
});
