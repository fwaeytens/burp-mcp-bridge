import test from 'node:test';
import assert from 'node:assert/strict';

import { createBridgeConfig } from '../lib/bridge-config.js';

test('createBridgeConfig normalizes IPv6 Burp targets and invalid numeric envs', () => {
  const config = createBridgeConfig({
    env: {
      BURP_MCP_SERVER_HOST: '::1',
      BURP_MCP_SERVER_PORT: '8089',
      BURP_MCP_REQUEST_TIMEOUT: 'not-a-number',
      MCP_USE_HTTPS: 'false',
      MCP_TRANSPORT_MODE: 'invalid'
    },
    bridgeDir: '/tmp/burp-mcp-bridge'
  });

  assert.equal(config.burpBaseUrl, 'http://[::1]:8089/');
  assert.equal(config.requestTimeout, 30_000);
  assert.equal(config.transportMode, 'both');
  assert.equal(config.httpSseTransportName, 'http-sse');
  assert.equal(config.keyFile, '/tmp/burp-mcp-bridge/certs/key.pem');
});

test('createBridgeConfig forces loopback binding by default', () => {
  const config = createBridgeConfig({
    env: { MCP_HTTP_HOST: '0.0.0.0' },
    bridgeDir: '/tmp/burp-mcp-bridge'
  });

  assert.equal(config.bindLoopbackOnly, true);
  assert.equal(config.httpHost, '127.0.0.1');
});
