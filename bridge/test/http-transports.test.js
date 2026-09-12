import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const mockTools = [{ name: 'mock_tool', inputSchema: { type: 'object' } }];
const mockInstructions = 'Use burp_help for action requirements; use burp_http_jobs for background batches.';

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function closeServer(server) {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}

async function startBridge(t, mode, options = {}) {
  // Every bridge request goes to this isolated stub, never the user's Burp.
  const burp = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    const request = JSON.parse(body);
    if (request.method === 'initialize') await options.beforeInitialize?.();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: request.method === 'tools/list' ? { tools: mockTools }
        : request.method === 'initialize' ? { instructions: mockInstructions } : {}
    }));
  });
  const burpPort = await listen(burp);
  const clients = [];
  let transport;
  let startupTimer;
  t.after(async () => {
    clearTimeout(startupTimer);
    for (const client of clients.reverse()) await client.close();
    await transport?.close();
    await closeServer(burp);
  });

  const portProbe = createServer();
  const bridgePort = await listen(portProbe);
  await closeServer(portProbe);

  transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('../index.js', import.meta.url))],
    stderr: 'pipe',
    env: {
      BURP_MCP_SERVER_HOST: '127.0.0.1',
      BURP_MCP_SERVER_PORT: String(burpPort),
      BURP_MCP_REQUEST_TIMEOUT: '2000',
      MCP_HTTP_PORT: String(bridgePort),
      MCP_USE_HTTPS: 'false',
      MCP_TRANSPORT_MODE: mode,
      MCP_MAX_SSE: String(options.maxSseSessions ?? 100),
      MCP_MAX_HTTP_SESSIONS: String(options.maxHttpSessions ?? 100)
    }
  });
  let logs = '';
  const ready = new Promise((resolve, reject) => {
    startupTimer = setTimeout(() => reject(new Error(`Bridge did not start: ${logs}`)), 10_000);
    transport.stderr.on('data', (chunk) => {
      logs += chunk.toString();
      if (logs.includes('started and ready')) {
        clearTimeout(startupTimer);
        resolve();
      }
    });
  });

  let stdioClient;
  if (mode === 'both') {
    stdioClient = new Client({ name: 'stdio-test', version: '1' });
    clients.push(stdioClient);
    await Promise.all([stdioClient.connect(transport, { timeout: 5000 }), ready]);
  } else {
    await Promise.all([transport.start(), ready]);
  }

  return {
    url: new URL(`http://127.0.0.1:${bridgePort}/mcp`),
    stdioClient,
    async connectSse(name) {
      const client = new Client({ name, version: '1' });
      clients.push(client);
      await client.connect(new SSEClientTransport(this.url), { timeout: 5000 });
      return client;
    }
  };
}

for (const mode of ['both', 'http']) {
  test(`SSE clients initialize and remain independent in ${mode} mode`, { timeout: 20_000 }, async (t) => {
    const bridge = await startBridge(t, mode);
    // The SDK uses the sessionId query URL advertised by the SSE endpoint.
    const first = await bridge.connectSse('first-sse');
    const second = await bridge.connectSse('second-sse');
    const clients = [first, second, bridge.stdioClient].filter(Boolean);
    for (const client of clients) assert.equal(client.getInstructions(), mockInstructions);

    for (const result of await Promise.all(clients.map((client) => client.listTools()))) {
      assert.deepEqual(result.tools, mockTools);
    }
    const health = await fetch(new URL('/health', bridge.url)).then((res) => res.json());
    assert.equal(health.activeSseSessions, 2);
    assert.equal(health.activeHttpSessions, 0);

    await first.close();
    assert.deepEqual((await second.listTools()).tools, mockTools);
    if (bridge.stdioClient) {
      assert.deepEqual((await bridge.stdioClient.listTools()).tools, mockTools);
    }
  });
}

test('browser CORS headers support streamable HTTP session initialization and follow-up calls', { timeout: 20_000 }, async (t) => {
  const bridge = await startBridge(t, 'http');
  const origin = 'http://localhost:5173';
  const headers = { origin, 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  const init = await fetch(bridge.url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'browser-test', version: '1' } }
    })
  });
  assert.equal(init.status, 200);
  assert.equal(init.headers.get('access-control-allow-origin'), origin);
  const exposed = init.headers.get('access-control-expose-headers')?.toLowerCase().split(/,\s*/) ?? [];
  assert.ok(exposed.includes('mcp-session-id'), 'Browsers must be able to read the returned session ID');
  const sessionId = init.headers.get('mcp-session-id');
  assert.ok(sessionId);
  const initialized = await init.json();
  assert.equal(initialized.result.instructions, mockInstructions);

  const requestedHeaders = ['content-type', 'mcp-session-id', 'mcp-protocol-version'];
  const preflight = await fetch(bridge.url, {
    method: 'OPTIONS',
    headers: {
      origin,
      'access-control-request-method': 'POST',
      'access-control-request-headers': requestedHeaders.join(', ')
    }
  });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('access-control-allow-origin'), origin);
  const allowed = preflight.headers.get('access-control-allow-headers').toLowerCase().split(/,\s*/);
  for (const header of requestedHeaders) assert.ok(allowed.includes(header), `Preflight must allow ${header}`);

  headers['mcp-session-id'] = sessionId;
  headers['mcp-protocol-version'] = initialized.result.protocolVersion;
  const notified = await fetch(bridge.url, {
    method: 'POST', headers,
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })
  });
  assert.equal(notified.status, 202);
  const listed = await fetch(bridge.url, {
    method: 'POST', headers,
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
  });
  assert.equal(listed.status, 200);
  assert.deepEqual((await listed.json()).result.tools, mockTools);
  const terminated = await fetch(bridge.url, { method: 'DELETE', headers });
  assert.equal(terminated.status, 200);
});

for (const kind of ['SSE', 'streamable HTTP']) {
  test(`${kind} disconnect during guidance lookup releases session resources`, { timeout: 20_000 }, async (t) => {
    let releaseGuidance;
    let lookupStarted;
    const guidanceGate = new Promise((resolve) => { releaseGuidance = resolve; });
    const lookup = new Promise((resolve) => { lookupStarted = resolve; });
    const bridge = await startBridge(t, 'http', {
      maxSseSessions: 1,
      maxHttpSessions: 1,
      beforeInitialize: async () => { lookupStarted(); await guidanceGate; }
    });
    const initialize = {
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'abandoned-client', version: '1' } }
    };
    const aborted = httpRequest(bridge.url, {
      method: kind === 'SSE' ? 'GET' : 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }
    });
    aborted.on('error', () => {});
    aborted.end(kind === 'SSE' ? undefined : JSON.stringify(initialize));
    try {
      await lookup; // The backend has received initialization, but cannot reply yet.
      const closed = new Promise((resolve) => aborted.once('close', resolve));
      aborted.destroy();
      await closed;
      let health;
      for (let attempt = 0; attempt < 20; attempt++) {
        health = await fetch(new URL('/health', bridge.url)).then((response) => response.json());
        if (health.activeSseSessions === 0 && health.activeHttpSessions === 0) break;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      assert.equal(health.activeSseSessions, 0, 'Abandoned SSE lookup must immediately release its capacity');
      assert.equal(health.activeHttpSessions, 0, 'Abandoned HTTP lookup must not retain a session');
    } finally {
      releaseGuidance();
    }

    if (kind === 'SSE') {
      const client = await bridge.connectSse('recovered-client');
      assert.deepEqual((await client.listTools()).tools, mockTools);
      assert.equal(client.getInstructions(), mockInstructions);
    } else {
      const response = await fetch(bridge.url, {
        method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
        body: JSON.stringify(initialize)
      });
      assert.equal(response.status, 200, 'A fresh client must be able to initialize after the abandoned lookup');
      assert.equal((await response.json()).result.instructions, mockInstructions);
      const sessionId = response.headers.get('mcp-session-id');
      assert.ok(sessionId);
      const health = await fetch(new URL('/health', bridge.url)).then((result) => result.json());
      assert.equal(health.activeHttpSessions, 1, 'Only the replacement HTTP session should be retained');
      const terminated = await fetch(bridge.url, { method: 'DELETE', headers: { 'mcp-session-id': sessionId } });
      assert.equal(terminated.status, 200);
    }
  });
}
