#!/usr/bin/env node
/**
 * Deterministic HTTP target for the integration suite.
 *
 * Every route returns a fixed, predictable response so assertions never depend
 * on the open internet. The server listens on 0.0.0.0 so it is reachable from
 * the burp container over the compose network (service name `target`).
 *
 * Routes:
 *   GET  /                      simple HTML landing page
 *   GET  /reflect?q=<value>     reflects <value> into the HTML body (response
 *                               analyzer "reflection" tests)
 *   GET  /json                  a small JSON document
 *   GET  /set-cookie            sets a cookie, 200
 *   GET  /redirect              302 -> /redirected
 *   GET  /redirected            200 "arrived"
 *   GET  /status/<code>         responds with the given status code
 *   GET  /slow?ms=<n>           responds after n ms (bounded)
 *   GET  /hangup                closes the connection without sending any
 *                               response, so Burp records a request that was
 *                               never answered
 *   *    anything else          404
 *
 * No dependencies: Node's built-in http only, so the target image is tiny.
 */
import { createServer } from 'node:http';

const PORT = Number(process.env.TARGET_PORT || 80);

function html(body) {
  return `<!doctype html><html><head><title>integration target</title></head><body>${body}</body></html>`;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const server = createServer((req, res) => {
  const url = new URL(req.url, 'http://target');
  const path = url.pathname;

  if (path === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html('<h1>integration target</h1><p>deterministic responses for burp-mcp-bridge tests</p>'));
    return;
  }

  if (path === '/reflect') {
    // Reflect the raw query value into the body. The sentinel markers make it
    // trivial for a test to assert the value round-tripped through Burp.
    const q = url.searchParams.get('q') ?? '';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html(`<p>reflected:[${escapeHtml(q)}]</p>`));
    return;
  }

  if (path === '/json') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'integration-target', items: [1, 2, 3] }));
    return;
  }

  if (path === '/set-cookie') {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Set-Cookie': 'session=deadbeef; Path=/; HttpOnly'
    });
    res.end(html('<p>cookie set</p>'));
    return;
  }

  if (path === '/redirect') {
    res.writeHead(302, { Location: '/redirected' });
    res.end();
    return;
  }

  if (path === '/redirected') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html('<p>arrived</p>'));
    return;
  }

  const statusMatch = path.match(/^\/status\/(\d{3})$/);
  if (statusMatch) {
    const code = Number(statusMatch[1]);
    res.writeHead(code, { 'Content-Type': 'text/plain' });
    res.end(`status ${code}`);
    return;
  }

  if (path === '/hangup') {
    // No status line, no headers, nothing: just drop the TCP connection.
    req.socket.destroy();
    return;
  }

  if (path === '/slow') {
    const ms = Math.min(Number(url.searchParams.get('ms') || 500), 5000);
    setTimeout(() => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`waited ${ms}ms`);
    }, ms);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('not found');
});

server.listen(PORT, '0.0.0.0', () => {
  // eslint-disable-next-line no-console
  console.log(`integration target listening on 0.0.0.0:${PORT}`);
});
