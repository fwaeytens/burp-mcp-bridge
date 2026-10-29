// Generate traffic that flows through Burp's proxy so it lands in proxy history
// and the site map. Requests go to the mock server at the address Burp uses for
// it (lib/endpoints.js target()); Burp, not the runner, connects to it.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { proxyUrl, target } from './endpoints.js';

const execFileP = promisify(execFile);

// --noproxy '' clears NO_PROXY for this request. curl honours NO_PROXY even with
// an explicit -x, and the sandbox lists 127.0.0.1 there, so without it a
// loopback target would be fetched directly and never pass through Burp.
function curlArgs(timeoutMs) {
  return ['-s', '--max-time', String(Math.ceil(timeoutMs / 1000)), '--noproxy', '', '-x', proxyUrl()];
}

/**
 * Fetch `path` on the mock server through Burp's proxy. Returns { status, url }.
 * Uses curl so the on-the-wire request is a normal proxied GET (curl emits
 * absolute-form request lines to the proxy), independent of Node's http stack.
 */
export async function proxyGet(path, { timeoutMs = 15000 } = {}) {
  const url = `${target().base}${path}`;
  const args = [...curlArgs(timeoutMs), '-o', '/dev/null', '-w', '%{http_code}', url];
  const { stdout } = await execFileP('curl', args, { timeout: timeoutMs + 2000 });
  return { status: Number(stdout.trim()), url };
}

/** Same, but return the response body (for reflection assertions). */
export async function proxyGetBody(path, { timeoutMs = 15000 } = {}) {
  const url = `${target().base}${path}`;
  const { stdout } = await execFileP('curl', [...curlArgs(timeoutMs), url], { timeout: timeoutMs + 2000 });
  return { body: stdout, url };
}
