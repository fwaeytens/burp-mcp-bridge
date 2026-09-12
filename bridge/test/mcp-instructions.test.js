import test from 'node:test';
import assert from 'node:assert/strict';

import { FALLBACK_INSTRUCTIONS, loadMcpInstructions } from '../lib/mcp-instructions.js';

test('initialization uses the extension guidance and preserves current wording', async () => {
  const instructions = 'Use the current action schemas. START returns job_id.';
  const result = await loadMcpInstructions(async (method, params) => {
    assert.equal(method, 'initialize');
    assert.equal(params.clientInfo.version, '2.9.0');
    return { result: { instructions } };
  }, '2.9.0');
  assert.equal(result, instructions);
});

test('missing or unavailable extension guidance retains useful discovery instructions', async () => {
  for (const response of [{ result: {} }, { result: { instructions: ' ' } },
    { result: { instructions: 123 } }, { error: { message: 'Older extension' } }]) {
    assert.equal(await loadMcpInstructions(async () => response, '2.9.0'), FALLBACK_INSTRUCTIONS);
  }
  assert.match(FALLBACK_INSTRUCTIONS, /burp_help/);
  assert.match(FALLBACK_INSTRUCTIONS, /burp_http_jobs/);
  assert.match(FALLBACK_INSTRUCTIONS, /pagination does not imply job completion/);
});

test('a failed guidance lookup can recover for a later MCP connection', async () => {
  let attempts = 0;
  const lookup = async () => {
    if (++attempts === 1) throw new Error('Burp is starting');
    return { result: { instructions: 'Recovered extension guidance' } };
  };
  assert.equal(await loadMcpInstructions(lookup, '2.9.0'), FALLBACK_INSTRUCTIONS);
  assert.equal(await loadMcpInstructions(lookup, '2.9.0'), 'Recovered extension guidance');
  assert.equal(attempts, 2);
});
