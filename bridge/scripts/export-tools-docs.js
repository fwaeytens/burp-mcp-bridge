#!/usr/bin/env node

import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createBridgeConfig } from '../lib/bridge-config.js';
import { BurpJsonRpcClient } from '../lib/burp-json-rpc-client.js';
import { sortJsonValue } from '../lib/json-utils.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const bridgeDir = resolve(__dirname, '..');

export async function exportToolsDocs({
  outputPath = resolve(bridgeDir, '..', 'docs', 'tools.json'),
  env = process.env,
  fetchImpl = globalThis.fetch
} = {}) {
  const config = createBridgeConfig({ env, bridgeDir });
  const client = new BurpJsonRpcClient({
    baseUrl: config.burpBaseUrl,
    version: config.bridgeVersion,
    requestTimeout: config.requestTimeout,
    fetchImpl
  });

  const response = await client.call('docs/export', {});
  if (response.error) {
    throw new Error(response.error.message || 'docs/export failed');
  }

  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(sortJsonValue(response.result), null, 2)}\n`, 'utf8');
  return outputPath;
}

if (process.argv[1] && resolve(process.argv[1]) === __filename) {
  exportToolsDocs()
    .then((outputPath) => {
      console.log(`Wrote ${outputPath}`);
    })
    .catch((error) => {
      console.error(`Failed to export tool docs: ${error.message}`);
      process.exitCode = 1;
    });
}
