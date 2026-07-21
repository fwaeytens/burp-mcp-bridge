import test from 'node:test';
import assert from 'node:assert/strict';

import { sortJsonValue } from '../lib/json-utils.js';

test('sortJsonValue sorts object keys recursively without reordering arrays', () => {
  const sorted = sortJsonValue({
    z: { b: 2, a: 1 },
    a: [{ d: 4, c: 3 }]
  });

  assert.deepEqual(Object.keys(sorted), ['a', 'z']);
  assert.deepEqual(Object.keys(sorted.z), ['a', 'b']);
  assert.deepEqual(Object.keys(sorted.a[0]), ['c', 'd']);
});
