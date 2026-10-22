// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import type { IdentityMessageContext } from '../packages/protocol-types/src/index.js';

test('shared Rust fixture preserves exact camelCase fields', async () => {
  const context: IdentityMessageContext = JSON.parse(await readFile(new URL('./identity-runtime-fixture.json', import.meta.url), 'utf8'));
  assert.equal(context.profile, 'oan-message-v1');
  assert.equal(context.protocol, 'http');
  const rustFixture = JSON.parse(await readFile(new URL('../../oan-protocol-common/test-fixtures/identity-runtime/message-context.json', import.meta.url), 'utf8'));
  assert.deepEqual(context, rustFixture);
});
