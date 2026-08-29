// Tests for `attestor --version` and `attestor -v`
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'src', 'cli.ts');
const PKG = join(here, '..', 'package.json');

test('attestor --version prints package version', async () => {
  const pkg = JSON.parse(readFileSync(PKG, 'utf8')) as { version: string };
  const { stdout } = await exec(process.execPath, [CLI, '--version']);
  assert.equal(stdout.trim(), pkg.version);
});

test('attestor -v prints package version', async () => {
  const pkg = JSON.parse(readFileSync(PKG, 'utf8')) as { version: string };
  const { stdout } = await exec(process.execPath, [CLI, '-v']);
  assert.equal(stdout.trim(), pkg.version);
});
