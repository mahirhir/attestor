// Tests for `attestor doctor` command
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'src', 'cli.ts');

test('attestor doctor runs and checks environment', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-doctor-'));
  const home = join(dir, 'home');
  mkdirSync(home, { recursive: true });

  const { stdout } = await exec(process.execPath, [CLI, 'doctor'], {
    cwd: dir,
    env: { ...process.env, ATTESTOR_HOME: home, ATTESTOR_OFFLINE: '1' },
  });

  assert.match(stdout, /attestor doctor/);
  assert.match(stdout, /Node runtime version/);
  assert.match(stdout, /ATTESTOR_HOME directory/);
});
