// P-256 recorder keys: PKCS#8 PEM on disk (0600), key_id = first 16 hex of
// SHA256(SPKI DER). P-256 (not Ed25519) because Rekor hashedrekord verifies
// over a pre-hashed digest, which pure Ed25519 cannot do (rekor#851).
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir, platform } from 'node:os';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

export interface KeyPair {
  keyId: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicPem: string;
}

export function attestorHome(): string {
  return process.env.ATTESTOR_HOME ?? join(homedir(), '.attestor');
}

export function keysDir(home: string = attestorHome()): string {
  return join(home, 'keys');
}

export function keyIdOf(publicKey: KeyObject): string {
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(spki).digest('hex').slice(0, 16);
}

function toKeyPair(privateKey: KeyObject): KeyPair {
  const publicKey = createPublicKey(privateKey);
  return {
    keyId: keyIdOf(publicKey),
    privateKey,
    publicKey,
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

export function generateKey(
  home: string = attestorHome(),
  passphrase?: string,
): KeyPair {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pair = toKeyPair(privateKey);
  const dir = keysDir(home);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const pem = passphrase
    ? privateKey.export({
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase,
      })
    : privateKey.export({ type: 'pkcs8', format: 'pem' });
  const keyPath = join(dir, `${pair.keyId}.pem`);
  writeFileSync(keyPath, pem, { mode: 0o600 });
  writeFileSync(join(dir, `${pair.keyId}.pub`), pair.publicPem, { mode: 0o644 });
  protectKeyFile(keyPath);
  return pair;
}

/**
 * Restrict a private key to the current user.
 *
 * POSIX mode bits are applied at write time and are enough there. On Windows
 * they are silently ignored — the file inherits the parent directory's ACL, so
 * a key written with `mode: 0o600` can still be readable by other accounts on
 * the machine. Since the whole product rests on that key, fix the ACL with
 * `icacls` (remove inheritance, grant only the current user) and, if that
 * cannot be done, say so loudly rather than pretending the key is protected.
 */
export function protectKeyFile(keyPath: string): { protected: boolean; detail: string } {
  if (platform() !== 'win32') {
    return { protected: true, detail: 'POSIX mode 0600' };
  }
  const user = process.env.USERNAME;
  if (user === undefined || user === '') {
    warnUnprotected(keyPath, 'USERNAME is not set, so the owning account is unknown');
    return { protected: false, detail: 'no USERNAME' };
  }
  // Domain-qualify when possible: a bare name is ambiguous if a local and a
  // domain account share it. Fall back to the bare name if there is no domain.
  const domain = process.env.USERDOMAIN;
  const principals = domain !== undefined && domain !== '' ? [`${domain}\\${user}`, user] : [user];
  // /inheritance:r drops inherited entries; /grant:r replaces any existing
  // grant for this user with full control and nothing else.
  let why = 'unknown error';
  for (const principal of principals) {
    const res = spawnSync('icacls', [keyPath, '/inheritance:r', '/grant:r', `${principal}:F`], {
      stdio: 'pipe',
      windowsHide: true,
    });
    if (res.status === 0) {
      return { protected: true, detail: `icacls: only ${principal} has access` };
    }
    why =
      (res.stderr?.toString() || res.stdout?.toString() || res.error?.message || `exit ${res.status}`)
        .trim()
        .split('\n')[0] ?? 'unknown error';
  }
  warnUnprotected(keyPath, why);
  return { protected: false, detail: why };
}

function warnUnprotected(keyPath: string, why: string): void {
  process.stderr.write(
    `[attestor] WARNING: could not restrict permissions on the signing key\n` +
      `  ${keyPath}\n` +
      `  reason: ${why}\n` +
      `  On Windows, file permissions are not applied by default, so other accounts on\n` +
      `  this machine may be able to read it. Anyone with this key can sign entries that\n` +
      `  verify as genuine. Restrict it yourself with:\n` +
      `    icacls "${keyPath}" /inheritance:r /grant:r "%USERNAME%:F"\n`,
  );
}

/**
 * True for any pinned Rekor log key file, legacy or keyed by log ID.
 *
 * These are public keys stored in the same directory as recorder private keys.
 * Recorder key discovery must skip all of them: selecting one yields an
 * OpenSSL error from deep inside key loading rather than a usable key, and
 * because pins are written after key generation the newest-first active-key
 * rule would select a pin in preference to the real signing key.
 */
export function isRekorPinFile(name: string): boolean {
  return name.startsWith('rekor-pub') && name.endsWith('.pem');
}

/** Key ids, oldest first (mtime order) — the last one is the active key. */
export function listKeyIds(home: string = attestorHome()): string[] {
  const dir = keysDir(home);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.pem') && !isRekorPinFile(f))
    .map((f) => ({ id: f.slice(0, -'.pem'.length), mtime: statSync(join(dir, f)).mtimeMs }))
    .sort((a, b) => a.mtime - b.mtime)
    .map((k) => k.id);
}

export function loadKey(
  home: string = attestorHome(),
  keyId?: string,
  passphrase?: string,
): KeyPair {
  const ids = listKeyIds(home);
  const id = keyId ?? ids[ids.length - 1];
  if (!id) throw new Error(`no keys found in ${keysDir(home)} — run: attestor keys init`);
  const pem = readFileSync(join(keysDir(home), `${id}.pem`), 'utf8');
  const privateKey = passphrase
    ? createPrivateKey({ key: pem, passphrase })
    : createPrivateKey(pem);
  const pair = toKeyPair(privateKey);
  if (pair.keyId !== id) {
    throw new Error(`key file ${id}.pem contains key with id ${pair.keyId}`);
  }
  return pair;
}

export function publicKeyFromPem(pem: string): KeyObject {
  return createPublicKey(pem);
}
