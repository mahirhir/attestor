// Rekor client tests: node:http mock asserting exact hashedrekord body shape,
// 201/409 paths, pending-queue retry/backoff, SET + inclusion + note verify
// against the live fixture captured by spike #0. Opt-in live smoke via
// ATTESTOR_LIVE=1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKey } from '../src/keys.ts';
import { canonicalCoreBytes, coreOf, Ledger, readEntries, sha256Hex } from '../src/ledger.ts';
import { writeCheckpoint } from '../src/checkpoint.ts';
import {
  anchorCheckpoint,
  backoffMs,
  getEntry,
  hashedRekordBody,
  postEntry,
  readPending,
  retryPending,
  UntrustedRekorKeyError,
  verifyCheckpointNote,
  verifyRekorInclusion,
  verifyRekorKeyTrust,
  verifySET,
  type RekorEntry,
} from '../src/rekor.ts';
import { verifyLedger } from '../src/verify.ts';
import { fakeRekor, rekorEntryFor, tmp } from './helpers.ts';

const fixturePath = join(dirname(fileURLToPath(import.meta.url)), 'vectors', 'rekor-live-fixture.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
  request_body: Record<string, unknown>;
  post_response: Record<string, RekorEntry>;
  get_response: Record<string, RekorEntry>;
  rekor_log_public_key_pem: string;
  artifact_b64: string;
};
const fixtureUuid = Object.keys(fixture.post_response)[0]!;
const fixtureEntry = fixture.get_response[fixtureUuid] ?? fixture.post_response[fixtureUuid]!;

// ---------- fixture-based verification (the fiddly 40 lines) ----------

test('SET verifies against the captured live Rekor entry', () => {
  assert.ok(verifySET(fixtureEntry, fixture.rekor_log_public_key_pem));
  assert.ok(!verifySET({ ...fixtureEntry, integratedTime: fixtureEntry.integratedTime + 1 }, fixture.rekor_log_public_key_pem));
  assert.ok(!verifySET({ ...fixtureEntry, logIndex: fixtureEntry.logIndex + 1 }, fixture.rekor_log_public_key_pem));
});

test('inclusion proof verifies against the captured live entry', () => {
  assert.ok(verifyRekorInclusion(fixtureEntry));
  const tampered = structuredClone(fixtureEntry);
  tampered.verification!.inclusionProof!.hashes[0] = 'ff'.repeat(32);
  assert.ok(!verifyRekorInclusion(tampered));
});

test('signed checkpoint note verifies against the live Rekor log key', () => {
  assert.ok(verifyCheckpointNote(fixtureEntry.verification!.inclusionProof!, fixture.rekor_log_public_key_pem));
  const wrongKeyNote = structuredClone(fixtureEntry.verification!.inclusionProof!);
  assert.ok(!verifyCheckpointNote(wrongKeyNote, fixture_pem_other()));
});

function fixture_pem_other(): string {
  // any other valid P-256 key — reuse the recorder key from the fixture request
  const b64 = (fixture.request_body as { spec: { signature: { publicKey: { content: string } } } })
    .spec.signature.publicKey.content;
  return Buffer.from(b64, 'base64').toString('utf8');
}

test('hashedrekord body matches the shape Rekor accepted live', () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const artifact = Buffer.from('test artifact');
  const body = hashedRekordBody(artifact, keys);
  const live = fixture.request_body as typeof body;
  assert.equal(body.apiVersion, live.apiVersion);
  assert.equal(body.kind, live.kind);
  assert.deepEqual(Object.keys(body.spec).sort(), Object.keys(live.spec).sort());
  assert.equal(body.spec.data.hash.algorithm, 'sha256');
  assert.equal(body.spec.data.hash.value, sha256Hex(artifact));
  assert.match(body.spec.data.hash.value, /^[0-9a-f]{64}$/);
});

// ---------- node:http mock ----------

interface MockRekor {
  server: Server;
  url: string;
  posts: Record<string, unknown>[];
  mode: 'ok' | 'dup' | 'down' | 'ratelimit' | 'divergent' | 'roguekey';
  close: () => Promise<void>;
}

function startMockRekor(): Promise<MockRekor> {
  const rekor = fakeRekor();
  const posts: Record<string, unknown>[] = [];
  const stored = new Map<string, unknown>(); // uuid → served entry
  const state = { mode: 'ok' as MockRekor['mode'] };
  const server = createServer((req, res) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      if (state.mode === 'down') {
        res.writeHead(500).end('mock down');
        return;
      }
      if (state.mode === 'ratelimit') {
        res.writeHead(429).end('slow down');
        return;
      }
      if (req.method === 'POST' && req.url === '/api/v1/log/entries') {
        const parsed = JSON.parse(data) as Record<string, unknown>;
        posts.push(parsed);
        const { uuid, ...entry } = rekorEntryFor(rekor, parsed);
        stored.set(uuid, entry);
        if (state.mode === 'dup') {
          res.writeHead(409, { Location: `/api/v1/log/entries/${uuid}` }).end();
          return;
        }
        res.writeHead(201, { 'Content-Type': 'application/json' }).end(JSON.stringify({ [uuid]: entry }));
        return;
      }
      if (req.method === 'GET' && req.url?.startsWith('/api/v1/log/entries/')) {
        const uuid = req.url.split('/').pop()!;
        let entry = stored.get(uuid);
        if (state.mode === 'divergent') {
          const { uuid: _u, ...div } = rekorEntryFor(rekor, { divergent: true });
          entry = div;
        }
        if (!entry) {
          res.writeHead(404).end();
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ [uuid]: entry }));
        return;
      }
      if (req.method === 'GET' && req.url === '/api/v1/log/publicKey') {
        // roguekey: the live key endpoint serves a key that never signed
        // anything in this log (substitution attack at the point of use)
        const served = state.mode === 'roguekey' ? fakeRekor().publicPem : rekor.publicPem;
        res.writeHead(200, { 'Content-Type': 'application/x-pem-file' }).end(served);
        return;
      }
      res.writeHead(404).end();
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      resolve({
        server,
        url: `http://127.0.0.1:${addr.port}`,
        posts,
        close: () => new Promise<void>((r) => server.close(() => r())),
        get mode() {
          return state.mode;
        },
        set mode(m: MockRekor['mode']) {
          state.mode = m;
        },
      });
    });
  });
}

test('anchorCheckpoint POSTs exact hashedrekord body and appends anchor entry', async () => {
  const mock = await startMockRekor();
  const dir = tmp();
  const home = join(dir, 'home');
  const keys = generateKey(home);
  process.env.ATTESTOR_HOME = home;
  try {
    const ledger = Ledger.open(join(dir, 'ledger'), keys);
    ledger.append({ type: 'wire', origin: 'proxy', payload: '"x"' });
    const ckpt = writeCheckpoint(ledger);
    const anchorEntry = await anchorCheckpoint(ledger, ckpt, { baseUrl: mock.url });
    ledger.close();

    assert.ok(anchorEntry);
    assert.equal(mock.posts.length, 1);
    const post = mock.posts[0] as { apiVersion: string; kind: string; spec: { data: { hash: { algorithm: string; value: string } }; signature: { content: string; publicKey: { content: string } } } };
    assert.equal(post.apiVersion, '0.0.1');
    assert.equal(post.kind, 'hashedrekord');
    const artifact = canonicalCoreBytes(coreOf(ckpt as unknown as Record<string, unknown>));
    assert.equal(post.spec.data.hash.value, sha256Hex(artifact));
    assert.equal(
      Buffer.from(post.spec.signature.publicKey.content, 'base64').toString('utf8'),
      keys.publicPem,
    );

    const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
    const anchor = entries.find((e) => e.type === 'anchor');
    assert.ok(anchor?.payload);
    const payload = JSON.parse(anchor.payload) as { checkpoint_seq: number; provider: string; logIndex: number };
    assert.equal(payload.checkpoint_seq, ckpt.seq);
    assert.equal(payload.provider, 'rekor-v1');
    assert.equal(typeof payload.logIndex, 'number');
    assert.ok(existsSync(join(dir, 'ledger', 'anchors', `${ckpt.seq}.json`)));
    assert.ok(existsSync(join(dir, 'ledger', 'anchors', 'rekor-pub.pem')));
  } finally {
    delete process.env.ATTESTOR_HOME;
    await mock.close();
  }
});

test('409 duplicate: follows Location and still records the anchor', async () => {
  const mock = await startMockRekor();
  mock.mode = 'dup';
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  process.env.ATTESTOR_HOME = join(dir, 'home');
  try {
    const ledger = Ledger.open(join(dir, 'ledger'), keys);
    const ckpt = writeCheckpoint(ledger);
    const anchorEntry = await anchorCheckpoint(ledger, ckpt, { baseUrl: mock.url });
    ledger.close();
    assert.ok(anchorEntry, 'anchor recorded via 409+Location path');
  } finally {
    delete process.env.ATTESTOR_HOME;
    await mock.close();
  }
});

test('rekor down: anchor queued to pending.jsonl, recording never blocked; retry drains', async () => {
  const mock = await startMockRekor();
  mock.mode = 'down';
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  process.env.ATTESTOR_HOME = join(dir, 'home');
  try {
    const ledger = Ledger.open(join(dir, 'ledger'), keys);
    const ckpt = writeCheckpoint(ledger);
    const result = await anchorCheckpoint(ledger, ckpt, { baseUrl: mock.url });
    assert.equal(result, undefined);
    let pending = readPending(ledger.dir);
    assert.equal(pending.length, 1);
    assert.equal(pending[0]!.checkpoint_seq, ckpt.seq);
    assert.ok(pending[0]!.next_at > Date.now(), 'backoff scheduled in the future');

    // not yet due → untouched
    assert.equal(await retryPending(ledger, { baseUrl: mock.url }), 0);
    assert.equal(readPending(ledger.dir).length, 1);

    // due but still down → attempts increment
    assert.equal(await retryPending(ledger, { baseUrl: mock.url, now: Date.now() + 3_600_000 }), 0);
    pending = readPending(ledger.dir);
    assert.equal(pending[0]!.attempts, 2);

    // rekor recovers → drains
    mock.mode = 'ok';
    assert.equal(await retryPending(ledger, { baseUrl: mock.url, now: Date.now() + 8_000_000 }), 1);
    assert.equal(readPending(ledger.dir).length, 0);
    ledger.close();
  } finally {
    delete process.env.ATTESTOR_HOME;
    await mock.close();
  }
});

test('429 rate limit also queues instead of throwing', async () => {
  const mock = await startMockRekor();
  mock.mode = 'ratelimit';
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  process.env.ATTESTOR_HOME = join(dir, 'home');
  try {
    const ledger = Ledger.open(join(dir, 'ledger'), keys);
    const ckpt = writeCheckpoint(ledger);
    assert.equal(await anchorCheckpoint(ledger, ckpt, { baseUrl: mock.url }), undefined);
    assert.equal(readPending(ledger.dir).length, 1);
    ledger.close();
  } finally {
    delete process.env.ATTESTOR_HOME;
    await mock.close();
  }
});

test('offline mode queues without any network attempt', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  const ckpt = writeCheckpoint(ledger);
  const result = await anchorCheckpoint(ledger, ckpt, { offline: true, baseUrl: 'http://127.0.0.1:1' });
  assert.equal(result, undefined);
  assert.equal(readPending(ledger.dir).length, 1);
  ledger.close();
});

test('backoff grows exponentially with jitter, capped at 1h', () => {
  for (let a = 0; a < 12; a++) {
    const ms = backoffMs(a);
    const base = Math.min(60_000 * 2 ** a, 3_600_000);
    assert.ok(ms >= base * 0.5 && ms <= base * 1.5, `attempt ${a}: ${ms}`);
  }
});

test('verify --online: full pass against the mock log, then catches divergence', async () => {
  const mock = await startMockRekor();
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  process.env.ATTESTOR_HOME = join(dir, 'home');
  try {
    const ledger = Ledger.open(join(dir, 'ledger'), keys);
    ledger.append({ type: 'wire', origin: 'proxy', payload: '"x"' });
    const ckpt = writeCheckpoint(ledger);
    await anchorCheckpoint(ledger, ckpt, { baseUrl: mock.url });
    ledger.close();

    const pass = await verifyLedger(join(dir, 'ledger'), { online: true, rekorUrl: mock.url });
    assert.equal(pass.exitCode, 0, JSON.stringify(pass.findings, null, 2));
    assert.ok(pass.checks.find((c) => c.name === 'ANCHOR-ONLINE')?.ok);

    // the public log now shows a different entry under that uuid → caught
    mock.mode = 'divergent';
    const fail = await verifyLedger(join(dir, 'ledger'), { online: true, rekorUrl: mock.url });
    assert.equal(fail.exitCode, 1);
    assert.ok(fail.findings.some((f) => f.check === 'ANCHOR-ONLINE'));
  } finally {
    delete process.env.ATTESTOR_HOME;
    await mock.close();
  }
});

test('online-substitution attack: live key endpoint serves a rogue key: exit 1, not authenticated', async () => {
  const mock = await startMockRekor();
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  process.env.ATTESTOR_HOME = join(dir, 'home');
  try {
    const ledger = Ledger.open(join(dir, 'ledger'), keys);
    ledger.append({ type: 'wire', origin: 'proxy', payload: '"x"' });
    const ckpt = writeCheckpoint(ledger);
    await anchorCheckpoint(ledger, ckpt, { baseUrl: mock.url });
    ledger.close();

    // now the log's key endpoint answers with a key that signed nothing here
    mock.mode = 'roguekey';
    const report = await verifyLedger(join(dir, 'ledger'), { online: true, rekorUrl: mock.url });
    assert.equal(report.exitCode, 1, JSON.stringify(report.findings, null, 2));
    assert.ok(report.findings.some((f) => f.check === 'ANCHOR-ONLINE'));
  } finally {
    delete process.env.ATTESTOR_HOME;
    await mock.close();
  }
});

test('verify --online exit 3 when Rekor unreachable', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  process.env.ATTESTOR_HOME = join(dir, 'home');
  const mock = await startMockRekor();
  try {
    const ledger = Ledger.open(join(dir, 'ledger'), keys);
    ledger.append({ type: 'wire', origin: 'proxy', payload: '"x"' });
    const ckpt = writeCheckpoint(ledger);
    await anchorCheckpoint(ledger, ckpt, { baseUrl: mock.url });
    ledger.close();
    await mock.close();

    const report = await verifyLedger(join(dir, 'ledger'), { online: true, rekorUrl: mock.url });
    assert.equal(report.exitCode, 3);
    assert.equal(report.result, 'REKOR UNREACHABLE');
  } finally {
    delete process.env.ATTESTOR_HOME;
  }
});

// ---------- opt-in live smoke ----------

test('live Rekor smoke: post + fetch + SET verify', { skip: process.env.ATTESTOR_LIVE !== '1' }, async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const artifact = Buffer.from(`attestor-live-smoke-${Date.now()}-${Math.random()}`);
  const { uuid, entry } = await postEntry('https://rekor.sigstore.dev', hashedRekordBody(artifact, keys));
  assert.ok(uuid);
  const fetched = await getEntry('https://rekor.sigstore.dev', uuid);
  assert.equal(fetched.body, entry.body);
  assert.ok(verifySET(fetched, fixture.rekor_log_public_key_pem));
  assert.ok(verifyRekorInclusion(fetched));
});

test('verifyRekorKeyTrust passes for official Sigstore Rekor log key', () => {
  assert.doesNotThrow(() => {
    verifyRekorKeyTrust('https://rekor.sigstore.dev', fixture.rekor_log_public_key_pem);
  });
});

test('verifyRekorKeyTrust throws UntrustedRekorKeyError for unknown key targeting official Sigstore', () => {
  const fakeKeyPem = generateKey(tmp()).publicPem;
  assert.throws(
    () => {
      verifyRekorKeyTrust('https://rekor.sigstore.dev', fakeKeyPem);
    },
    UntrustedRekorKeyError,
  );
});
