# Attestor

[![CI](https://github.com/asinadarsh/attestor/actions/workflows/ci.yml/badge.svg)](https://github.com/asinadarsh/attestor/actions/workflows/ci.yml)

**A tamper-evident flight recorder for AI agents.**

Your agents are calling tools that move money and touch PHI; when a regulator
or incident review asks *"what exactly did the agent do,"* a mutable app log
is not an answer. Attestor records every tool call into a hash-chained,
per-entry-signed ledger, checkpoints it with RFC 6962 Merkle roots, and
anchors each root in [Sigstore's public Rekor transparency log](https://docs.sigstore.dev/logging/overview/) —
so tampering with any recorded call breaks verification loudly, and even
rewriting the whole ledger with stolen keys can't beat the public log.

```sh
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/asinadarsh/attestor/main/install.sh | sh

# Windows PowerShell
irm https://raw.githubusercontent.com/asinadarsh/attestor/main/install.ps1 | iex
```

The installer builds attestor, puts it on your PATH, and runs `attestor setup`,
which finds your MCP configs and offers to start recording them. It only asks
when there is a real decision to make; everything else it does on its own. Piped
into a shell it has no terminal to ask with, so it prints its plan and stops
rather than rewriting your config behind your back. Finish with `attestor
setup` in a terminal, or accept the defaults unattended:

```sh
curl -fsSL https://raw.githubusercontent.com/asinadarsh/attestor/main/install.sh | sh -s -- --yes
```
```powershell
$env:ATTESTOR_YES=1; irm https://raw.githubusercontent.com/asinadarsh/attestor/main/install.ps1 | iex
```

(`ATTESTOR_YES=1 curl … | sh` would set the variable for `curl`, not for the
script — hence `sh -s --`.)

Then see what it is for:

```sh
attestor demo tamper
# 30 seconds: record → verify green → attacker edits → caught → attacker re-signs everything → still caught
```

The demo is offline by default and writes nothing to any public log; `--live`
opts in to a real Sigstore anchor.

```
✔ CHAIN    15 entries, hash chain intact
✔ MERKLE   1 checkpoint, all roots reproduce
✔ SIG      15/15 entry signatures valid (key 37f92a70955fa3b5)
✔ ANCHOR   1/1 anchor recorded (latest logIndex 2256596856), SET+inclusion authenticated
RESULT: VERIFIED  (exit 0)

--- attacker edits the ledger ---
✖ CHAIN    entry 7 payload does not match its signed commitment (payload mutated)
           blast radius: entries 7–14 untrustworthy
RESULT: TAMPER DETECTED  (exit 1)
```

One runtime dependency ([`canonicalize`](https://www.npmjs.com/package/canonicalize),
the RFC 8785 JCS implementation). Everything else is `node:crypto` and `fetch`.
Node ≥ 24, Linux/macOS.

## Record an MCP server (no code changes)

```sh
attestor install                # wraps every server in .mcp.json / Claude Desktop config (with backup)
# or by hand — prepend "attestor wrap --" to any stdio MCP server:
attestor wrap -- npx -y @modelcontextprotocol/server-github
```

The proxy is an opaque byte relay with a recording tap: it never re-serializes
a message, so notifications, server→client requests, and future protocol
methods pass through untouched. Unparsable lines are relayed *and* recorded.
Default failure mode is `--on-error block` (fail closed): if the ledger can't
be written, tool calls get a synthesized JSON-RPC `-32000` error instead of
running unrecorded. `--on-error continue` relays anyway and records a signed
**gap marker** — the ledger is honest about its own holes.

## Record a non-MCP app (one line)

```ts
import { Attestor } from "attestor/sdk";

const attestor = new Attestor();
const anthropic = new Anthropic({ fetch: attestor.wrapFetch() });  // also: new OpenAI({ fetch: ... })

// the HTTP tap sees the model REQUEST the tool and your app REPORT the result.
// attest what your app actually did in between:
await attestor.record({ tool_use_id, name: "payments_transfer", input, output });
```

`wrapFetch()` records exact request/response bytes (SSE streams are teed
without back-pressuring your app) and indexes Anthropic `tool_use` /
OpenAI `tool_calls` + `function_call` structures, streaming or not.

## Verify

```sh
attestor verify <dir>            # CHAIN → MERKLE → SIG → ANCHOR, offline
attestor verify <dir> --online   # + compare every anchor against the public Rekor log
```

Exit codes: `0` verified · `1` tamper · `2` usage/IO error · `3` Rekor
unreachable (CI can tell network from tamper) · `4` the chain is intact but the
anchors could not be authenticated. On tamper you get the entry, the reason,
the blast radius, and an `audit-packet.json`.

**Exit 4 matters more than it looks.** A Rekor key that travels inside the
artifact cannot vouch for that artifact — an attacker who forges anchors ships
a matching key. So verifying a pack offline, on a machine that has never
pinned the log key, does not exit 0; it exits 4 and says the anchors are
unconfirmed. Only a key you trust independently (`--online`, which fetches it
live, or a pinned `~/.attestor/keys/rekor-pub.pem`) turns that into a 0.

**What the trust model actually is.** A Rekor log key shipped *inside* an
evidence pack cannot authenticate that pack — an attacker who forges anchors
would ship a matching key. So attestor separates the two questions: an anchor
verified only against the key packaged with it is reported as
`⚠ UNAUTHENTICATED`, never as proof. Authenticity needs a key you trust
independently — `--online` (fetched live from the log) or a host-pinned
`~/.attestor/keys/rekor-pub.pem`. `--online` also queries the log by your
recorder key, so anchors deleted from a local ledger still surface.

## Evidence packs

```sh
attestor export <ledger-dir>     # → attestor-pack-<date>/
```

Self-contained: ledger, Rekor anchor records (SET + inclusion proofs), public
keys, `manifest.json` with the SHA-256 of every file, `report.html`, and a
`VERIFY.md` whose **curl + jq + openssl recipe verifies the anchors without
installing attestor** — an auditor does not have to trust our binary.
Control mappings (SOC 2 CC7.2/CC7.3/CC4.1, EU AI Act Art. 12, HIPAA
§164.312(b)) claim *supports evidence for* — never certification.

## Threat model

| Attacker capability | Defeated by | Status |
|---|---|---|
| Edit any past entry | hash chain + per-entry sig breaks | ✅ in scope |
| Delete a middle entry | `prev` mismatch + `seq` gap | ✅ |
| Reorder entries | `prev` chain + `seq` | ✅ |
| Truncate tail (delete newest) | chain stays valid locally; signed checkpoint anchored in Rekor at size *N* proves the log was longer. **Window: entries since last anchor are silently truncatable** | ✅ post-anchor / ⚠️ ≤60 s window |
| Fork/rollback (show auditor an alternate history) | two Rekor entries under the same `ledger_id`+pubkey with inconsistent roots = cryptographic fork proof; `verify --online` compares anchored checkpoints against the public log | ✅ if verifier queries Rekor |
| Steal signing key (disk access) | cannot rewrite anchored history without Rekor collusion; **can** forge/fork from theft onward. Rotation bounds blast radius | ⚠️ partial — forward forgery out of scope |
| Rewrite history under a **fresh key** and anchor it | nothing, unless you tell verify which recorder key to expect (`--expect-key`). Rekor is an open log: anyone may anchor anything, so a self-consistent forgery with its own key and its own genuine anchors passes every internal check | ⚠️ needs `--expect-key` |
| Delete every anchor so the ledger reads as "never anchored" | the artifacts anchoring leaves behind — a pinned log key, or a pack manifest declaring anchors — are checked against the chain; `--online` also sweeps the log by recorder key | ✅ offline for packs and pinned ledgers |
| Root on host *during* recording | nothing — recorder signs what it saw; lies fed to it are faithfully attested | ❌ out of scope, say so |
| Delete entire ledger | Rekor entries under the pubkey survive as existence evidence; absence of a ledger proves nothing about activity | ⚠️ detection only |
| Compromise of Rekor itself | out of scope; Rekor's own witness/monitor ecosystem | ❌ out of scope |

## Honest limits (read before you rely on this)

- **Tamper-EVIDENT, not tamper-proof.** The signing key lives next to the
  ledger (`~/.attestor/keys`, 0600, optional scrypt passphrase). An attacker
  with the key can forge *from theft onward* — but cannot rewrite history
  whose roots are already in Rekor. HSM/TPM support is roadmap, not MVP.
- **Entry `ts` is a claim** by the local clock. The only trusted time is
  Rekor's `integratedTime`. `verify` cross-checks the two, one-directionally:
  an entry inside an anchored checkpoint's covered prefix whose `ts` is later
  than that anchor's `integratedTime` by more than 300 s (clock-skew
  tolerance) is reported as ANCHOR tamper (exit 1) — the log cannot have
  integrated an entry that had not happened yet. Within the tolerance nothing
  is reported (drift is indistinguishable from honest clocks; there is no
  warning tier). The check only runs for anchors whose SET authenticated
  under an independently trusted log key: on an unauthenticated anchor
  `integratedTime` is attacker-controlled, so those stay exit 4.
- **Truncation window**: entries after the last anchored checkpoint
  (≤ 64 entries or ≤ 60 s by default) can be silently dropped. `verify`
  reports this as ANCHOR LAG rather than pretending otherwise.
- **The proxy records transport traffic, not truth.** A malicious tool server
  can lie in its responses; Attestor proves *what was said*, not *what was
  done*. `record()` exists so your app can attest the doing.
- **`npx`-wrapped servers**: the recorded `argv` does not pin server code
  identity. No binary attestation is claimed.
- **stdio only** for MVP. Streamable-HTTP MCP proxying is deferred by design
  (SSE resume/ordering is genuinely subtle; punting beats shipping it
  half-right). Claude Desktop / Claude Code local servers are stdio.
- **Windows is supported but the least exercised.** CI runs the full suite,
  the evidence-pack check and the demo on Windows, macOS and Linux, so the
  claim is tested rather than asserted — but it has far less real-world use
  than Linux. Two Windows specifics worth knowing: `.cmd` shims (which is what
  `npx` is) are launched through `cmd.exe` with hand-escaped arguments rather
  than `shell: true`, and arguments containing a newline or NUL are refused
  because they cannot be escaped safely. File permissions are not applied by
  Windows the way `chmod` is, so the signing key's ACL is set with `icacls`;
  if that fails you get a loud warning instead of a silently readable key.
- **Anchoring is a public write.** Each anchor puts a digest, your recorder
  public key, and a timestamp permanently into a shared transparency log.
  Nothing sensitive leaves your machine, but *that you were active, and when,
  and roughly how often* becomes inferable by anyone. Point
  `ATTESTOR_REKOR_URL` at your own Rekor if that matters.
- **No published latency numbers yet.** `--on-error block` with
  `--durability strict` puts an fsync in the path of every tool call. Tool
  calls take 10 ms–10 s so it should be noise, but nothing in this repo
  measures it — treat the overhead as unquantified until it is. (The fsync
  itself is the real thing on every platform: Node uses `F_FULLFSYNC` on
  macOS and `FlushFileBuffers` on Windows, not a cache-only flush.)
- **Verification proves consistency, not identity, unless you supply one.**
  A ledger signed end to end by a key you have never seen is still internally
  valid. `--expect-key <keyid|pem>` is what turns "this is a coherent ledger"
  into "this is *their* ledger" — get the recorder's public key the way you
  would get any other counterparty key, out of band.
- **The pinned Rekor key is trust-on-first-use, gated for the official log.**
  It is fetched from `ATTESTOR_REKOR_URL` at the first successful anchor and
  cached at `~/.attestor/keys/rekor-pub.pem`. When the URL targets the
  official public log (canonicalized hostname `rekor.sigstore.dev` — spelling
  tricks do not change the host), the fetched key must match a built-in
  Sigstore trust-root allowlist or pinning fails loudly
  (`UntrustedRekorKeyError`); the same allowlist is enforced wherever a key is
  used — `verify --online` live fetches, and existing local/home pins
  (including legacy pins taken before this gate existed) whenever they
  authenticate an anchor that claims the official log. The allowlist is a set,
  so a Sigstore key rotation ships as an added ID with both valid during
  migration. Custom logs are NOT gated: any other host is the auditor's own
  trust decision, pinned TOFU as before — if that first fetch was pointed
  somewhere hostile, the pin is hostile. `attestor verify --rekor-pubkey
  <file>` lets an auditor supply their own key either way.
- **Key rotation** is manual (`attestor keys rotate`, old key signs the new
  one into the chain). No revocation list.
- **Rekor v1** REST API, URL configurable via `ATTESTOR_REKOR_URL`; v1 gets
  ≥ 1 year freeze notice, and a v2 writer is additive (same digest payload).

## Design notes

- **Merkle**: RFC 6962 byte-for-byte — `leaf = SHA256(0x00‖h)`,
  `node = SHA256(0x01‖L‖R)`, unbalanced trees per §2.1; verification follows
  RFC 9162 §2.1.3.2/§2.1.4.2; tested against the CT known-answer vectors.
- **Signing**: ECDSA **P-256** + SHA-256 via `node:crypto`, because Rekor's
  `hashedrekord` verifies over a pre-hashed digest, which pure Ed25519 cannot
  do ([rekor#851](https://github.com/sigstore/rekor/issues/851)) — the
  Ed25519+hashedrekord combo ships a broken anchor. One key signs entries
  *and* checkpoints; validated against the live log before anything was
  built on it.
- **Canonicalization**: RFC 8785 JCS over the flat signed core only
  (strings/ints, no floats). Tool-call payloads are **never canonicalized** —
  they're committed as exact wire bytes via
  `payload_hash = SHA256(salt ‖ bytes)`, which eliminates the JCS float/
  surrogate attack surface structurally and makes redaction possible:
  `attestor redact <seq>` strips a payload while chain, sigs, roots, and
  anchors stay valid. The 16-byte salt is itself unsigned and is deleted with
  the payload, so what survives is a commitment nobody can brute-force — a
  salt that stayed on the line would defeat its own purpose.
- **Storage**: append-only JSONL — the ledger file *is* the exhibit. An
  auditor can `jq` it and re-hash it with a 50-line script in any language.
  Torn final lines (crash) are moved to `ledger.torn`; a newline-terminated
  line that fails hash checks is **never** auto-"recovered" — that's tamper
  evidence, and verify must see it.
- **Vocabulary**: "tamper-evident," never "immutable" or "blockchain."

## CLI

```
attestor setup [--yes]              guided install: key + record your MCP servers
attestor keys init|list|rotate      P-256 recorder keys (PKCS#8, 0600)
attestor wrap [opts] -- <cmd...>    record an MCP stdio server
attestor install [--dry-run]        wrap servers in .mcp.json / Claude Desktop config
                                   (each server gets its own ledger)
attestor verify <dir> [--online]    verify a ledger or evidence pack
attestor export <dir> [--out d]     regulator-ready evidence pack
attestor redact <dir> <seq>         strip one payload, keep proofs valid
attestor replay <dir> [--session s] print recorded calls (VCR-style)
attestor demo tamper [--live]       the 30-second pitch (offline by default)
```

Env: `ATTESTOR_HOME` (default `~/.attestor`), `ATTESTOR_REKOR_URL`,
`ATTESTOR_OFFLINE=1` (queue anchors, never POST), `ATTESTOR_LIVE=1`
(opt-in live-network tests).

## Verify my claims, not my prose

`examples/` holds two real evidence packs from one recorded session — one
clean, one with a single byte changed. Both reference the same anchor in
Sigstore's public log, so you can check them against a log I do not control:

```sh
attestor verify examples/pack-2026-07            # exit 4: chain intact, anchor unconfirmed
attestor verify examples/pack-2026-07 --online   # exit 0: anchor authenticated against the public log
attestor verify examples/pack-2026-07-TAMPERED   # exit 1: caught
```

See [`examples/README.md`](examples/README.md) for the curl recipe.

## Platform support

| | Linux | macOS | Windows |
|---|---|---|---|
| Test suite + build | CI | CI | CI |
| Evidence-pack verify (clean + tampered) | CI | CI | CI |
| `demo tamper` end to end | CI | CI | CI |
| Real-world use | yes | light | light |

Node 24+ is required on all three (the CLI runs TypeScript directly via
Node's native type stripping). `npm install` builds the `attestor` binary;
`npm link` puts it on your PATH. `attestor install` does not depend on that —
it writes an absolute interpreter and script path into your MCP config, which
is what the MCP docs recommend anyway, because GUI-launched clients start
with a minimal PATH.

## Contributing

Issues tagged [`good first issue`](https://github.com/asinadarsh/attestor/labels/good%20first%20issue)
are scoped to be self-contained; [`help wanted`](https://github.com/asinadarsh/attestor/labels/help%20wanted)
marks the larger pieces. [CONTRIBUTING.md](CONTRIBUTING.md) covers setup, the
three constraints that explain most review comments, and why three tests skip
by design. Security problems go through
[private reporting](https://github.com/asinadarsh/attestor/security/advisories/new),
not public issues — see [SECURITY.md](SECURITY.md).

## Development

npm-workspaces monorepo: `packages/attestor` (published) +
`packages/toy-mcp-server` (test fixture). `npm test` runs 72 tests on
`node:test` with Node 24 native type stripping — chain round-trips, the CT
Merkle vectors, a 13-case tamper matrix, a real MCP SDK client through the
proxy, SSE tee reconstruction, a mocked Rekor (201/409/429/offline queue),
and SET/inclusion verification against a captured live Rekor entry.

MIT.
