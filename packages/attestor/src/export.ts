// Evidence pack: a self-contained directory an auditor can verify without
// installing attestor (VERIFY.md carries a pure curl/jq/openssl recipe).
// Control mappings claim "supports evidence for", never certification.
import { createHash } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { join, basename } from 'node:path';
import { parseArgs } from 'node:util';
import { readEntries, type LedgerEntry } from './ledger.ts';
import { verifyLedger } from './verify.ts';
import type { AnchorPayload } from './rekor.ts';

const PACK_VERSION = 1;
const ATTESTOR_VERSION = '0.1.0';

const CONTROL_MAPPINGS = {
  disclaimer:
    'Attestor provides audit-trail evidence. Compliance determinations are made by your assessor. These mappings claim that the evidence pack SUPPORTS the listed controls — never that it makes you compliant or certified.',
  soc2_2017_tsc: {
    'CC7.2': 'Monitoring system components for anomalous activity — complete, tamper-evident record of agent tool calls.',
    'CC7.3': 'Evaluation of security events — verifiable reconstruction of what an agent did and when.',
    'CC4.1': 'Ongoing evaluations of internal control — verification is independently re-runnable by any party.',
    'PI1.4_PI1.5':
      'Conditional (Processing Integrity in scope): complete, accurate retention of outputs/records with integrity proof.',
  },
  eu_ai_act: {
    'Art. 12(1)':
      'Automatic recording of events (logs) over the system lifetime — directly supported, with tamper-evidence exceeding the bar.',
    'Art. 12(2)(a)': 'Recording the period of each use — per-call RFC 3339 timestamps (local-clock claims) plus Rekor integratedTime (trusted).',
    'Art. 12(2)(b-d)':
      'Conditional — reference-database checks, input data, and human-verifier identity are populated only if the SDK user records those fields via record().',
    'Art. 19 / Art. 26(6)': 'Provider/deployer log retention — retention with independently verifiable integrity proof.',
  },
  hipaa_security_rule: {
    '45 CFR 164.312(b)': 'Audit controls — record and examine activity in systems containing ePHI.',
    '45 CFR 164.308(a)(1)(ii)(D)': 'Information system activity review.',
    '45 CFR 164.312(c)(1)': 'Integrity — applied to the audit trail itself (tamper-evident logs). No "HIPAA certification" exists; none is claimed.',
  },
} as const;

export async function runExport(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      out: { type: 'string' },
      format: { type: 'string', default: 'pack' },
    },
  });
  const ledgerDir = positionals[0];
  if (ledgerDir === undefined) {
    process.stderr.write('attestor: usage: attestor export <ledger-dir> [--format <pack|ocsf|cef>] [--out <path>]\n');
    process.exit(2);
  }
  const format = (values.format ?? 'pack').toLowerCase();
  if (format === 'ocsf') {
    const output = exportOcsf(ledgerDir);
    if (values.out !== undefined) {
      writeFileSync(values.out, output);
      process.stdout.write(`OCSF export written to ${values.out}\n`);
    } else {
      process.stdout.write(output);
    }
    return;
  }
  if (format === 'cef') {
    const output = exportCef(ledgerDir);
    if (values.out !== undefined) {
      writeFileSync(values.out, output);
      process.stdout.write(`CEF export written to ${values.out}\n`);
    } else {
      process.stdout.write(output);
    }
    return;
  }
  if (format !== 'pack') {
    process.stderr.write(`attestor: unsupported export format: ${format} (choose: pack, ocsf, cef)\n`);
    process.exit(2);
  }
  if (!existsSync(join(ledgerDir, 'ledger.jsonl')) && !existsSync(join(ledgerDir, 'ledger', 'entries.jsonl'))) {
    process.stderr.write(`attestor: no ledger found at ${ledgerDir}\n`);
    process.exit(2);
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 17) + 'Z';
  const out = values.out ?? `attestor-pack-${stamp}`;
  const packDir = await buildPack(ledgerDir, out);
  process.stdout.write(`evidence pack written to ${packDir}\n  verify it: attestor verify ${packDir}\n  or follow ${packDir}/VERIFY.md (curl + jq + openssl only)\n`);
}

export function extractExportEvents(ledgerDir: string): { events: any[]; ledgerId?: string } {
  const path = existsSync(join(ledgerDir, 'ledger.jsonl'))
    ? join(ledgerDir, 'ledger.jsonl')
    : join(ledgerDir, 'ledger', 'entries.jsonl');
  if (!existsSync(path)) throw new Error(`no ledger found at ${ledgerDir}`);
  const entries = readEntries(path);
  let ledgerId: string | undefined;
  if (entries.length > 0 && entries[0]!.type === 'genesis' && entries[0]!.payload) {
    try {
      ledgerId = (JSON.parse(entries[0]!.payload) as { ledger_id?: string }).ledger_id;
    } catch {}
  }

  // Collect anchor mappings by checkpoint_seq
  const anchors: AnchorPayload[] = [];
  for (const e of entries) {
    if (e.type === 'anchor' && e.payload) {
      try {
        anchors.push(JSON.parse(e.payload) as AnchorPayload);
      } catch {}
    }
  }

  const requests = new Map<string, LedgerEntry>();
  const key = (e: LedgerEntry) => `${e.session_id} ${e.call_id}`;
  for (const e of entries) {
    if (e.type === 'call_request' && e.call_id !== undefined && !requests.has(key(e))) {
      requests.set(key(e), e);
    }
  }

  const events: any[] = [];
  for (const e of entries) {
    if (e.type !== 'call_result' || e.call_id === undefined) continue;
    const req = requests.get(key(e));
    if (!req) continue;
    requests.delete(key(e));

    const reqTs = Date.parse(req.ts);
    const resTs = Date.parse(e.ts);
    const durationMs = isNaN(reqTs) || isNaN(resTs) ? 0 : Math.max(0, resTs - reqTs);
    const isError = e.payload?.includes('"error"') || e.payload?.includes('"isError":true');

    // Find nearest covering anchor (first anchor covering this entry)
    const coveringAnchor = anchors.find((a) => a.checkpoint_seq >= e.seq);

    events.push({
      tool_name: req.tool?.name ?? 'unknown_tool',
      call_id: e.call_id,
      session_id: e.session_id,
      request_ts: req.ts,
      response_ts: e.ts,
      duration_ms: durationMs,
      status: isError ? 'error' : 'ok',
      request_payload: req.payload !== undefined ? safeJsonParse(req.payload) : undefined,
      response_payload: e.payload !== undefined ? safeJsonParse(e.payload) : undefined,
      request_seq: req.seq,
      request_hash: req.hash,
      response_seq: e.seq,
      response_hash: e.hash,
      log_index: coveringAnchor?.logIndex,
      integrated_time: coveringAnchor?.integratedTime,
      rekor_url: coveringAnchor?.url,
    });
  }
  return { events, ledgerId };
}

function safeJsonParse(str: string): any {
  try {
    return JSON.parse(str);
  } catch {
    return str;
  }
}

export function exportOcsf(ledgerDir: string): string {
  const { events, ledgerId } = extractExportEvents(ledgerDir);
  const lines = events.map((ev) => {
    const timeMs = !isNaN(Date.parse(ev.request_ts)) ? Date.parse(ev.request_ts) : Date.now();
    const isOk = ev.status === 'ok';
    const ocsfRecord = {
      activity_id: 1,
      activity_name: 'agent_tool_call',
      category_uid: 6,
      category_name: 'Application Activity',
      class_uid: 6003,
      class_name: 'API Activity',
      time: timeMs,
      severity_id: isOk ? 1 : 4,
      severity: isOk ? 'Informational' : 'Medium',
      status_id: isOk ? 1 : 2,
      status: isOk ? 'Success' : 'Failure',
      metadata: {
        version: '1.3.0',
        product: {
          name: 'attestor',
          version: ATTESTOR_VERSION,
          vendor_name: 'attestor',
        },
        uid: ev.request_hash,
      },
      api: {
        operation: ev.tool_name,
        service: {
          name: 'mcp',
        },
        request: {
          data: ev.request_payload,
        },
        response: {
          data: ev.response_payload,
        },
      },
      actor: {
        session: {
          uid: ev.session_id,
        },
      },
      unmapped: {
        ledger_id: ledgerId,
        ledger_seq_req: ev.request_seq,
        ledger_hash_req: ev.request_hash,
        ledger_seq_res: ev.response_seq,
        ledger_hash_res: ev.response_hash,
        rekor_log_index: ev.log_index,
        rekor_integrated_time: ev.integrated_time,
        audit_note:
          'SIEM copy is an unauthenticated index into the tamper-evident ledger; verify with `attestor verify` using ledger_seq and ledger_hash',
      },
    };
    return JSON.stringify(ocsfRecord);
  });
  return lines.length > 0 ? lines.join('\n') + '\n' : '';
}

export function exportCef(ledgerDir: string): string {
  const { events, ledgerId } = extractExportEvents(ledgerDir);
  const lines = events.map((ev) => {
    const reqTsMs = !isNaN(Date.parse(ev.request_ts)) ? Date.parse(ev.request_ts) : Date.now();
    const resTsMs = !isNaN(Date.parse(ev.response_ts)) ? Date.parse(ev.response_ts) : reqTsMs + ev.duration_ms;
    const severity = ev.status === 'ok' ? '1' : '6';
    const logIdx = ev.log_index !== undefined ? ` cs5=${ev.log_index} cs5Label=rekorLogIndex` : '';
    const safeMsg = `Agent tool call ${ev.tool_name} (${ev.status}) in session ${ev.session_id}`.replace(/[\\|]/g, ' ');
    return `CEF:0|attestor|attestor|${ATTESTOR_VERSION}|agent_tool_call|${ev.tool_name}|${severity}|start=${reqTsMs} end=${resTsMs} suser=${ev.session_id} cs1=${ev.request_seq} cs1Label=ledgerSeqReq cs2=${ev.request_hash} cs2Label=ledgerHashReq cs3=${ev.response_seq} cs3Label=ledgerSeqRes cs4=${ev.response_hash} cs4Label=ledgerHashRes${logIdx} msg=${safeMsg}`;
  });
  return lines.length > 0 ? lines.join('\n') + '\n' : '';
}

export async function buildPack(ledgerDir: string, outDir: string): Promise<string> {
  const entries = readEntries(join(ledgerDir, 'ledger.jsonl'));
  if (entries.length === 0) throw new Error('empty ledger');
  const genesis = JSON.parse(entries[0]!.payload ?? '{}') as { ledger_id?: string; public_key_pem?: string };

  mkdirSync(join(outDir, 'ledger'), { recursive: true });
  mkdirSync(join(outDir, 'anchors', 'rekor'), { recursive: true });
  mkdirSync(join(outDir, 'keys'), { recursive: true });
  mkdirSync(join(outDir, 'controls'), { recursive: true });

  copyFileSync(join(ledgerDir, 'ledger.jsonl'), join(outDir, 'ledger', 'entries.jsonl'));

  const anchorsSrc = join(ledgerDir, 'anchors');
  const anchorInfos: AnchorPayload[] = [];
  if (existsSync(anchorsSrc)) {
    for (const f of readdirSync(anchorsSrc)) {
      if (/^\d+\.json$/.test(f)) copyFileSync(join(anchorsSrc, f), join(outDir, 'anchors', 'rekor', f));
      if (f === 'rekor-pub.pem') copyFileSync(join(anchorsSrc, f), join(outDir, 'keys', 'rekor-pub.pem'));
    }
  }
  for (const e of entries) {
    if (e.type === 'anchor' && e.payload !== undefined) {
      try {
        anchorInfos.push(JSON.parse(e.payload) as AnchorPayload);
      } catch {
        /* verify reports this */
      }
    }
  }
  if (genesis.public_key_pem !== undefined) {
    writeFileSync(join(outDir, 'keys', 'recorder-pub.pem'), genesis.public_key_pem);
  }
  writeFileSync(join(outDir, 'controls', 'mapping.json'), JSON.stringify(CONTROL_MAPPINGS, null, 2) + '\n');

  const report = await verifyLedger(ledgerDir);
  writeFileSync(join(outDir, 'VERIFY.md'), verifyMd(anchorInfos, entries));
  writeFileSync(join(outDir, 'report.html'), reportHtml(entries, anchorInfos, report.result, genesis.ledger_id));

  // manifest last: hashes every file in the pack
  const files: Record<string, string> = {};
  const walk = (dir: string, prefix: string) => {
    for (const f of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, f.name);
      const rel = prefix === '' ? f.name : `${prefix}/${f.name}`;
      if (f.isDirectory()) walk(p, rel);
      else files[rel] = createHash('sha256').update(readFileSync(p)).digest('hex');
    }
  };
  walk(outDir, '');
  const sessions = new Set(entries.map((e) => e.session_id));
  const manifest = {
    pack_version: PACK_VERSION,
    attestor_version: ATTESTOR_VERSION,
    generated_at: new Date().toISOString(),
    ledger_id: genesis.ledger_id,
    entry_count: entries.length,
    session_count: sessions.size,
    time_range: { from: entries[0]!.ts, to: entries[entries.length - 1]!.ts },
    recorder_key_ids: [...new Set(entries.map((e) => e.key_id))],
    verify_result_at_export: report.result,
    anchors: anchorInfos.map((a) => ({
      checkpoint_seq: a.checkpoint_seq,
      uuid: a.uuid,
      log_index: a.logIndex,
      integrated_time: a.integratedTime,
      rekor_url: a.url,
      search_url: `https://search.sigstore.dev/?logIndex=${a.logIndex}`,
    })),
    files_sha256: files,
  };
  writeFileSync(join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return outDir;
}

function verifyMd(anchors: AnchorPayload[], entries: LedgerEntry[]): string {
  const first = anchors[0];
  return `# Verifying this evidence pack

## Option A — attestor CLI (30 seconds)

\`\`\`sh
npx attestor verify .            # offline: chain, Merkle roots, signatures, stored anchors
npx attestor verify . --online   # also compares every anchor against the public Rekor log
\`\`\`

Exit codes: 0 verified · 1 tamper · 2 usage/IO error · 3 Rekor unreachable ·
4 the chain is intact but the anchors could not be authenticated.

Exit 4 is the expected result when you verify this pack offline on a machine
that has never talked to the log: the Rekor key inside the pack cannot vouch
for the pack. Run \`npx attestor verify . --online\`, or follow Option B below,
to authenticate the anchors against the public log itself.

## Option B — no attestor, no trust in our code (curl + jq + openssl)

Every checkpoint of this ledger was anchored in Sigstore's public Rekor
transparency log. You can confirm the anchors are real, public, and signed by
Rekor without running anything we shipped.

${
  first
    ? `### 1. The anchor exists in the public log

\`\`\`sh
curl -s "${first.url}/api/v1/log/entries/${first.uuid}" | jq .
# → the same entry stored in anchors/rekor/${first.checkpoint_seq}.json
# → human view: https://search.sigstore.dev/?logIndex=${first.logIndex}
\`\`\`

### 2. The stored copy matches the public log byte-for-byte

\`\`\`sh
curl -s "${first.url}/api/v1/log/entries/${first.uuid}" \\
  | jq -r '.[].body' > /tmp/public-body.b64
jq -r '.body' "anchors/rekor/${first.checkpoint_seq}.json" | diff - /tmp/public-body.b64 && echo MATCH
\`\`\`

### 3. Rekor's signature (SET) over the stored entry verifies

Rekor signs the JSON-canonicalized \`{body, integratedTime, logID, logIndex}\`.
For these flat ASCII fields, \`jq -cS\` produces exactly that canonical form.
The pinned log key is in \`keys/rekor-pub.pem\`; cross-check it first:

\`\`\`sh
curl -s "${first.url}/api/v1/log/publicKey" | diff - keys/rekor-pub.pem && echo KEY-MATCHES-PUBLIC-LOG
A="anchors/rekor/${first.checkpoint_seq}.json"
jq -cjS '{body, integratedTime, logID, logIndex}' "$A" > /tmp/set-bundle.json
jq -r '.verification.signedEntryTimestamp' "$A" | base64 -d > /tmp/set.sig
openssl dgst -sha256 -verify keys/rekor-pub.pem -signature /tmp/set.sig /tmp/set-bundle.json
# → Verified OK
\`\`\`

### 4. What the anchor commits to

The anchored artifact is the SHA-256 of a checkpoint entry's canonical signed
core (RFC 8785 JCS). That checkpoint commits an RFC 6962 Merkle root over
every ledger entry before it — so any edit to \`ledger/entries.jsonl\` at or
before seq ${first.checkpoint_seq} changes hashes that Rekor has already
publicly timestamped. Decode it yourself:

\`\`\`sh
jq -r '.body' "$A" | base64 -d | jq .   # → kind hashedrekord, spec.data.hash = anchored digest
\`\`\`
`
    : '### No anchors in this pack\n\nThis ledger was exported before any checkpoint was anchored (offline recording). The chain and signatures are still verifiable with Option A; external anchoring is what pins history to a public log.\n'
}
## What this proves — and what it does not

- **Proves**: the recorded history existed, in this order, no later than each
  anchor's \`integratedTime\`; any post-hoc edit, reorder, deletion, or
  truncation at-or-before an anchored checkpoint is detectable by anyone.
- **Does not prove**: that the recorder was fed the truth (a compromised host
  during recording can attest lies faithfully), or anything about entries
  after the last anchor (window ≤ 64 entries / 60 s by default, reported as
  ANCHOR LAG). Entry \`ts\` fields are local-clock claims; Rekor
  \`integratedTime\` is the trusted time.
- Ledger entries: ${entries.length}. Independent re-implementation targets:
  RFC 8785 (JCS), RFC 6962 §2.1 (Merkle), ECDSA P-256 + SHA-256 (signatures).
`;
}

function reportHtml(
  entries: LedgerEntry[],
  anchors: AnchorPayload[],
  verifyResult: string,
  ledgerId?: string,
): string {
  const calls = entries.filter((e) => e.type === 'call_request');
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const rows = entries
    .map((e) => {
      const payload =
        e.payload === undefined
          ? e.type === 'session_end'
            ? ''
            : `<em>redacted (commitment ${e.payload_hash.slice(0, 16)}…)</em>`
          : esc(e.payload.length > 160 ? e.payload.slice(0, 157) + '…' : e.payload);
      return `<tr><td>${e.seq}</td><td>${e.ts}</td><td>${e.type}</td><td>${esc(e.tool?.name ?? '')}</td><td class="p">${payload}</td></tr>`;
    })
    .join('\n');
  const anchorRows = anchors
    .map(
      (a) =>
        `<tr><td>${a.checkpoint_seq}</td><td>${a.logIndex}</td><td>${new Date(a.integratedTime * 1000).toISOString()}</td><td><a href="https://search.sigstore.dev/?logIndex=${a.logIndex}">search.sigstore.dev</a></td></tr>`,
    )
    .join('\n');
  const ok = verifyResult === 'VERIFIED';
  return `<!doctype html>
<meta charset="utf-8">
<title>Attestor evidence pack — ${ledgerId ?? 'ledger'}</title>
<style>
  body { font: 14px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 72rem; padding: 0 1rem; color: #1a1a1a; }
  h1 { font-size: 1.4rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
  .verdict { padding: .6rem 1rem; border-radius: 6px; font-weight: 600; display: inline-block; }
  .ok { background: #e6f4ea; color: #137333; } .bad { background: #fce8e6; color: #c5221f; }
  table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
  th, td { border: 1px solid #ddd; padding: 4px 8px; text-align: left; vertical-align: top; }
  th { background: #f5f5f5; } td.p { font-family: ui-monospace, monospace; word-break: break-all; }
  .note { color: #555; font-size: 13px; }
</style>
<h1>Attestor evidence pack</h1>
<p><span class="verdict ${ok ? 'ok' : 'bad'}">verify at export: ${esc(verifyResult)}</span></p>
<p class="note">Ledger ${esc(ledgerId ?? '?')} · ${entries.length} entries · ${calls.length} tool calls · ${anchors.length} public anchors.
Re-run verification yourself — see <code>VERIFY.md</code>. This report is a rendering convenience, not the evidence; the evidence is <code>ledger/entries.jsonl</code> + the public Rekor log.</p>
<h2>Public anchors (Sigstore Rekor)</h2>
${anchors.length > 0 ? `<table><tr><th>checkpoint seq</th><th>logIndex</th><th>integratedTime (trusted)</th><th>public record</th></tr>${anchorRows}</table>` : '<p class="note">none — recorded offline</p>'}
<h2>Control mappings</h2>
<p class="note">Evidence support only — compliance determinations are made by your assessor (see <code>controls/mapping.json</code>): SOC 2 CC7.2 / CC7.3 / CC4.1 · EU AI Act Art. 12 · HIPAA §164.312(b).</p>
<h2>Timeline</h2>
<table><tr><th>seq</th><th>ts (claimed)</th><th>type</th><th>tool</th><th>payload</th></tr>
${rows}
</table>
`;
}
