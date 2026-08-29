// Evidence pack: a self-contained directory an auditor can verify without
// installing attestor (VERIFY.md carries a pure curl/jq/openssl recipe).
// Control mappings claim "supports evidence for", never certification.
//
// SIEM exports (CEF/OCSF): SIEM records are indices into cryptographic evidence,
// not replacements for it. Each exported record carries entry seq, hash, and
// logIndex so auditors can locate and verify the raw cryptographic chain.
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
      format: { type: 'string' },
    },
  });
  const ledgerDir = positionals[0];
  if (ledgerDir === undefined || !existsSync(join(ledgerDir, 'ledger.jsonl'))) {
    process.stderr.write('attestor: usage: attestor export <ledger-dir> [--out <dir|file>] [--format <pack|cef|ocsf>]\n');
    process.exit(2);
  }

  const format = (values.format ?? 'pack').toLowerCase();
  if (format === 'cef') {
    const output = exportCef(ledgerDir);
    if (values.out !== undefined) {
      writeFileSync(values.out, output);
      process.stdout.write(`CEF events written to ${values.out}\n`);
    } else {
      process.stdout.write(output);
    }
    return;
  }

  if (format === 'ocsf') {
    const output = exportOcsf(ledgerDir);
    if (values.out !== undefined) {
      writeFileSync(values.out, output);
      process.stdout.write(`OCSF events written to ${values.out}\n`);
    } else {
      process.stdout.write(output);
    }
    return;
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 17) + 'Z';
  const out = values.out ?? `attestor-pack-${stamp}`;
  const packDir = await buildPack(ledgerDir, out);
  process.stdout.write(`evidence pack written to ${packDir}\n  verify it: attestor verify ${packDir}\n  or follow ${packDir}/VERIFY.md (curl + jq + openssl only)\n`);
}

/** Reconstructs tool call pairs and extracts recent anchoring logIndex for each entry. */
function collectToolCallEvents(ledgerDir: string) {
  const entries = readEntries(join(ledgerDir, 'ledger.jsonl'));
  const requests = new Map<string, LedgerEntry>();
  const key = (e: LedgerEntry) => `${e.session_id} ${e.call_id}`;

  let currentLogIndex: number | undefined;
  const events: {
    req: LedgerEntry;
    res?: LedgerEntry;
    durationMs?: number;
    status: string;
    logIndex?: number;
  }[] = [];

  for (const e of entries) {
    if (e.type === 'anchor' && e.payload !== undefined) {
      try {
        const payload = JSON.parse(e.payload) as AnchorPayload;
        currentLogIndex = payload.logIndex;
      } catch {
        // ignore
      }
    }
    if (e.type === 'call_request' && e.call_id !== undefined && !requests.has(key(e))) {
      requests.set(key(e), e);
    }
    if (e.type === 'call_result' && e.call_id !== undefined) {
      const req = requests.get(key(e));
      if (req) {
        requests.delete(key(e));
        const durationMs = Date.parse(e.ts) - Date.parse(req.ts);
        const status = e.payload?.includes('"error"') || e.payload?.includes('"isError":true') ? 'failure' : 'success';
        events.push({ req, res: e, durationMs, status, logIndex: currentLogIndex });
      }
    }
  }

  // Any unmatched requests
  for (const [, req] of requests) {
    events.push({ req, status: 'in_progress', logIndex: currentLogIndex });
  }

  return events;
}

/** Exports tool call events in Common Event Format (CEF) with cryptographic index back-references. */
export function exportCef(ledgerDir: string): string {
  const events = collectToolCallEvents(ledgerDir);
  const lines: string[] = [];

  for (const ev of events) {
    const toolName = ev.req.tool?.name ?? 'unknown_tool';
    const serverName = ev.req.tool?.server ?? 'mcp';
    const severity = ev.status === 'failure' ? '6' : '3';
    const msg = ev.req.payload ? ev.req.payload.slice(0, 200).replace(/\|/g, '\\|') : 'Tool invocation';

    const ext: string[] = [
      `src=${ev.req.session_id}`,
      `cs1=${ev.req.call_id ?? ''}`,
      `cs1Label=CallID`,
      `cs2=${ev.req.entry_hash}`,
      `cs2Label=LedgerEntryHash`,
      `cn1=${ev.req.seq}`,
      `cn1Label=LedgerSeq`,
      `outcome=${ev.status}`,
      `app=${serverName}`,
      `msg=${msg}`,
    ];

    if (ev.durationMs !== undefined) {
      ext.push(`cn2=${ev.durationMs}`, `cn2Label=DurationMs`);
    }
    if (ev.logIndex !== undefined) {
      ext.push(`cn3=${ev.logIndex}`, `cn3Label=RekorLogIndex`);
    }

    // CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
    lines.push(`CEF:0|attestor|attestor|${ATTESTOR_VERSION}|tool_call|${toolName}|${severity}|${ext.join(' ')}`);
  }

  return lines.join('\n') + (lines.length > 0 ? '\n' : '');
}

/** Exports tool call events in Open Cybersecurity Schema Framework (OCSF) API Activity JSONL format. */
export function exportOcsf(ledgerDir: string): string {
  const events = collectToolCallEvents(ledgerDir);
  const lines: string[] = [];

  for (const ev of events) {
    const record = {
      class_uid: 6003, // API Activity
      class_name: 'API Activity',
      category_uid: 6, // Application Activity
      category_name: 'Application Activity',
      activity_id: 1,  // Invoke
      activity_name: 'Invoke',
      time: Date.parse(ev.req.ts),
      status: ev.status === 'success' ? 'Success' : 'Failure',
      status_id: ev.status === 'success' ? 1 : 2,
      api: {
        operation: ev.req.tool?.name ?? 'unknown_tool',
        service: {
          name: ev.req.tool?.server ?? 'mcp',
        },
      },
      actor: {
        session: {
          uid: ev.req.session_id,
        },
      },
      unmapped: {
        ledger_seq: ev.req.seq,
        entry_hash: ev.req.entry_hash,
        rekor_log_index: ev.logIndex,
        call_id: ev.req.call_id,
        duration_ms: ev.durationMs,
        payload_hash: ev.req.payload_hash,
      },
    };
    lines.push(JSON.stringify(record));
  }

  return lines.join('\n') + (lines.length > 0 ? '\n' : '');
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
`;
}

function reportHtml(
  entries: LedgerEntry[],
  anchors: AnchorPayload[],
  result: string,
  ledgerId?: string,
): string {
  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Attestor Evidence Report</title></head>
<body>
<h1>Attestor Evidence Report</h1>
<p>Ledger ID: ${ledgerId ?? 'unknown'}</p>
<p>Verification: ${result}</p>
<p>Entries: ${entries.length}</p>
</body>
</html>`;
}
