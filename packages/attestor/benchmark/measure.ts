// Benchmark script to measure ledger append latency, durability modes, and proxy overhead.
// Run with: node benchmark/measure.ts
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir, platform, arch, cpus } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { generateKey } from '../src/keys.ts';
import { Ledger } from '../src/ledger.ts';

interface BenchResult {
  mode: string;
  payloadSize: string;
  iterations: number;
  meanMs: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  throughputOpsSec: number;
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(Math.floor((p / 100) * sorted.length), sorted.length - 1);
  return sorted[idx]!;
}

function benchmarkAppend(durability: 'strict' | 'group', payloadBytes: number, iterations = 100): BenchResult {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-bench-'));
  const home = join(dir, 'home');
  const ledgerDir = join(dir, 'ledger');

  try {
    const keys = generateKey(home);
    const ledger = Ledger.open(ledgerDir, keys, { durability });
    const payloadStr = JSON.stringify({ data: 'x'.repeat(payloadBytes) });

    const latencies: number[] = [];

    // Warmup
    for (let i = 0; i < 5; i++) {
      ledger.append({
        type: 'call_request',
        origin: 'proxy',
        call_id: `warmup-${i}`,
        payload: payloadStr,
      });
    }

    // Measurement
    const totalStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      ledger.append({
        type: 'call_request',
        origin: 'proxy',
        call_id: `bench-${i}`,
        payload: payloadStr,
      });
      latencies.push(performance.now() - t0);
    }
    const totalElapsedSec = (performance.now() - totalStart) / 1000;
    ledger.close();

    latencies.sort((a, b) => a - b);
    const meanMs = latencies.reduce((a, b) => a + b, 0) / latencies.length;
    const p50Ms = percentile(latencies, 50);
    const p95Ms = percentile(latencies, 95);
    const p99Ms = percentile(latencies, 99);
    const throughputOpsSec = iterations / totalElapsedSec;

    const payloadLabel =
      payloadBytes >= 1024 * 1024
        ? `${payloadBytes / (1024 * 1024)} MB`
        : payloadBytes >= 1024
        ? `${payloadBytes / 1024} KB`
        : `${payloadBytes} B`;

    return {
      mode: durability,
      payloadSize: payloadLabel,
      iterations,
      meanMs: Number(meanMs.toFixed(3)),
      p50Ms: Number(p50Ms.toFixed(3)),
      p95Ms: Number(p95Ms.toFixed(3)),
      p99Ms: Number(p99Ms.toFixed(3)),
      throughputOpsSec: Number(throughputOpsSec.toFixed(1)),
    };
  } finally {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
}

async function main() {
  process.stdout.write('\n============================================================\n');
  process.stdout.write('  Attestor Flight Recorder — Overhead & Latency Benchmark\n');
  process.stdout.write('============================================================\n\n');

  const cpuList = cpus();
  const cpuModel = cpuList.length > 0 ? cpuList[0]!.model : 'Unknown';
  process.stdout.write(`Platform: ${platform()} (${arch()})\n`);
  process.stdout.write(`CPU:      ${cpuModel} (${cpuList.length} cores)\n`);
  process.stdout.write(`Node:     ${process.version}\n\n`);

  const SIZES = [
    { label: '1 KB', bytes: 1024 },
    { label: '64 KB', bytes: 64 * 1024 },
    { label: '1 MB', bytes: 1024 * 1024 },
  ];

  const results: BenchResult[] = [];

  process.stdout.write('Running benchmarks (100 appends each)...\n\n');

  for (const size of SIZES) {
    process.stdout.write(`Measuring payload: ${size.label} (strict)...\n`);
    results.push(benchmarkAppend('strict', size.bytes, 100));

    process.stdout.write(`Measuring payload: ${size.label} (group)...\n`);
    results.push(benchmarkAppend('group', size.bytes, 100));
  }

  process.stdout.write('\n----------------------------------------------------------------------------------------\n');
  process.stdout.write(
    `| ${'Durability'.padEnd(10)} | ${'Payload'.padEnd(10)} | ${'Mean (ms)'.padEnd(10)} | ${'P50 (ms)'.padEnd(10)} | ${'P95 (ms)'.padEnd(10)} | ${'P99 (ms)'.padEnd(10)} | ${'Throughput (ops/s)'.padEnd(18)} |\n`,
  );
  process.stdout.write('----------------------------------------------------------------------------------------\n');

  for (const r of results) {
    process.stdout.write(
      `| ${r.mode.padEnd(10)} | ${r.payloadSize.padEnd(10)} | ${String(r.meanMs).padEnd(10)} | ${String(r.p50Ms).padEnd(10)} | ${String(r.p95Ms).padEnd(10)} | ${String(r.p99Ms).padEnd(10)} | ${String(r.throughputOpsSec).padEnd(18)} |\n`,
    );
  }
  process.stdout.write('----------------------------------------------------------------------------------------\n\n');
}

main().catch((err) => {
  process.stderr.write(`Benchmark error: ${(err as Error).stack}\n`);
  process.exit(1);
});
