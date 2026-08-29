import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHttpProxyServer } from '../src/proxy_http.ts';
import { Ledger, readEntries } from '../src/ledger.ts';
import { generateKey } from '../src/keys.ts';

test('Streamable HTTP proxy: POST round-trip records c2s and s2c in ledger', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-http-proxy-test-'));
  const keys = generateKey(dir);
  const ledger = Ledger.open(dir, keys);

  // 1. Mock upstream MCP server
  const upstream = createServer((req, res) => {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Mcp-Session-Id': 'sess-1' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { status: 'ok' } }));
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', () => resolve()));
  const upstreamPort = (upstream.address() as { port: number }).port;

  // 2. Start reverse proxy
  const proxy = createHttpProxyServer({
    target: `http://127.0.0.1:${upstreamPort}/mcp`,
    ledger,
  });

  await new Promise<void>((resolve) => proxy.server.listen(0, '127.0.0.1', () => resolve()));
  const proxyPort = (proxy.server.address() as { port: number }).port;

  // 3. Make client request through proxy
  const res = await fetch(`http://127.0.0.1:${proxyPort}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': 'sess-1' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'add' } }),
  });

  assert.equal(res.status, 200);
  const data = (await res.json()) as { result: { status: string } };
  assert.equal(data.result.status, 'ok');

  ledger.close();
  await proxy.close();
  await new Promise<void>((resolve) => upstream.close(() => resolve()));

  // 4. Verify ledger entries
  const entries = readEntries(join(dir, 'ledger.jsonl'));
  const c2s = entries.find((e) => e.type === 'wire' && e.direction === 'c2s');
  const s2c = entries.find((e) => e.type === 'wire' && e.direction === 's2c');

  assert.ok(c2s, 'c2s wire entry must be recorded');
  assert.ok(s2c, 's2c wire entry must be recorded');
  assert.ok(c2s.payload?.includes('tools/call'));
  assert.ok(s2c.payload?.includes('status'));

  rmSync(dir, { recursive: true, force: true });
});

test('Streamable HTTP proxy: SSE deduplication on Last-Event-ID replay', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-sse-test-'));
  const keys = generateKey(dir);
  const ledger = Ledger.open(dir, keys);

  // 1. Mock upstream SSE server
  const upstream = createServer((req, res) => {
    if (req.method === 'GET') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Mcp-Session-Id': 'sess-sse-1',
        'Cache-Control': 'no-cache',
      });
      // Emits event id: 101, then id: 102
      res.write('id: 101\nevent: message\ndata: {"count":1}\n\n');
      res.write('id: 102\nevent: message\ndata: {"count":2}\n\n');
      res.end();
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', () => resolve()));
  const upstreamPort = (upstream.address() as { port: number }).port;

  const proxy = createHttpProxyServer({
    target: `http://127.0.0.1:${upstreamPort}/mcp`,
    ledger,
  });

  await new Promise<void>((resolve) => proxy.server.listen(0, '127.0.0.1', () => resolve()));
  const proxyPort = (proxy.server.address() as { port: number }).port;

  // Initial SSE stream read
  const res1 = await fetch(`http://127.0.0.1:${proxyPort}`, {
    headers: { Accept: 'text/event-stream', 'Mcp-Session-Id': 'sess-sse-1' },
  });
  await res1.text();

  // Replay SSE stream (same session)
  const res2 = await fetch(`http://127.0.0.1:${proxyPort}`, {
    headers: { Accept: 'text/event-stream', 'Mcp-Session-Id': 'sess-sse-1', 'Last-Event-ID': '101' },
  });
  await res2.text();

  ledger.close();
  await proxy.close();
  await new Promise<void>((resolve) => upstream.close(() => resolve()));

  // Verify only 2 SSE wire entries were recorded, not 4 (no double-counting)
  const entries = readEntries(join(dir, 'ledger.jsonl'));
  const sseEntries = entries.filter((e) => e.type === 'wire' && e.direction === 's2c');

  assert.equal(sseEntries.length, 2, 'Replayed SSE events must be deduplicated in ledger');

  rmSync(dir, { recursive: true, force: true });
});
