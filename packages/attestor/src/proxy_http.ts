// Streamable HTTP MCP reverse proxy with tamper-evident audit logging.
// Supports POST (JSON-RPC), GET (SSE stream with Last-Event-ID deduplication),
// and DELETE (session close).
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { URL } from 'node:url';
import type { Ledger } from './ledger.ts';
import { uuidv7 } from './ledger.ts';

export interface HttpProxyOptions {
  ledger: Ledger;
  target: string;
  onError?: 'block' | 'continue';
}

export interface HttpProxyInstance {
  server: Server;
  close(): Promise<void>;
}

export function createHttpProxyServer(opts: HttpProxyOptions): HttpProxyInstance {
  const targetUrl = new URL(opts.target);
  const isHttps = targetUrl.protocol === 'https:';
  const doRequest = isHttps ? httpsRequest : httpRequest;

  // Session high-watermark deduplication table for SSE events: session_id -> Set of seen event IDs
  const seenEvents = new Map<string, Set<string>>();

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const sessionId = (req.headers['mcp-session-id'] as string) || (req.headers['x-session-id'] as string) || uuidv7();

    if (!seenEvents.has(sessionId)) {
      seenEvents.set(sessionId, new Set());
    }
    const sessionSeen = seenEvents.get(sessionId)!;

    if (req.method === 'POST') {
      const chunks: Buffer[] = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => {
        const bodyBuf = Buffer.concat(chunks);
        const bodyStr = bodyBuf.toString('utf8');

        // Record request wire entry
        try {
          opts.ledger.append({
            type: 'wire',
            direction: 'c2s',
            origin: 'proxy',
            session_id: sessionId,
            payload: bodyStr,
          });
        } catch (err) {
          if (opts.onError === 'block') {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'attestor: audit ledger unavailable' } }));
            return;
          }
        }

        const forwardHeaders = { ...req.headers, host: targetUrl.host };
        const upstreamReq = doRequest(
          targetUrl,
          {
            method: 'POST',
            path: targetUrl.pathname + (targetUrl.search || ''),
            headers: forwardHeaders,
          },
          (upstreamRes) => {
            const respChunks: Buffer[] = [];
            upstreamRes.on('data', (c) => respChunks.push(c));
            upstreamRes.on('end', () => {
              const respBuf = Buffer.concat(respChunks);
              const respStr = respBuf.toString('utf8');

              // Record response wire entry
              try {
                opts.ledger.append({
                  type: 'wire',
                  direction: 's2c',
                  origin: 'proxy',
                  session_id: sessionId,
                  payload: respStr,
                });
              } catch {
                /* non-fatal on response record */
              }

              res.writeHead(upstreamRes.statusCode ?? 200, upstreamRes.headers);
              res.end(respBuf);
            });
          },
        );

        upstreamReq.on('error', (err) => {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `upstream gateway error: ${err.message}` }));
        });

        upstreamReq.write(bodyBuf);
        upstreamReq.end();
      });
      return;
    }

    if (req.method === 'GET') {
      const isSSE = (req.headers.accept || '').includes('text/event-stream');
      const forwardHeaders = { ...req.headers, host: targetUrl.host };

      const upstreamReq = doRequest(
        targetUrl,
        {
          method: 'GET',
          path: targetUrl.pathname + (targetUrl.search || ''),
          headers: forwardHeaders,
        },
        (upstreamRes) => {
          res.writeHead(upstreamRes.statusCode ?? 200, upstreamRes.headers);

          if (isSSE) {
            let buffer = '';
            upstreamRes.on('data', (chunk) => {
              res.write(chunk);
              buffer += chunk.toString('utf8');

              const lines = buffer.split('\n\n');
              buffer = lines.pop() || '';

              for (const frame of lines) {
                if (!frame.trim()) continue;
                const idMatch = frame.match(/^id:\s*(.+)$/m);
                const eventId = idMatch ? idMatch[1]?.trim() : undefined;

                if (eventId && sessionSeen.has(eventId)) {
                  // Duplicate replayed event from Last-Event-ID, skip recording
                  continue;
                }
                if (eventId) {
                  sessionSeen.add(eventId);
                }

                try {
                  opts.ledger.append({
                    type: 'wire',
                    direction: 's2c',
                    origin: 'proxy',
                    session_id: sessionId,
                    payload: frame,
                  });
                } catch {}
              }
            });
            upstreamRes.on('end', () => res.end());
          } else {
            upstreamRes.pipe(res);
          }
        },
      );

      upstreamReq.on('error', (err) => {
        res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end(`upstream error: ${err.message}`);
      });
      upstreamReq.end();
      return;
    }

    if (req.method === 'DELETE') {
      const forwardHeaders = { ...req.headers, host: targetUrl.host };
      const upstreamReq = doRequest(
        targetUrl,
        {
          method: 'DELETE',
          path: targetUrl.pathname + (targetUrl.search || ''),
          headers: forwardHeaders,
        },
        (upstreamRes) => {
          try {
            opts.ledger.append({
              type: 'session_end',
              origin: 'proxy',
              session_id: sessionId,
              payload: JSON.stringify({ reason: 'client_delete' }),
            });
          } catch {}
          res.writeHead(upstreamRes.statusCode ?? 200, upstreamRes.headers);
          upstreamRes.pipe(res);
        },
      );
      upstreamReq.on('error', (err) => {
        res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end(`upstream error: ${err.message}`);
      });
      upstreamReq.end();
      return;
    }

    res.writeHead(405, { 'Content-Type': 'text/plain' });
    res.end('Method Not Allowed');
  });

  return {
    server,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
