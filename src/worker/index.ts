import { Env } from '../types';
import { HTML } from './html';

export { SSHSessionDO } from './durable-object';

// --- Rate Limiting (per-edge-node, best-effort) ---
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_MAX = 10;      // max requests per window
const RATE_LIMIT_WINDOW = 60000; // 1 minute window

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return false;
  }
  entry.count++;
  return entry.count > RATE_LIMIT_MAX;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/api/ssh') {
      // Apply rate limiting
      const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
      if (isRateLimited(clientIP)) {
        return new Response('Too Many Requests', { status: 429 });
      }
      return handleSSHConnection(request, env);
    }

    if (url.pathname === '/api/health') {
      return Response.json({ status: 'ok', timestamp: Date.now() });
    }

    return new Response(HTML, {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
      }
    });
  },
};

async function handleSSHConnection(request: Request, env: Env): Promise<Response> {
  const upgradeHeader = request.headers.get('Upgrade');
  if (upgradeHeader !== 'websocket') {
    return Response.json(
      { error: 'Expected WebSocket upgrade' },
      { status: 426 }
    );
  }

  // Prevent Cross-Site WebSocket Hijacking / Quota Leeching
  const origin = request.headers.get('Origin');
  if (origin) {
    const url = new URL(request.url);
    if (origin !== url.origin) {
      return new Response('Forbidden', { status: 403 });
    }
  }

  const doId = env.SSH_SESSION.idFromName(`session:${Date.now()}:${Math.random()}`);
  const stub = env.SSH_SESSION.get(doId);

  return stub.fetch(request);
}
