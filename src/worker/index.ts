import { Env } from '../types';
import { HTML } from './html';

export { SSHSessionDO } from './durable-object';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/api/ssh') {
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
