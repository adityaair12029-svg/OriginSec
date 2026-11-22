import type { IncomingMessage, ServerResponse } from 'node:http';

let cachedApp: ((req: any, res: any) => any) | null = null;

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  try {
    if (!cachedApp) {
      const { createApiApp } = await import('../src/lib/server/app.js');
      cachedApp = createApiApp();
    }
    return cachedApp(req as any, res as any);
  } catch (err) {
    console.error('Vercel API handler error:', err);
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          error: err instanceof Error ? err.message : 'Serverless handler initialization error.',
        })
      );
    }
  }
}
