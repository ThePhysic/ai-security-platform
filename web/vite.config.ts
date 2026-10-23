import { defineConfig, type Plugin } from 'vite';

export const FRONTEND = 'http://127.0.0.1:18082';
export const API = 'http://127.0.0.1:18081';

function boundary(): Plugin {
  const install = (server: { middlewares: { use: Function } }, development: boolean) => {
    server.middlewares.use((req: { headers: Record<string, string | undefined> }, res: {
      setHeader: (name: string, value: string) => void;
      writeHead: (status: number) => void; end: (value?: string) => void;
    }, next: () => void) => {
      if (req.headers.host !== '127.0.0.1:18082' ||
          (req.headers.origin !== undefined && req.headers.origin !== FRONTEND)) {
        res.writeHead(403); res.end('Local dashboard access denied'); return;
      }
      res.setHeader('Content-Security-Policy', [
        "default-src 'none'", "script-src 'self'", "style-src 'self'" + (development ? " 'unsafe-inline'" : ''),
        "img-src 'self'", "font-src 'self'", `connect-src 'self' ${API}` + (development ? ' ws://127.0.0.1:18082' : ''),
        "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'",
      ].join('; '));
      const originalSetHeader = res.setHeader.bind(res);
      res.setHeader = (name: string, value: string) => originalSetHeader(name,
        name.toLowerCase() === 'cache-control' ? 'no-store' : value);
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
      next();
    });
  };
  return {
    name: 'local-browser-boundary',
    configureServer: server => install(server, true),
    configurePreviewServer: server => install(server, false),
  };
}

export default defineConfig({
  plugins: [boundary()],
  envDir: false,
  envPrefix: '__NO_CLIENT_ENVIRONMENT__',
  server: { host: '127.0.0.1', port: 18082, strictPort: true, cors: false,
    allowedHosts: ['127.0.0.1'], fs: { strict: true, allow: ['.'], deny: ['**/.env*', '**/AGENTS.md', '**/.local/**', '**/.git/**', '**/tests/**'] } },
  preview: { host: '127.0.0.1', port: 18082, strictPort: true, cors: false, allowedHosts: ['127.0.0.1'] },
  build: { sourcemap: false },
});
