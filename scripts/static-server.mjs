#!/usr/bin/env node
// Zero-dependency static file server for the Playwright E2E run.
//
// Replaces `http-server`, which is unmaintained and pulls in a deprecated
// dependency chain (html-encoding-sniffer@3 -> whatwg-encoding@2). E2E only
// needs to serve `public/` over HTTP with caching disabled, which is about
// forty lines of `node:http` — not worth a transitive dependency tree.
//
// Usage: node scripts/static-server.mjs <root> <port>

import { createServer } from 'node:http';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { extname, join, normalize, resolve, sep } from 'node:path';

const root = resolve(process.argv[2] ?? 'public');
const port = Number(process.argv[3] ?? 4173);

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.webp': 'image/webp',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
    '.txt': 'text/plain; charset=utf-8',
    '.map': 'application/json; charset=utf-8'
};

// Resolve a URL path to a file inside `root`, or null if it escapes the root.
// normalize() collapses `..` segments before the prefix check, so `/../etc/passwd`
// can't traverse out.
function resolveWithinRoot(urlPath) {
    const decoded = decodeURIComponent(urlPath.split('?')[0]);
    const candidate = resolve(join(root, normalize(decoded)));
    if (candidate !== root && !candidate.startsWith(root + sep)) return null;
    return candidate;
}

const server = createServer(async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { Allow: 'GET, HEAD' }).end();
        return;
    }

    let filePath = resolveWithinRoot(req.url ?? '/');
    if (!filePath) {
        res.writeHead(403).end('Forbidden');
        return;
    }

    try {
        let info = await stat(filePath);
        if (info.isDirectory()) {
            filePath = join(filePath, 'index.html');
            info = await stat(filePath);
        }
        res.writeHead(200, {
            'Content-Type': MIME[extname(filePath)] ?? 'application/octet-stream',
            'Content-Length': info.size,
            // -c-1 equivalent: E2E must never see a stale asset.
            'Cache-Control': 'no-store'
        });
        if (req.method === 'HEAD') {
            res.end();
            return;
        }
        createReadStream(filePath).pipe(res);
    } catch {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found');
    }
});

server.listen(port, () => {
    process.stdout.write(`static-server: ${root} on http://localhost:${port}\n`);
});
