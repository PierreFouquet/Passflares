#!/usr/bin/env node
// Zero-dependency static file server for the Playwright E2E run.
//
// Replaces `http-server`, which is unmaintained and pulls in a deprecated
// dependency chain (html-encoding-sniffer@3 -> whatwg-encoding@2). E2E only
// needs to serve `public/` over HTTP with caching disabled, which is about
// sixty lines of `node:http` — not worth a transitive dependency tree.
//
// Design note: the served tree is enumerated once at startup into an allowlist
// keyed by URL path, and a request can only ever *look up* that map. No value
// derived from the request is ever joined, resolved, or otherwise turned into a
// filesystem path. That makes directory traversal structurally impossible
// rather than defended-against — an earlier version did build paths from the
// URL and guard them with a containment check, which was correct but relied on
// getting the guard exactly right, and left an unhandled `decodeURIComponent`
// throw that let `GET /%` take the whole process down.
//
// Usage: node scripts/static-server.mjs <root> <port>

import { createServer } from 'node:http';
import { createReadStream } from 'node:fs';
import { readdir, stat } from 'node:fs/promises';
import { extname, join, posix, resolve } from 'node:path';

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

/**
 * Walks `dir` once and returns Map<urlPath, { file, size }>.
 * Directories get an extra entry pointing at their index.html, so `/` and
 * `/docs/` resolve without any request-time path arithmetic.
 */
async function buildAllowlist(dir, urlPrefix = '') {
    const entries = new Map();
    for (const name of await readdir(dir)) {
        const absolute = join(dir, name);
        const info = await stat(absolute);
        const urlPath = `${urlPrefix}/${name}`;
        if (info.isDirectory()) {
            for (const [k, v] of await buildAllowlist(absolute, urlPath)) entries.set(k, v);
        } else {
            entries.set(urlPath, { file: absolute, size: info.size });
            if (name === 'index.html') {
                entries.set(`${urlPrefix}/`, { file: absolute, size: info.size });
                if (urlPrefix) entries.set(urlPrefix, { file: absolute, size: info.size });
            }
        }
    }
    return entries;
}

/**
 * Request path -> allowlist key. Returns null for anything unusable, including
 * malformed percent-encoding: decodeURIComponent throws URIError on input like
 * `/%`, and an uncaught throw here previously killed the process.
 */
function lookupKey(rawUrl) {
    try {
        const path = decodeURIComponent(rawUrl.split('?')[0].split('#')[0]);
        // Normalise `//a`, `/a/./b`, `/a/../b` to a single canonical form so one
        // file has one key. Traversal above the root cannot escape anything —
        // the result is only ever a map lookup — but it should still 404 rather
        // than alias some other entry.
        return posix.normalize(path);
    } catch {
        return null;
    }
}

const allowlist = await buildAllowlist(root);

const server = createServer((req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { Allow: 'GET, HEAD' }).end();
        return;
    }

    const key = lookupKey(req.url ?? '/');
    const entry = key === null ? undefined : allowlist.get(key);
    if (!entry) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found');
        return;
    }

    res.writeHead(200, {
        'Content-Type': MIME[extname(entry.file)] ?? 'application/octet-stream',
        'Content-Length': entry.size,
        // -c-1 equivalent: E2E must never see a stale asset.
        'Cache-Control': 'no-store'
    });
    if (req.method === 'HEAD') {
        res.end();
        return;
    }

    const stream = createReadStream(entry.file);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
});

server.listen(port, () => {
    process.stdout.write(`static-server: ${root} (${allowlist.size} paths) on http://localhost:${port}\n`);
});
