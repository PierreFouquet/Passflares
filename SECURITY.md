# Security Policy

## Reporting a Vulnerability

Please go to - https://github.com/PierreFouquet/Passflares/security/advisories - and report a vulnerability here.

Please include all details, including, if you managed to, any data to took (not the actual data just examples).

## Scope

This repository's threat surface ends at the Cloudflare Worker and its
static assets. The following are explicitly **out of scope**, because they
are controlled by Cloudflare's edge platform rather than by application
code in this repo:

- Any path under `/cdn-cgi/*` (Cloudflare's own infrastructure: challenge
  pages, rocket loader, email decoding, etc.). External scanners
  sometimes flag missing or weak headers on these paths — they cannot be
  changed from the Worker. If you need to influence those responses,
  configure a Cloudflare Transform Rule on the zone.
- The `Server: cloudflare` response header and `cf-ray` / `cf-cache-status`
  metadata. Cloudflare appends these after the Worker returns.

Findings against application code (`src/**`, `public/**`, `wrangler.toml`)
are in scope and welcome.
