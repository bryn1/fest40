# fest40

Password-gated host for the owner's 40-year party page. Public URL:
`https://sibbamala.com/fest40/` (vm106 reconciler auto-hosts this public repo;
nginx proxies the service under the `/fest40/` prefix — `server.py` answers
both prefixed and bare paths).

## What it is

A stdlib-only Python service (`server.py`, binds `0.0.0.0:$PORT`):

- **Gate (fail-closed).** `GET /` ALWAYS answers `200` with a gate page — the
  setup form while unconfigured ("Sidan är under uppsättning"), then the
  password form once a password exists. That page carries ZERO site bytes:
  it is the fleet-accepted shape (the vm106 staging gate and the live probe
  both demand a 200 with a sized body on the product path — the slakttraff
  precedent), and the real content still only opens behind the cookie.
  `POST /login` verifies with a constant-time compare and sets an HttpOnly
  SameSite=Lax HMAC-signed session cookie (30 days). While unconfigured,
  `POST /login`, `/seed` and `/rotate` answer `503`, and a one-time register
  window — 20 minutes from process start, only while unconfigured — accepts
  `POST /register` (`password=...`) and stores an scrypt hash. Unauthenticated
  `GET` on anything but `/` and `/robots.txt` answers `404` — never `401`,
  because to the vm106 quarantine probe a `401` on a repo file counts as
  REACHABLE and discloses the path; every such `404` is byte-identical, so the
  server leaks no path inventory. `POST` auth failures still answer `401`
  (the probes never POST). **No cookie, no site byte is ever served.**
- **Content in.** The only content channel is `POST /seed` with a valid
  session cookie and raw zip bytes (cap 20 MB, zip-slip guarded: absolute
  paths, `..`, symlinks and non-files rejected). The zip is unpacked
  atomically (wipe-then-write) into the host state dir.
- **Served map.** `GET /` → `state/site/index.html` (404 "empty" until
  seeded); `GET /_assets/…` → files strictly under `state/site/_assets/`
  (resolve + prefix check, 404 otherwise). No directory listings.
- **Invisible to search.** `X-Robots-Tag: noindex,nosnippet` on every response
  plus a `robots.txt` with `Disallow: /`.

## State (NOT in git — never commit content)

Site data lives in the service's own state dir, OUTSIDE the repo, and
survives redeploys. Base = `$HOME/fest40-state`, because the rendered unit
sets `Environment=HOME=%S/vm106-app-fest40` (its `StateDirectory`, writable)
and never sets `$XDG_STATE_HOME`. `./state/` is the fallback only when HOME
is unset or unwritable (plain local runs); if neither is writable the
service exits with a clear error instead of writing blind. Layout: `site/`
(served content), `password.hash` (scrypt), `secret.key` (0600, generated on
first boot). The repo is CODE ONLY — wedding bytes never enter git.

## Admin

- Rotate the password: `POST /rotate` (valid session cookie, `password=...`).
- Re-seed any time: `POST /seed` (same cookie).

## Honest limits

- The gate is **anti-casual + noindex, NOT a vault.** Anyone with the password
  is admin (can re-seed/deface and read the page).
- The register window is open for the first 20 minutes of a first boot until
  the password is set — configure immediately after the first deploy.
- The password hash (and the ability to rotate it) lives in the host state
  dir; a host compromise reads it.

## Test

`tests/selftest.sh` — pytest suite + a live-curl gate battery (register,
login, tamper, seed guards, traversal, rotate, both prefixes). Run it after
any change; every leg prints PASS/FAIL and the script exits non-zero on any
failure.
