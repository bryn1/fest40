#!/usr/bin/env python3
"""fest40 — password-gated host for the owner's party page (MC 10286.22).

Stdlib-only http.server service deployed by the vm106 reconciler (public-repo
auto-host lane). nginx proxies it under /fest40/, so every route answers BOTH
/fest40/... and bare /... paths. Binds 0.0.0.0:$PORT (no fallback).

State lives OUTSIDE git in the service's own state dir. Per the systemd unit
contract the unit sets HOME=%S/vm106-app-fest40 (a writable StateDirectory)
and NEVER sets $XDG_STATE_HOME; so state_base() = $HOME/fest40-state, with a
./state/ fallback only when HOME is unset/unwritable (local tests), and a
fail-fast exit when neither is writable (never write blind). Layout: site/
(served content, enters ONLY via POST /seed, never committed), password.hash
(scrypt), secret.key (0600 HMAC secret, made on first boot).

Gate is fail-closed: unconfigured -> site/seed/rotate 503; one register
window (20 min from process start, only while unconfigured) sets the
password. Configured -> every site byte requires a valid HMAC session cookie
(30 d, HttpOnly SameSite=Lax). X-Robots-Tag: noindex,nosnippet + robots.txt
Disallow everywhere. Honest limits: register window open at first boot until
configured; password hash lives in the host state dir (rotate via
POST /rotate); admin = anyone-with-the-password. Anti-casual, NOT a vault.
"""
import hashlib
import hmac
import io
import os
import secrets
import time
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

PREFIX = "/fest40"
HASH_NAME = "password.hash"
SECRET_NAME = "secret.key"
SITE_DIR = "site"
REGISTER_WINDOW_S = 20 * 60
SESSION_TTL_S = 30 * 24 * 3600
MAX_BODY = 20 * 1024 * 1024
MIN_PW_LEN = 10
START_TIME = time.time()
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1

LOGIN_FORM = (
    "<!doctype html><meta charset=utf-8>"
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>fest40</title><meta name=robots content=noindex>"
    "<body style='font-family:sans-serif;max-width:24em;margin:4em auto'>"
    "<h1>fest40</h1><p>Denna sida kräver lösenord.</p>"
    "<form method=post action='{base}/login'>"
    "<input type=password name=password placeholder='Lösenord' required>"
    "<button type=submit>Logga in</button></form></body>"
)
ROBOTS_TXT = "User-agent: *\nDisallow: /\n"


def state_base() -> Path:
    """Service state dir per the vm106 unit contract: $HOME/fest40-state
    (the unit sets HOME=%S/vm106-app-fest40, a writable StateDirectory, and
    NEVER sets $XDG_STATE_HOME). Fallback ./state/ only when HOME is
    unset/unwritable (local runs). Fail fast when neither is writable --
    never write blind (MC 10286.22: the first deploy died Errno 30 writing
    into the read-only mirror, because this read only $XDG_STATE_HOME)."""
    cands = []
    home = os.environ.get("HOME")
    if home:
        cands.append(Path(home, "fest40-state"))
    cands.append(Path.cwd() / "state")
    for cand in cands:
        try:
            cand.mkdir(parents=True, exist_ok=True)
            if os.access(cand, os.W_OK):
                return cand
        except OSError:
            continue
    raise SystemExit("fest40: FATAL no writable state dir "
                     f"(tried {', '.join(str(c) for c in cands)}) -- refusing to start")


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                        p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    """Constant-time compare of a recomputed digest; malformed stored -> False."""
    try:
        scheme, n, r, p, salt_hex, dk_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt_hex),
                            n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(dk_hex)))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, TypeError):
        return False


def make_token(secret: bytes, expiry: int) -> str:
    sig = hmac.new(secret, str(expiry).encode(), hashlib.sha256).hexdigest()
    return f"{expiry}.{sig}"


def check_token(secret: bytes, token: str) -> bool:
    expiry, _, sig = token.partition(".")
    try:
        exp = int(expiry)
    except ValueError:
        return False
    if exp < time.time():
        return False
    want = hmac.new(secret, expiry.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)


def get_secret(base: Path) -> bytes:
    """0600 hex HMAC secret, generated on first boot. Caller holds umask 0o077."""
    f = base / SECRET_NAME
    if not f.exists():
        f.write_bytes(secrets.token_hex(32).encode() + b"\n")
    return bytes.fromhex(f.read_text().strip())


def read_password(base: Path):
    f = base / HASH_NAME
    if not f.exists():
        return None
    return f.read_text().strip() or None


def write_password(base: Path, pw: str) -> None:
    """Atomic: temp + os.replace under umask 0o077."""
    tmp = base / (HASH_NAME + ".tmp")
    tmp.write_text(hash_password(pw))
    os.chmod(tmp, 0o600)
    os.replace(tmp, base / HASH_NAME)


def strip_prefix(path: str) -> str:
    if path == PREFIX:
        return "/"
    if path.startswith(PREFIX + "/"):
        return path[len(PREFIX):]
    return path


def app_base(path: str) -> str:
    return PREFIX if path.startswith(PREFIX) else ""


def safe_rel(rel: str):
    """Zip member name -> repo-safe relative path, or None if hostile."""
    if not rel or rel.startswith("/") or "\\" in rel or ":" in rel:
        return None
    parts = rel.split("/")
    if any(part == ".." for part in parts):
        return None
    return "/".join(p for p in parts if p not in ("", ".")) or None


def safe_site_path(site_dir: Path, url_path: str):
    """URL path -> existing regular file strictly under site_dir, else None."""
    try:
        rel = unquote(url_path)
        cand = (site_dir / rel.lstrip("/")).resolve()
    except (OSError, ValueError):
        return None
    base = site_dir.resolve()
    if cand == base or not str(cand).startswith(str(base) + os.sep):
        return None
    return cand if cand.is_file() else None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fest40/1.0"

    # -- plumbing ---------------------------------------------------------
    def log_message(self, fmt, *args):  # keep stderr clean of request noise
        pass

    def _send(self, status, body=b"", ctype="text/plain; charset=utf-8",
              extra_headers=(), include_body=True):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Robots-Tag", "noindex,nosnippet")
        self.send_header("Cache-Control", "no-store")
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        if include_body:
            self.wfile.write(data)

    def _body(self, limit):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0:
            return None
        if length > limit:
            return "TOOBIG"
        return self.rfile.read(length)

    def _session_ok(self):
        cookie = self.headers.get("Cookie", "")
        secret = get_secret(state_base())
        for part in cookie.split(";"):
            name, _, val = part.strip().partition("=")
            if name == "session" and val and check_token(secret, unquote(val)):
                return True
        return False

    def _pw_form(self, base, status=HTTPStatus.UNAUTHORIZED):
        self._send(status, LOGIN_FORM.format(base=base), "text/html; charset=utf-8")

    # -- routes -----------------------------------------------------------
    def do_GET(self):
        raw = urlparse(self.path).path
        if raw == "/robots.txt" or raw == PREFIX + "/robots.txt":
            self._send(200, ROBOTS_TXT, "text/plain; charset=utf-8")
            return
        path, base = strip_prefix(raw), app_base(raw)
        if path == "/register" and self._register_open():
            self._send(200, "<!doctype html><meta charset=utf-8><title>fest40 setup</title>"
                       "<meta name=robots content=noindex><body><h1>fest40 setup</h1>"
                       "<form method=post action='" + base + "/register'>"
                       "<input type=password name=password placeholder='Nytt losenord' required>"
                       "<button>Installera</button></form></body>",
                       "text/html; charset=utf-8")
            return
        if not self._session_ok():
            if read_password(state_base()) is None:
                self._send(HTTPStatus.SERVICE_UNAVAILABLE, "not configured\n")
            else:
                self._pw_form(base)
            return
        if path in ("/", "/index.html"):
            self._serve_site_index()
        elif path.startswith("/_assets/"):
            self._serve_asset(path)
        else:
            self._send(HTTPStatus.NOT_FOUND, "not found\n")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        raw = urlparse(self.path).path
        path, base = strip_prefix(raw), app_base(raw)
        body = self._body(MAX_BODY)
        if body == "TOOBIG":
            self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body too large\n")
            return
        configured = read_password(state_base()) is not None
        if path == "/register":
            if configured or not self._register_open():
                self._send(HTTPStatus.CONFLICT, "register closed\n")
                return
            pw = self._form_pw(body)
            if not pw or len(pw) < MIN_PW_LEN:
                self._send(HTTPStatus.BAD_REQUEST, f"password too short\n")
                return
            write_password(state_base(), pw)
            self._send(200, "configured\n")
            return
        if path == "/login":
            if not configured:
                self._send(HTTPStatus.SERVICE_UNAVAILABLE, "not configured\n")
                return
            if not verify_password(self._form_pw(body) or "", read_password(state_base())):
                time.sleep(0.5)  # cheap brute-force pace, fail closed
                self._pw_form(base)
                return
            exp = int(time.time()) + SESSION_TTL_S
            tok = make_token(get_secret(state_base()), exp)
            self._send(HTTPStatus.FOUND, b"", extra_headers=[
                ("Set-Cookie", f"session={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_S}"),
                ("Location", base + "/"),
            ])
            return
        # everything past here is admin: session required, fail closed
        if not self._session_ok():
            self._send(HTTPStatus.UNAUTHORIZED, "login required\n")
            return
        if path == "/seed":
            self._seed(body if isinstance(body, bytes) else b"")
        elif path == "/rotate":
            pw = self._form_pw(body)
            if not pw or len(pw) < MIN_PW_LEN:
                self._send(HTTPStatus.BAD_REQUEST, "password too short\n")
                return
            write_password(state_base(), pw)
            self._send(200, "rotated\n")
        else:
            self._send(HTTPStatus.NOT_FOUND, "not found\n")

    # -- route helpers ----------------------------------------------------
    def _register_open(self):
        return read_password(state_base()) is None and \
            time.time() - START_TIME < REGISTER_WINDOW_S

    @staticmethod
    def _form_pw(body):
        if not isinstance(body, bytes) or not body:
            return None
        vals = parse_qs(body.decode("utf-8", "replace")).get("password")
        return vals[0] if vals else None

    def _serve_site_index(self):
        idx = state_base() / SITE_DIR / "index.html"
        if not idx.is_file():
            self._send(HTTPStatus.NOT_FOUND, "empty\n")
            return
        self._send(200, idx.read_bytes(), "text/html; charset=utf-8")

    def _serve_asset(self, path):
        # path keeps its /_assets/ prefix: files live under state/site/_assets/
        f = safe_site_path(state_base() / SITE_DIR, path)
        if f is None:
            self._send(HTTPStatus.NOT_FOUND, "not found\n")
            return
        ctype = "text/html; charset=utf-8" if f.suffix == ".html" else "text/plain; charset=utf-8"
        self._send(200, f.read_bytes(), ctype)

    def _seed(self, body: bytes):
        if not body:
            self._send(HTTPStatus.BAD_REQUEST, "empty body\n")
            return
        base, site = state_base(), state_base() / SITE_DIR
        try:
            zf = zipfile.ZipFile(io.BytesIO(body))
            infos = [i for i in zf.infolist() if not i.is_dir()]
        except zipfile.BadZipFile:
            self._send(HTTPStatus.BAD_REQUEST, "bad zip\n")
            return
        entries = []
        for i in infos:
            if i.create_system not in (0, 3):           # 0/3 = DOS/unix; others exotic
                self._send(HTTPStatus.BAD_REQUEST, f"zip entry not allowed: {i.filename!r}\n")
                return
            if (i.external_attr >> 16) & 0o170000 == 0o120000:  # symlink
                self._send(HTTPStatus.BAD_REQUEST, f"zip symlink rejected: {i.filename!r}\n")
                return
            rel = safe_rel(i.filename)
            if rel is None:
                self._send(HTTPStatus.BAD_REQUEST, f"zip entry not allowed: {i.filename!r}\n")
                return
            entries.append((i, rel))
        staging = base / (SITE_DIR + ".staging")
        old = base / (SITE_DIR + ".old")
        try:
            if staging.exists():
                _rmtree(staging)
            staging.mkdir(parents=True)
            for info, rel in entries:
                target = staging / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    while chunk := src.read(65536):
                        dst.write(chunk)
            if site.exists():
                if old.exists():
                    _rmtree(old)
                site.rename(old)
            staging.rename(site)
            if old.exists():
                _rmtree(old)
        except (OSError, zipfile.BadZipFile, RuntimeError):
            if staging.exists():
                _rmtree(staging)
            if not site.exists() and old.exists():     # restore the wipe-then-fail case
                old.rename(site)
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, "seed failed\n")
            return
        self._send(200, f"seeded {len(entries)} files\n")


def _rmtree(p: Path):
    import shutil
    shutil.rmtree(p)


def main():
    os.umask(0o077)
    base = state_base()
    get_secret(base)                    # generate on first boot, under the umask
    port = int(os.environ["PORT"])      # no fallback: the unit must export PORT
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"fest40 listening on 0.0.0.0:{port}, state {base}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
