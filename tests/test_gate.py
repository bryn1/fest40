"""Gate tests for fest40 server (MC 10286.22). Live HTTP, stdlib + pytest.

Every assertion asserts on a status/content that COULD be different if the
gate were removed — the suite goes RED against a server that serves openly.
"""
import http.client
import io
import os
import socket
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

PW = "kanin-skap-2026-test"
PW2 = "nyckel-laren-2026-test"


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    """Live server on an ephemeral port, HOME set to a fresh dir exactly as
    the systemd unit does (HOME=%S/vm106-app-fest40) -- so the deployed
    state path ($HOME/fest40-state) is the path the tests exercise."""
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setattr(server, "START_TIME", time.time())
    server.get_secret(server.state_base())   # what main() does at boot
    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd
    httpd.shutdown()


def state_of(tmp_path):
    return tmp_path / "home" / "fest40-state"


def req(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    finally:
        conn.close()


def get(port, path, cookie=None):
    h = {"Cookie": cookie} if cookie else {}
    return req(port, "GET", path, headers=h)


def register(port, pw=PW):
    return req(port, "POST", "/register", body=f"password={pw}",
               headers={"Content-Type": "application/x-www-form-urlencoded"})


def login(port, pw=PW, path="/login"):
    return req(port, "POST", path, body=f"password={pw}",
               headers={"Content-Type": "application/x-www-form-urlencoded"})


def cookie_from(headers):
    sc = headers.get("Set-Cookie", "")
    tok = sc.split(";")[0]
    return tok if tok.startswith("session=") else None


def good_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.html", b"<h1>dummy party " + PARTY_MARKER + b"</h1>")
        z.writestr("_assets/dummy.txt", "dummy asset bytes")
    return buf.getvalue()


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


# -- the gate page (always-200 front, zero site bytes) -----------------------

PARTY_MARKER = b"PARTY-MARKER-9f2c"   # planted in the dummy zip; MUST never
                                      # appear on any gate page

def test_unconfigured_root_200_setup_page(srv):
    st, hdrs, body = get(srv.server_address[1], "/")
    assert st == 200
    assert "under uppsättning".encode() in body
    assert b"/register" in body
    assert len(body) >= 256 and b"dummy party" not in body
    assert hdrs.get("X-Robots-Tag") == "noindex,nosnippet"


def test_unconfigured_asset_401(srv):
    st, _, _ = get(srv.server_address[1], "/_assets/whatever.txt")
    assert st == 401   # no cookie, no byte -- the /-only 200 exception is exact


def test_gate_pages_clear_the_real_size_floor():
    """staging.py:65-66 -> MIN_BYTES_FLOOR = 256, and the live probe fails any
    product-path body under it. Both gate pages must clear it by 2x, and the
    floor value is read from the reconciler source, not hardcoded blind."""
    import re
    src = Path("/home/claudecode/agent-town/infra/vm106/repo-visibility-hosting/staging.py")
    floor = 256
    if src.is_file():                      # fleet source when present
        found = re.search(r"^MIN_BYTES_FLOOR\s*=\s*(\d+)", src.read_text(), re.M)
        assert found, "MIN_BYTES_FLOOR no longer readable in staging.py -- re-check the bar"
        floor = int(found.group(1))
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import gate_pages
    for name in ("LOGIN_PAGE", "SETUP_PAGE"):
        body = gate_pages.render(getattr(gate_pages, name), "/fest40").encode()
        assert len(body) >= 2 * floor, f"{name} is {len(body)}B, floor is {floor}B"
        assert "Alexander".encode() in body and b"<form" in body


def test_register_then_configured(srv, tmp_path):
    port = srv.server_address[1]
    st, _, _ = register(port)
    assert st == 200
    assert (state_of(tmp_path) / "password.hash").is_file()
    # configured now: / is a 200 LOGIN page (probe contract), never the site
    st, hdrs, body = get(port, "/")
    assert st == 200
    assert "Lösenord".encode() in body and b"/login" in body
    assert len(body) >= 256 and b"dummy party" not in body
    assert hdrs.get("X-Robots-Tag") == "noindex,nosnippet"
    # second register refused once configured
    st, _, _ = register(port)
    assert st == 409


def test_register_window_expired(srv, monkeypatch):
    port = srv.server_address[1]
    monkeypatch.setattr(server, "START_TIME", time.time() - server.REGISTER_WINDOW_S - 1)
    st, _, _ = register(port)
    assert st == 409
    # still unconfigured -> the setup page keeps answering (nothing to show yet)
    st, _, body = get(port, "/")
    assert st == 200 and "under uppsättning".encode() in body and PARTY_MARKER not in body


# -- the login gate ---------------------------------------------------------

def test_login_wrong_pw_401(srv):
    port = srv.server_address[1]
    assert register(port)[0] == 200
    st, hdrs, _ = login(port, "fel-losenord-har")
    assert st == 401
    assert "Set-Cookie" not in hdrs or cookie_from(hdrs) is None


def test_login_right_pw_sets_cookie(srv):
    port = srv.server_address[1]
    assert register(port)[0] == 200
    st, hdrs, _ = login(port)
    assert st == 302
    cookie = cookie_from(hdrs)
    assert cookie is not None
    assert "HttpOnly" in hdrs["Set-Cookie"] and "SameSite=Lax" in hdrs["Set-Cookie"]
    # the cookie opens the site (empty -> 404 "empty", never 401)
    st, _, body = get(port, "/", cookie)
    assert st == 404 and b"empty" in body


def test_cookie_tamper_no_site_bytes(srv):
    """A tampered cookie opens NOTHING: /_assets -> 401, / -> 200 gate page
    without a single site byte (the marker)."""
    port, cookie = _seeded(srv)
    sig, _, last = cookie.rpartition(".")
    tampered = cookie[:-1] + ("0" if cookie[-1] != "0" else "1")
    assert tampered != cookie
    st, _, _ = get(port, "/_assets/dummy.txt", tampered)
    assert st == 401
    st, _, body = get(port, "/", tampered)
    assert st == 200 and PARTY_MARKER not in body   # gate page, zero site bytes


def test_cookie_expired_no_site_bytes(srv, tmp_path):
    port, _ = _seeded(srv)
    secret = bytes.fromhex((state_of(tmp_path) / "secret.key").read_text().strip())
    stale = server.make_token(secret, int(time.time()) - 10)
    st, _, _ = get(port, "/_assets/dummy.txt", "session=" + stale)
    assert st == 401
    st, _, body = get(port, "/", "session=" + stale)
    assert st == 200 and PARTY_MARKER not in body


# -- the seed channel -------------------------------------------------------

def test_seed_without_cookie_401(srv):
    port = srv.server_address[1]
    assert register(port)[0] == 200
    st, _, _ = req(port, "POST", "/seed", body=good_zip(),
                   headers={"Content-Type": "application/zip"})
    assert st == 401


def test_seed_and_serve(srv):
    port = srv.server_address[1]
    assert register(port)[0] == 200
    cookie = cookie_from(login(port)[1])
    st, _, _ = req(port, "POST", "/seed", body=good_zip(),
                   headers={"Content-Type": "application/zip", "Cookie": cookie})
    assert st == 200
    st, hdrs, body = get(port, "/", cookie)
    assert st == 200 and PARTY_MARKER in body      # the real page opens WITH cookie
    assert "noindex" in hdrs["X-Robots-Tag"]
    st, _, body = get(port, "/_assets/dummy.txt", cookie)
    assert st == 200 and body == b"dummy asset bytes"


def test_seed_zipslip_rejected(srv, tmp_path):
    port = srv.server_address[1]
    assert register(port)[0] == 200
    cookie = cookie_from(login(port)[1])
    evil = make_zip([("../evil.txt", "pwned"), ("index.html", "<h1>dummy party</h1>")])
    st, _, _ = req(port, "POST", "/seed", body=evil,
                   headers={"Content-Type": "application/zip", "Cookie": cookie})
    assert st == 400
    assert not (tmp_path / "home" / "evil.txt").exists()      # ../ from the state dir
    assert not (state_of(tmp_path) / "evil.txt").exists()
    assert not (tmp_path / "evil.txt").exists()


def test_seed_absolute_and_symlink_rejected(srv):
    port = srv.server_address[1]
    assert register(port)[0] == 200
    cookie = cookie_from(login(port)[1])
    for bad in [make_zip([("/etc/evil.txt", "x")]),
                make_zip([("..", "x")]),
                make_zip([("a/../../evil.txt", "x")])]:
        st, _, _ = req(port, "POST", "/seed", body=bad,
                       headers={"Content-Type": "application/zip", "Cookie": cookie})
        assert st == 400
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        zi = zipfile.ZipInfo("link")
        zi.create_system = 3
        zi.external_attr = (0o120777 << 16)   # symlink mode
        z.writestr(zi, "/etc/passwd")
    st, _, _ = req(port, "POST", "/seed", body=buf.getvalue(),
                   headers={"Content-Type": "application/zip", "Cookie": cookie})
    assert st == 400


# -- the served map ---------------------------------------------------------

def _seeded(srv):
    port = srv.server_address[1]
    register(port)
    cookie = cookie_from(login(port)[1])
    req(port, "POST", "/seed", body=good_zip(),
        headers={"Content-Type": "application/zip", "Cookie": cookie})
    return port, cookie


def test_traversal_asset_404(srv):
    port, cookie = _seeded(srv)
    st, _, _ = get(port, "/_assets/../../etc/passwd", cookie)
    assert st == 404
    st, _, body = get(port, "/_assets/%2e%2e/%2e%2e/etc/passwd", cookie)
    assert st == 404 and b"root:" not in body


def test_no_index_no_site_bytes_without_cookie(srv):
    """The law: seeded + NO cookie -> / answers 200 (probe contract) but is
    the gate page: the planted marker appears on NO unauthenticated body."""
    port, _ = _seeded(srv)
    st, _, body = get(port, "/")
    assert st == 200 and PARTY_MARKER not in body
    st, _, body = get(port, "/fest40/")
    assert st == 200 and PARTY_MARKER not in body
    st, _, body = get(port, "/_assets/dummy.txt")
    assert st == 401 and b"dummy asset" not in body


def test_noindex_everywhere(srv):
    port, cookie = _seeded(srv)
    for method, path, headers in [("GET", "/", {}), ("GET", "/robots.txt", {}),
                                  ("GET", "/", {"Cookie": cookie}),
                                  ("POST", "/login", {})]:
        st, hdrs, _ = req(port, method, path, headers=headers)
        assert hdrs.get("X-Robots-Tag") == "noindex,nosnippet", (method, path, st)
    st, _, body = get(port, "/robots.txt")
    assert st == 200 and "Disallow: /" in body.decode()


# -- rotation ---------------------------------------------------------------

def test_rotate_old_pw_dead(srv):
    port, cookie = _seeded(srv)
    st, _, _ = req(port, "POST", "/rotate", body=f"password={PW2}",
                   headers={"Content-Type": "application/x-www-form-urlencoded",
                            "Cookie": cookie})
    assert st == 200
    st, _, _ = login(port, PW)
    assert st == 401
    st, hdrs, _ = login(port, PW2)
    assert st == 302 and cookie_from(hdrs) is not None


def test_rotate_without_cookie_401(srv):
    port = srv.server_address[1]
    register(port)
    st, _, _ = req(port, "POST", "/rotate", body=f"password={PW2}",
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert st == 401


# -- prefix safety ----------------------------------------------------------

def test_prefix_both_ways(srv):
    port, cookie = _seeded(srv)
    st, hdrs, body = get(port, "/fest40/", cookie)
    assert st == 200 and b"dummy party" in body
    assert hdrs.get("Location") is None
    st, _, body = get(port, "/fest40/_assets/dummy.txt", cookie)
    assert st == 200 and body == b"dummy asset bytes"
    st, _, body = get(port, "/fest40/")          # no cookie under prefix: gate page
    assert st == 200 and PARTY_MARKER not in body  # 200 form, zero site bytes
    # login under the prefix redirects back into the prefix
    st, hdrs, _ = login(port, PW, path="/fest40/login")
    assert st == 302 and hdrs.get("Location") == "/fest40/"
    # register under the prefix
    st, _, _ = req(port, "POST", "/fest40/register", body="password=zzzzzzzzzzzz")
    assert st == 409  # already configured


# -- port from env (real subprocess, real bind) ------------------------------

def test_port_env_bind(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    env = dict(os.environ, PORT=str(free), HOME=str(home))
    env.pop("XDG_STATE_HOME", None)
    proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve().parent.parent
                                                   / "server.py")],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", free), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.fail(f"server did not bind PORT={free}")
        st, hdrs, _ = req(free, "GET", "/robots.txt")
        assert st == 200
        assert hdrs.get("X-Robots-Tag") == "noindex,nosnippet"
        # booted on the unit's state contract: state under $HOME, secret made
        assert (home / "fest40-state" / "secret.key").is_file()
    finally:
        proc.terminate()
        proc.wait(timeout=5)


# -- state-dir contract (MC 10286.22 fix: HOME, not XDG_STATE_HOME) ----------

def test_home_based_state_resolution(tmp_path, monkeypatch):
    """HOME writable -> state lands under $HOME/fest40-state, cwd untouched
    (the deploy died before this fix by falling back into the read-only mirror)."""
    home, cwd = tmp_path / "home", tmp_path / "cwd"
    home.mkdir(); cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.chdir(cwd)
    base = server.state_base()
    assert base == home / "fest40-state"
    assert base.is_dir() and os.access(base, os.W_OK)
    assert not (cwd / "state").exists()          # cwd NEVER touched when HOME works
    server.write_password(base, PW)              # real write lands under HOME
    assert (base / "password.hash").is_file()
    assert not any(cwd.iterdir())                # cwd completely untouched


def test_fail_fast_when_unwritable(tmp_path):
    """HOME and cwd both unwritable -> immediate non-zero exit, clear stderr,
    never a silent fallback and never a crash-loop after bind."""
    ro_home, ro_cwd = tmp_path / "ro-home", tmp_path / "ro-cwd"
    ro_home.mkdir(); ro_cwd.mkdir()
    os.chmod(ro_home, 0o555); os.chmod(ro_cwd, 0o555)
    try:
        env = dict(os.environ, HOME=str(ro_home), PORT="0")
        env.pop("XDG_STATE_HOME", None)
        proc = subprocess.run([sys.executable,
                               str(Path(__file__).resolve().parent.parent / "server.py")],
                              env=env, cwd=str(ro_cwd), capture_output=True, timeout=10)
        assert proc.returncode != 0
        assert b"FATAL no writable state dir" in proc.stderr
    finally:
        os.chmod(ro_home, 0o755); os.chmod(ro_cwd, 0o755)
