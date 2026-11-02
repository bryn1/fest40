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
    """Live server on an ephemeral port with an isolated state dir."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(server, "START_TIME", time.time())
    server.get_secret(server.state_base())   # what main() does at boot
    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd
    httpd.shutdown()


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
        z.writestr("index.html", "<h1>dummy party</h1>")
        z.writestr("_assets/dummy.txt", "dummy asset bytes")
    return buf.getvalue()


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


# -- the unconfigured gate --------------------------------------------------

def test_unconfigured_site_503(srv):
    st, _, body = get(srv.server_address[1], "/")
    assert st == 503
    assert b"not configured" in body


def test_unconfigured_asset_503(srv):
    st, _, _ = get(srv.server_address[1], "/_assets/whatever.txt")
    assert st == 503


def test_register_then_configured(srv, tmp_path):
    port = srv.server_address[1]
    st, _, _ = register(port)
    assert st == 200
    assert (tmp_path / "password.hash").is_file()
    # configured now: / is a 401 login form, not 503, and NOT the site
    st, hdrs, body = get(port, "/")
    assert st == 401
    assert b"password" in body.lower()
    assert b"dummy party" not in body
    # second register refused once configured
    st, _, _ = register(port)
    assert st == 409


def test_register_window_expired(srv, monkeypatch):
    port = srv.server_address[1]
    monkeypatch.setattr(server, "START_TIME", time.time() - server.REGISTER_WINDOW_S - 1)
    st, _, _ = register(port)
    assert st == 409
    # and still unconfigured -> site stays 503
    assert get(port, "/")[0] == 503


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


def test_cookie_tamper_401(srv):
    port = srv.server_address[1]
    assert register(port)[0] == 200
    cookie = cookie_from(login(port)[1])
    sig, _, last = cookie.rpartition(".")
    tampered = cookie[:-1] + ("0" if cookie[-1] != "0" else "1")
    assert tampered != cookie
    st, _, _ = get(port, "/", tampered)
    assert st == 401


def test_cookie_expired_401(srv, tmp_path):
    port = srv.server_address[1]
    assert register(port)[0] == 200
    secret = bytes.fromhex((tmp_path / "secret.key").read_text().strip())
    stale = server.make_token(secret, int(time.time()) - 10)
    st, _, _ = get(port, "/", "session=" + stale)
    assert st == 401


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
    assert st == 200 and b"dummy party" in body
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
    assert not (tmp_path.parent / "evil.txt").exists()
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
    port, _ = _seeded(srv)
    st, _, body = get(port, "/")
    assert st == 401
    assert b"dummy party" not in body
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
    st, _, _ = get(port, "/fest40/")          # no cookie under prefix: still gated
    assert st == 401
    # login under the prefix redirects back into the prefix
    st, hdrs, _ = login(port, PW, path="/fest40/login")
    assert st == 302 and hdrs.get("Location") == "/fest40/"
    # register under the prefix
    st, _, _ = req(port, "POST", "/fest40/register", body="password=zzzzzzzzzzzz")
    assert st == 409  # already configured


# -- port from env (real subprocess, real bind) ------------------------------

def test_port_env_bind():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    env = dict(os.environ, PORT=str(free))
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
    finally:
        proc.terminate()
        proc.wait(timeout=5)
