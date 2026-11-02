"""RSVP tests for fest40 (MC 10286.24). Live HTTP through the same server as
test_gate.py (its fixture/helpers are imported, not duplicated). Fixture
guest data is the fictional "Test Testsson" only — no real guest data here."""
import csv
import io
import json

from test_gate import cookie_from, get, login, register, req, srv, state_of  # noqa: F401

GOOD = {"namn": "Test Testsson", "vuxna": 2, "barn": 1, "meddelande": "Tack ja!"}


def rsvp_post(port, cookie, obj, raw=None):
    body = raw if raw is not None else json.dumps(obj).encode("utf-8")
    h = {"Content-Type": "application/json"}
    if cookie:
        h["Cookie"] = cookie
    return req(port, "POST", "/rsvp", body=body, headers=h)


def rsvp_lines(tmp_path):
    f = state_of(tmp_path) / "rsvp.ndjson"
    return f.read_text("utf-8").splitlines() if f.is_file() else []


# -- POST /rsvp ---------------------------------------------------------------

def test_rsvp_valid_200_and_line_in_state(srv, tmp_path):
    """Read-back, not just status: the appended NDJSON line must exist with
    the exact fields (mutation-red: drops the append -> this goes RED)."""
    port = srv.server_address[1]
    register(port)
    cookie = cookie_from(login(port)[1])
    st, _, body = rsvp_post(port, cookie, GOOD)
    assert st == 200
    assert json.loads(body) == {"ok": True, "mottagen": True}
    lines = rsvp_lines(tmp_path)
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert (row["namn"], row["vuxna"], row["barn"], row["meddelande"]) == \
        ("Test Testsson", 2, 1, "Tack ja!")
    assert row["tid"].endswith("Z")
    # second POST appends a second line, never rewrites the first
    rsvp_post(port, cookie, {**GOOD, "namn": "Test Testsson II"})
    lines = rsvp_lines(tmp_path)
    assert len(lines) == 2 and json.loads(lines[0])["namn"] == "Test Testsson"


def test_rsvp_no_cookie_401(srv):
    """Cookie-auth exactly like /seed: without it, 401 (POST posture)."""
    port = srv.server_address[1]
    register(port)
    st, _, _ = rsvp_post(port, None, GOOD)
    assert st == 401
    assert req(port, "POST", "/seed", body=b"x")[0] == 401   # same pattern


def test_rsvp_bad_bodies_400(srv, tmp_path):
    port = srv.server_address[1]
    register(port)
    cookie = cookie_from(login(port)[1])
    bad = [b"not json", b"[1,2]", b'{"namn":"', b'{"namn":"","vuxna":1,"barn":0}',
           b'{"namn":"x","vuxna":-1,"barn":0}', b'{"namn":"x","vuxna":21,"barn":0}',
           b'{"namn":"x","vuxna":"2","barn":0}', b'{"namn":"x","vuxna":true,"barn":0}',
           b'{"namn":"x","vuxna":1,"barn":1.5}', b'{"namn":"' + b"a" * 121 + b'","vuxna":1,"barn":0}',
           b'{"namn":"x","vuxna":1,"barn":0,"meddelande":"' + b"m" * 1001 + b'"}',
           b'{"namn":"x","vuxna":1}']                      # barn missing -> 400
    for raw in bad:
        st, _, _ = rsvp_post(port, cookie, None, raw=raw)
        assert st == 400, raw[:40]
    assert rsvp_lines(tmp_path) == []                      # nothing persisted


def test_rsvp_too_large_413(srv, tmp_path):
    port = srv.server_address[1]
    register(port)
    cookie = cookie_from(login(port)[1])
    big = json.dumps({**GOOD, "meddelande": "m" * 9000}).encode()
    st, _, _ = rsvp_post(port, cookie, None, raw=big)
    assert st == 413
    assert rsvp_lines(tmp_path) == []


# -- GET /gaster + /gäster ----------------------------------------------------

def test_gaster_unauth_404_byte_identical(srv):
    """Unauthenticated gäster answers the SAME 404 bytes as every other
    non-public path — zero path inventory for the quarantine probe."""
    port = srv.server_address[1]
    register(port)
    _, _, ref = get(port, "/hosting.yaml")               # the existing 404
    for p in ("/gaster", "/g%C3%A4ster", "/fest40/g%C3%A4ster"):
        st, _, body = get(port, p)
        assert st == 404, (p, st)
        assert body == ref                              # byte-identical


def test_gaster_cookie_200_and_escaped(srv):
    """Injected <script> name must render escaped — the raw tag may never
    appear (mutation-red: drop html.escape -> this goes RED)."""
    port = srv.server_address[1]
    register(port)
    cookie = cookie_from(login(port)[1])
    evil = {"namn": "<script>Test Testsson</script>", "vuxna": 1, "barn": 0,
            "meddelande": '& "kvitt" <b>och</b>'}
    assert rsvp_post(port, cookie, evil)[0] == 200
    for p in ("/gaster", "/g%C3%A4ster"):
        st, hdrs, body = get(port, p, cookie)
        assert st == 200 and hdrs.get("Content-Type", "").startswith("text/html")
        text = body.decode("utf-8")
        assert "<script>" not in text and "&lt;script&gt;" in text
        assert "&amp; &quot;kvitt&quot; &lt;b&gt;och&lt;/b&gt;" in text


def test_gaster_empty_message(srv):
    port = srv.server_address[1]
    register(port)
    cookie = cookie_from(login(port)[1])
    st, _, body = get(port, "/gaster", cookie)
    assert st == 200 and "Inga anmälingar än.".encode() in body


def test_gaster_csv_quoting(srv):
    """Comma+quote name must round-trip through the CSV via the csv module."""
    port = srv.server_address[1]
    register(port)
    cookie = cookie_from(login(port)[1])
    nasty = 'Testsson, "Stora", Hönö'
    assert rsvp_post(port, cookie, {**GOOD, "namn": nasty})[0] == 200
    st, hdrs, body = get(port, "/gaster?format=csv", cookie)
    assert st == 200 and hdrs.get("Content-Type", "").startswith("text/csv")
    rows = list(csv.reader(io.StringIO(body.decode("utf-8"))))
    assert rows[0] == ["tid", "namn", "vuxna", "barn", "meddelande"]
    assert rows[1][1] == nasty                          # doubled quotes survived
    assert '"Testsson, ""Stora"", Hönö"'.encode() in body   # quoted on the wire


def test_gaster_prefixed_and_head(srv):
    port = srv.server_address[1]
    register(port)
    cookie = cookie_from(login(port)[1])
    st, _, body = get(port, "/fest40/g%C3%A4ster", cookie)
    assert st == 200 and "Inga anmälingar än.".encode() in body
    st, _, _ = req(port, "HEAD", "/gaster", headers={"Cookie": cookie})
    assert st == 200
