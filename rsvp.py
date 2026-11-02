"""fest40 — RSVP persistence (MC 10286.24). POST /rsvp appends one NDJSON
line per guest to <state>/rsvp.ndjson; GET /gaster (also spelled /gäster,
raw or percent-encoded) lists them as HTML, or text/csv with ?format=csv.
Auth lives in server.py's wiring (401 POST / 404 GET, exactly like /seed);
every function here runs BEHIND that gate. All HTML output is escaped and
the body is never logged nor echoed into a reason. Stdlib only."""
import csv
import html
import io
import json
import time
from http import HTTPStatus
from urllib.parse import parse_qs, unquote

RSVP_NAME = "rsvp.ndjson"
RSVP_MAX_BODY = 8 * 1024
NAMN_MAX = 120
MEDDELANDE_MAX = 1000
ANTAL_MAX = 20
GASTER_PATHS = ("/gaster", "/gäster")
CSV_FIELDS = ("tid", "namn", "vuxna", "barn", "meddelande")


def validate(body):
    """Valid POST body -> (row, None); invalid -> (None, (status, swedish reason))."""
    if len(body) > RSVP_MAX_BODY:
        return None, (HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "anmälan är för stor (max 8 kB)\n")
    if not body:
        return None, (HTTPStatus.BAD_REQUEST, "tom anmälan\n")
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, (HTTPStatus.BAD_REQUEST, "anmälan måste vara giltig JSON\n")
    if not isinstance(data, dict):
        return None, (HTTPStatus.BAD_REQUEST, "anmälan måste vara ett JSON-objekt\n")
    namn = data.get("namn")
    if not isinstance(namn, str) or not 1 <= len(namn.strip()) <= NAMN_MAX:
        return None, (HTTPStatus.BAD_REQUEST, f"namn saknas eller måste vara 1–{NAMN_MAX} tecken\n")
    vuxna, barn = data.get("vuxna"), data.get("barn")
    for name, val in (("vuxna", vuxna), ("barn", barn)):
        if isinstance(val, bool) or not isinstance(val, int) or not 0 <= val <= ANTAL_MAX:
            return None, (HTTPStatus.BAD_REQUEST, f"{name} måste vara ett heltal 0–{ANTAL_MAX}\n")
    meddelande = data.get("meddelande", "")
    if not isinstance(meddelande, str) or len(meddelande) > MEDDELANDE_MAX:
        return None, (HTTPStatus.BAD_REQUEST, f"meddelande måste vara text, max {MEDDELANDE_MAX} tecken\n")
    row = {"tid": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "namn": namn.strip(), "vuxna": vuxna, "barn": barn,
           "meddelande": meddelande}
    return row, None


def append(base, row):
    """One NDJSON line, O_APPEND single write (ThreadingHTTPServer-safe)."""
    with open(base / RSVP_NAME, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_rows(base):
    """Stored rows in order; an unparseable (torn) line is skipped, never fatal."""
    f = base / RSVP_NAME
    if not f.is_file():
        return []
    rows = []
    for line in f.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def render_html(rows):
    out = io.StringIO()
    out.write('<!doctype html><html lang="sv"><head><meta charset="utf-8">'
              '<meta name="robots" content="noindex,nosnippet">'
              "<title>Gäster</title></head><body><h1>Gäster</h1>")
    if not rows:
        out.write("<p>Inga anmälingar än.</p>")
    else:
        out.write(f"<p>{len(rows)} anmäling(ar).</p><ul>")
        for r in rows:
            cells = " | ".join(html.escape(str(r.get(k, ""))) for k in CSV_FIELDS)
            out.write(f"<li>{cells}</li>")
        out.write("</ul>")
    out.write("</body></html>")
    return out.getvalue()


def render_csv(rows):
    buf = io.StringIO()
    writer = csv.writer(buf)          # QUOTE_MINIMAL: quotes/commas/newlines doubled
    writer.writerow(CSV_FIELDS)
    for r in rows:
        writer.writerow([r.get(k, "") for k in CSV_FIELDS])
    return buf.getvalue()


def handle_get(h, path, query, base):
    """GET /gaster|/gäster behind the session gate; True = response sent."""
    if path not in GASTER_PATHS and unquote(path) not in GASTER_PATHS:
        return False
    rows = read_rows(base)
    if parse_qs(query).get("format", [""])[0] == "csv":
        h._send(200, render_csv(rows), "text/csv; charset=utf-8")
    else:
        h._send(200, render_html(rows), "text/html; charset=utf-8")
    return True


def handle_post(h, body, base):
    """POST /rsvp behind the session gate: validate, append, answer."""
    row, err = validate(body)
    if err is not None:
        h._send(err[0], err[1])
        return
    append(base, row)
    h._send(200, '{"ok":true,"mottagen":true}\n', "application/json; charset=utf-8")
