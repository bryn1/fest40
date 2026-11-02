#!/usr/bin/env bash
# fest40 selftest (MC 10286.22): pytest suite + live-curl gate battery.
# One line per leg, PASS/FAIL; exits non-zero on ANY failure. No venv needed.
set -u
cd "$(dirname "$0")/.."
FAILS=0
ok()   { echo "PASS $1"; }
bad()  { echo "FAIL $1"; FAILS=$((FAILS+1)); }

PY=$(command -v python3)
[ -n "$PY" ] || { echo "FAIL python3-missing"; exit 1; }

# ---- leg 1: pytest suite ----------------------------------------------------
if "$PY" -m pytest tests/ -q >/tmp/fest40-selftest-pytest.log 2>&1; then
  ok "pytest ($("$PY" -m pytest tests/ -q 2>/dev/null | grep -oE '[0-9]+ passed' | tail -1))"
else
  bad "pytest (see /tmp/fest40-selftest-pytest.log)"
fi

# ---- leg 2: live server + curl gate battery ----------------------------------
STATE=$(mktemp -d); mkdir -p "$STATE/home"
PORT=$((20000 + RANDOM % 10000))
# HOME exactly as the systemd unit sets it (Environment=HOME=%S/vm106-app-fest40)
env -u XDG_STATE_HOME HOME="$STATE/home" PORT="$PORT" "$PY" server.py >/tmp/fest40-selftest-srv.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$STATE"' EXIT
for _ in $(seq 50); do
  curl -s -o /dev/null "http://127.0.0.1:$PORT/robots.txt" && break; sleep 0.2
done
B="http://127.0.0.1:$PORT"
PW="selftest-kana-2026"; PW2="selftest-nyckel-2026"
MARKER="PARTY-MARKER-9f2c"
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
nbytes() { curl -s "$@" | wc -c | tr -d ' '; }

# the product path ALWAYS answers 200 with a body over the probe floor
# (staging.py MIN_BYTES_FLOOR=256); site bytes always need the cookie.
[ "$(code $B/)" = "200" ]                            && ok "unconfigured-/->200"        || bad "unconfigured-/->200"
curl -s $B/ | grep -q "under upps"                  && ok "unconfigured-/->setup-page" || bad "unconfigured-/->setup-page"
[ "$(nbytes $B/)" -ge 256 ]                          && ok "setup-page-over-floor"      || bad "setup-page-over-floor"
[ "$(code $B/_assets/x)" = "404" ]                   && ok "unconfigured-asset->404"    || bad "unconfigured-asset->404"
QF=0
for q in /hosting.yaml /tests/test_gate.py /fest40/hosting.yaml /fest40/server.py; do
  [ "$(code $B$q)" = "404" ] || QF=1
done
[ "$QF" = "0" ]                                    && ok "quarantine-paths->404"      || bad "quarantine-paths->404"
[ "$(code -X POST -d "password=$PW" $B/register)" = "200" ] && ok "register->200"     || bad "register->200"
[ "$(code -X POST -d "password=$PW" $B/register)" = "409" ] && ok "register-again->409" || bad "register-again->409"
[ "$(code $B/)" = "200" ]                            && ok "configured-/->200"          || bad "configured-/->200"
curl -s $B/ | grep -q "Lösenord"                    && ok "configured-/->login-page"   || bad "configured-/->login-page"
[ "$(nbytes $B/)" -ge 256 ]                          && ok "login-page-over-floor"      || bad "login-page-over-floor"
[ "$(code -X POST -d "password=wrongpassword" $B/login)" = "401" ] && ok "login-wrong->401" || bad "login-wrong->401"
SC=$(curl -s -D - -o /dev/null -X POST -d "password=$PW" $B/login | tr -d '\r' | grep -i '^set-cookie:' | sed 's/.*session=//;s/;.*//')
[ -n "$SC" ]                                       && ok "login-right->set-cookie"    || bad "login-right->set-cookie"
TAMPER="session=$(echo "$SC" | sed 's/.$/X/')"
[ "$(code -H "Cookie: $TAMPER" $B/_assets/whatever.txt)" = "404" ] && ok "cookie-tamper-asset->404" || bad "cookie-tamper-asset->404"
[ "$(code -X POST --data-binary @/dev/null $B/seed)" = "401" ] && ok "seed-nocookie->401" || bad "seed-nocookie->401"

Z="$STATE/dummy.zip"
"$PY" - "$Z" "$MARKER" <<'EOF'
import io, sys, zipfile
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("index.html", f"<h1>dummy party {sys.argv[2]}</h1>")
    z.writestr("_assets/dummy.txt", "dummy asset bytes")
open(sys.argv[1], "wb").write(buf.getvalue())
EOF
EVIL="$STATE/evil.zip"
"$PY" - "$EVIL" <<'EOF'
import io, sys, zipfile
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("../evil.txt", "pwned")
open(sys.argv[1], "wb").write(buf.getvalue())
EOF
[ "$(code -X POST --data-binary @$EVIL -H "Cookie: session=$SC" $B/seed)" = "400" ] && ok "seed-zipslip->400" || bad "seed-zipslip->400"
[ ! -e "$STATE/home/evil.txt" ]                    && ok "zipslip-no-write"           || bad "zipslip-no-write"
[ "$(code -X POST --data-binary @$Z -H "Cookie: session=$SC" $B/seed)" = "200" ] && ok "seed-cookie->200" || bad "seed-cookie->200"
BODY=$(curl -s -H "Cookie: session=$SC" $B/)
echo "$BODY" | grep -q "$MARKER"                   && ok "served-index-content"       || bad "served-index-content"
[ "$(curl -s $B/ | grep -c "$MARKER")" = "0" ]     && ok "no-cookie-no-site-bytes"    || bad "no-cookie-no-site-bytes"
[ "$(code $B/)" = "200" ]                          && ok "no-cookie-/->200-gate"      || bad "no-cookie-/->200-gate"
[ "$(curl -s -H "Cookie: session=$SC" $B/_assets/dummy.txt)" = "dummy asset bytes" ] && ok "served-asset" || bad "served-asset"
[ "$(code -H "Cookie: session=$SC" $B/_assets/../../etc/passwd)" = "404" ] && ok "asset-traversal->404" || bad "asset-traversal->404"
curl -sI $B/ | grep -qi 'x-robots-tag: noindex,nosnippet' && ok "noindex-header" || bad "noindex-header"
curl -s $B/robots.txt | grep -q 'Disallow: /'      && ok "robots-disallow"            || bad "robots-disallow"
# prefix both ways
[ "$(code -H "Cookie: session=$SC" $B/fest40/)" = "200" ] && ok "prefix-index->200" || bad "prefix-index->200"
[ "$(code $B/fest40/)" = "200" ] && [ "$(curl -s $B/fest40/ | grep -c "$MARKER")" = "0" ] \
  && ok "prefix-noauth-200-gate-no-site-bytes" || bad "prefix-noauth-200-gate-no-site-bytes"
[ "$(code $B/fest40/_assets/dummy.txt)" = "404" ] && ok "prefix-noauth-asset->404" || bad "prefix-noauth-asset->404"
LOC=$(curl -s -D - -o /dev/null -X POST -d "password=$PW" $B/fest40/login | tr -d '\r' | grep -i '^location:' | sed 's/.*: //')
[ "$LOC" = "/fest40/" ]                            && ok "prefix-login-redirect"     || bad "prefix-login-redirect"
curl -s $B/fest40/ | grep -q 'action="/fest40/login"'  && ok "emit-action-prefixed"     || bad "emit-action-prefixed"
curl -s $B/ | grep -q 'action="/fest40/login"'         && ok "emit-action-bare"         || bad "emit-action-bare"
# rotate: old pw must die, new pw must work
[ "$(code -X POST -d "password=$PW2" -H "Cookie: session=$SC" $B/rotate)" = "200" ] && ok "rotate->200" || bad "rotate->200"
[ "$(code -X POST -d "password=$PW" $B/login)" = "401" ] && ok "rotate-oldpw->401" || bad "rotate-oldpw->401"
[ "$(code -X POST -d "password=$PW2" $B/login)" = "302" ] && ok "rotate-newpw->302" || bad "rotate-newpw->302"

# ---- rsvp + gäster (MC 10286.24) ---------------------------------------------
[ "$(curl -s -H "Cookie: session=$SC" $B/gaster | grep -c "Inga anmälingar än.")" = "1" ] \
  && ok "gaster-empty-text" || bad "gaster-empty-text"
[ "$(code $B/gaster)" = "404" ] && [ "$(curl -s $B/gaster)" = "$(curl -s $B/hosting.yaml)" ] \
  && ok "gaster-404-unauth" || bad "gaster-404-unauth"
[ "$(code -X POST -H "Content-Type: application/json" -d '{"namn":"Test Testsson","vuxna":2,"barn":1,"meddelande":"Tack ja"}' $B/rsvp)" = "401" ] \
  && ok "rsvp-nocookie->401" || bad "rsvp-nocookie->401"
[ "$(code -X POST -H "Content-Type: application/json" -d 'not json' -H "Cookie: session=$SC" $B/rsvp)" = "400" ] \
  && ok "rsvp-badjson->400" || bad "rsvp-badjson->400"
[ "$(code -X POST -H "Content-Type: application/json" -d '{"namn":"Test Testsson","vuxna":2,"barn":1,"meddelande":"Tack ja"}' -H "Cookie: session=$SC" $B/rsvp)" = "200" ] \
  && grep -q '"namn": "Test Testsson"' "$STATE/home/fest40-state/rsvp.ndjson" \
  && ok "rsvp-append" || bad "rsvp-append"
[ "$(code -X POST -H "Content-Type: application/json" -d '{"namn":"<script>Test Testsson</script>","vuxna":1,"barn":0,"meddelande":""}' -H "Cookie: session=$SC" $B/rsvp)" = "200" ] \
  && ok "rsvp-escape-post->200" || bad "rsvp-escape-post->200"
GB=$(curl -s -H "Cookie: session=$SC" "$B/g%C3%A4ster")
echo "$GB" | grep -q '&lt;script&gt;' && ! echo "$GB" | grep -q '<script>' \
  && ok "gaster-escape" || bad "gaster-escape"
[ "$(code -X POST -H "Content-Type: application/json" -d '{"namn":"Testsson, \"Stora\"","vuxna":1,"barn":0,"meddelande":""}' -H "Cookie: session=$SC" $B/rsvp)" = "200" ] \
  && curl -s -H "Cookie: session=$SC" "$B/gaster?format=csv" | grep -qF '"Testsson, ""Stora"""' \
  && ok "gaster-csv-quoting" || bad "gaster-csv-quoting"

# ---- verdict ----------------------------------------------------------------
if [ "$FAILS" -gt 0 ]; then echo "SELFTEST FAIL ($FAILS legs)"; exit 1; fi
echo "SELFTEST PASS"; exit 0
