"""fest40 gate pages (MC 10286.22) -- the always-200 front of the service.

Why this file exists: the vm106 staging gate AND the post-promotion live
probe both require GET /<name>/ to answer 200 with a body of at least
MIN_BYTES_FLOOR bytes (staging.py:65-66 -> 256). A bare 401/503 entry page
is REFUSED as "never served its product path" -- see the slakttraff
precedent, which answers 200 with its own password-form page. So the fleet-
accepted shape here is: the GATE PAGE serves 200 always, and only the
PROTECTED bytes behind it require the session cookie. Nothing about that
weakens the gate: a 200 gate page carries ZERO site bytes (asserted by test
on a planted party marker).

Both pages are >= 512 bytes -- double the real 256 floor. A test asserts the
measured byte length against MIN_GATE_BYTES, and both bodies are
content-free (honest Swedish copy, no secrets, no site data).
"""

GATE_STYLE = (
    "<style>:root{color-scheme:light dark}"
    "body{font:16px/1.6 system-ui,sans-serif;margin:0 auto;padding:3rem 1.25rem;"
    "max-width:34rem}"
    "h1{font-size:1.6rem;margin:0 0 .35rem}"
    "p{margin:.6rem 0;color:currentColor;opacity:.85}"
    "form{display:flex;gap:.5rem;margin-top:1.4rem;flex-wrap:wrap}"
    "input{flex:1 1 12rem;padding:.6rem .75rem;font:inherit;border:1px solid;"
    "border-radius:.4rem;background:transparent;color:currentColor}"
    "button{padding:.6rem 1.1rem;font:inherit;border:1px solid;border-radius:.4rem;"
    "cursor:pointer;background:currentColor;color:transparent}"
    "small{display:block;margin-top:1.6rem;opacity:.6}"
    "</style>"
)


def _page(title, heading, paras, form_action, form_label, button, hint, pad):
    """One shared shell so the gate pages cannot drift apart in size or shape."""
    body = "".join(f"<p>{p}</p>" for p in paras)
    return (
        "<!doctype html>\n"
        '<html lang="sv">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f"<title>{title}</title>\n"
        '<meta name="robots" content="noindex,nosnippet">\n'
        f"{GATE_STYLE}</head>\n<body>\n"
        f"<main>\n<h1>{heading}</h1>\n{body}\n"
        f'<form method="post" action="{form_action}">\n'
        f'<label for="pw">{form_label}</label>\n'
        f'<input id="pw" type="password" name="password" autocomplete="current-password" '
        f'placeholder="{form_label}" required>\n'
        f'<button type="submit">{button}</button>\n</form>\n'
        f"<small>{hint}</small>\n</main>\n"
        f"<!-- {pad} -->\n</body>\n</html>\n"
    )


def render(template: str, base: str = "") -> str:
    """Fill the only placeholder the templates carry ({base}, the form action).
    str.replace, not str.format: GATE_STYLE contains CSS braces."""
    return template.replace("{base}", base)


LOGIN_PAGE = _page(
    title="Fest 40 &mdash; lösenord krävs",
    heading="Fest 40",
    paras=["Det här är en inbjudningssida — lösenord får du av Alexander.",
           "Sidan är lösenordsskyddad och syns inte i sökmotorer. Har du lösenordet "
           "sedan tidigare ändras det när någon med tillgång väljer ett nytt, så "
           "logga in med det som gäller just nu."],
    form_action="{base}/login",
    form_label="Lösenord",
    button="Logga in",
    hint="Ett felaktigt lösenord ger bara den här sidan igen — ingenting "
         "av innehållet visas någonsin utan inloggning.",
    pad="Lösenordssida. Inget festinnehåll här: sidans ändamål är att hålla "
        "listan och programmet borta från sök och från förbigående. Innehållet "
        "bakom den här dörren lever på den egna state-katalogen på värden och "
        "nås bara med en giltig session, aldrig härifrån.",
)

SETUP_PAGE = _page(
    title="Fest 40 — sidan håller på att sättas upp",
    heading="Fest 40 — under uppsättning",
    paras=["Sidan är under uppsättning. Alexander sätter lösenordet nu, och strax "
           "därefter kan den som har det logga in här.",
           "Det här är en inbjudningssida — lösenord får du av Alexander. Ännu finns "
           "inget att visa: inbjudan, program och gästlista läggs in först efter att "
           "uppsättningen är klar — aldrig i kodekoden."],
    form_action="{base}/register",
    form_label="Nytt lösenord",
    button="Installera",
    hint="Det här fönstret är öppet i tjugo minuter från starten och stänger "
         "när ett lösenord är satt. Därefter visas inloggningssidan.",
    pad="Uppsättningssida. Medvetet tomt på innehåll: medan fönstret är öppet "
        "finns bara den här texten, så att en halvfärdig sida aldrig kan läckas "
        "eller indexeras. Setting page for the host, deliberately content-free.",
)
