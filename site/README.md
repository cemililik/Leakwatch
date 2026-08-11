# Leakwatch website

The marketing site and documentation portal for Leakwatch, published to GitHub
Pages. It is a **dependency-free static site** — plain HTML, CSS, and vanilla
JavaScript, no runtime framework and no client-side build step. The visual
concept is **"Redacted"**: a classified-dossier aesthetic with redaction bars,
scan-line reveals, and evidence stamps. Dark-only by design.

## Structure

```
site/
├── index.html          Landing page (Redacted hero with a scan-reveal document)
├── docs.html           Documentation portal (sidebar + hash-routed content)
├── contact.html        Contact page (Formspree-backed form + GitHub channels)
├── playground.html     In-browser scanner — paste text, real detection runs client-side
├── css/style.css       Design system (the Redacted dossier theme)
├── js/
│   ├── translations.js UI strings for EN / TR (marketing chrome + docs shell)
│   ├── i18n.js         Language detection, switching, persistence
│   ├── main.js         Mobile nav, copy buttons, hero scan animation, contact form
│   ├── docs.js         Docs portal controller (nav, routing, search, Mermaid)
│   ├── scanner.js      Playground engine (runs window.LW_DETECTORS client-side)
│   ├── detectors.js    GENERATED — detector patterns extracted from internal/detector
│   └── manuals/        GENERATED — compiled manual content (do not edit by hand)
│       ├── _index.js   Navigation tree (from docs/user-manuals/_meta.yaml)
│       ├── en.js       English manual pages, rendered to HTML
│       └── tr.js       Turkish manual pages, rendered to HTML
├── assets/             favicon.svg, og.svg, fonts/
└── .nojekyll           Disable Jekyll (so files like _index.js are served)
```

## Internationalization

The site is bilingual (English + Turkish) with **client-side switching**: a
single set of URLs, with the language toggled in the navbar and remembered in
`localStorage`. UI strings live in `js/translations.js`; manual content is
compiled per language into `js/manuals/<lang>.js`.

## Playground (in-browser scanner)

`playground.html` + `js/scanner.js` let visitors paste a file and run Leakwatch's
**real detection patterns entirely client-side** — nothing is uploaded. It is a
preview: regex + entropy detection only. The CLI adds live verification, Git
history, containers, cloud/Slack, and the entropy/custom-rule detectors.

The patterns are **not hand-maintained**. `tools/site-build` parses
`internal/detector/**` with `go/ast` and emits `js/detectors.js`
(`window.LW_DETECTORS`) — each detector's ID, severity, keywords, and regex
pattern(s). Go uses RE2 (no look-around/back-references), a subset of JS regex,
so patterns port over; a small normalization step handles Go-only tokens
(leading inline flags → JS flags, `(?P<name>)` → `(?<name>)`, Go anchors). This
keeps the browser scanner in sync with the engine automatically. Currently
**62 of 63** detectors run in the browser (the entropy-gated generic detector
and runtime custom rules stay CLI-only). Regenerate together with the manuals:

```bash
cd tools/site-build && go run .
```

## Contact form (Formspree)

`contact.html` posts to [Formspree](https://formspree.io). Before it works you
must create a free form and paste its endpoint ID:

1. Create a form at https://formspree.io and copy your form ID.
2. In `contact.html`, replace `YOUR_FORM_ID` in the form's `action`:
   `https://formspree.io/f/YOUR_FORM_ID` → `https://formspree.io/f/abcdwxyz`.

The form submits via `fetch` (inline success/error) and degrades to a normal
POST without JavaScript. It includes a honeypot field and never asks for secrets.

## Editing the documentation

Current product behavior is authored in the English Markdown manual under
[`../docs/user-manuals/`](../docs/user-manuals/):

```
docs/user-manuals/
├── _meta.yaml                       navigation: sections, page order, titles
├── en/<section>/<page>.md           authoritative English source
└── tr/<section>/<page>.md           reviewed Turkish translation
```

Update the English page first, then its Turkish counterpart in the same change.
Files under `js/manuals/` are generated publication artifacts and must never be
edited by hand. Supplemental long-form guides under `docs/guides/` may add
operational depth, but they defer product contracts to the user manual.

Each page has YAML front matter (`title`, `description`), GFM Markdown, fenced
code blocks, optional `:::tip` / `:::note` / `:::warn` / `:::danger` callouts,
and ` ```mermaid ` diagrams. Cross-links use the hash-router form
`[Label](#/<section>/<page>)`.

After editing Markdown (or `_meta.yaml`), regenerate the compiled bags:

```bash
cd tools/site-build
go run .            # add -strict to fail on any missing translation
```

## Fonts

Web fonts (JetBrains Mono + Space Grotesk) are **self-hosted** under
`assets/fonts/` and declared in `css/fonts.css` — no third-party requests, no
subresource-integrity concerns, and the site works offline. Only the `latin`
and `latin-ext` subsets are bundled (latin-ext covers Turkish: ş, ğ, ı, İ, …).

To regenerate after changing weights, run this from the repo root (Python 3):

```bash
python3 - <<'PY'
import re, os, urllib.request
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"}
url = "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&family=Space+Grotesk:wght@500;600;700&display=swap"
css = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30).read().decode()
os.makedirs("site/assets/fonts", exist_ok=True); faces=[]
for sub, block in re.findall(r"/\*\s*([\w-]+)\s*\*/\s*(@font-face\s*\{[^}]+\})", css):
    if sub not in ("latin", "latin-ext"): continue
    fam=re.search(r"font-family:\s*'([^']+)'",block)[1]; w=re.search(r"font-weight:\s*(\d+)",block)[1]
    u=re.search(r"src:\s*url\((https://[^)]+\.woff2)\)",block)[1]; ur=re.search(r"unicode-range:\s*([^;]+);",block)[1]
    fn=f"{fam.lower().replace(' ','-')}-{w}-{sub}.woff2"
    open(f"site/assets/fonts/{fn}","wb").write(urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=30).read())
    faces.append(f"@font-face{{font-family:'{fam}';font-style:normal;font-weight:{w};font-display:swap;src:url(../assets/fonts/{fn}) format('woff2');unicode-range:{ur};}}")
open("site/css/fonts.css","w").write("/* Self-hosted web fonts (latin + latin-ext). */\n"+"\n".join(faces)+"\n")
PY
```

## Local preview

Serve the folder over HTTP (the docs portal loads JS files, so `file://` will
not work):

```bash
cd site
python3 -m http.server 8080
# then open http://localhost:8080/
```

## Deployment

Pushes to `main` that touch `site/`, `docs/user-manuals/`, or
`tools/site-build/` trigger
[`.github/workflows/site-deploy.yml`](../.github/workflows/site-deploy.yml),
which recompiles the manuals and deploys `site/` to GitHub Pages. Enable it once
under **Settings → Pages → Build and deployment → Source: GitHub Actions**.
