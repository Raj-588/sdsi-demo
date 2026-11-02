"""Render a Markdown doc as a self-contained HTML page in the style of the spec page.

    pip install markdown
    python scripts/md_to_html.py architecture.md            # -> architecture.html

Re-run it whenever the Markdown changes; the .md stays the source of truth.

- The first H1 and the blockquote after it become the masthead.
- Every H2 becomes a section, with a sticky contents list built from them.
- Images are embedded as data: URIs, so the file works on its own.
- Mermaid fences render with mermaid.js (pinned, from jsDelivr); offline, their source stays readable.
- Box-drawing diagrams keep a tight line height so their lines connect.
- Links to a .md that has an .html sibling point to the .html.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import html
import mimetypes
import re
from pathlib import Path

import markdown

MERMAID_JS = "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"
BOX_DRAWING = re.compile(r"[─-╿▲-▼]")

CSS = r"""
/* Layout: a spec sheet. Sticky contents on the left at desktop width, one reading column on the right;
   tables, code and diagrams scroll inside their own boxes, never the page. Same tokens as the spec page. */
:root {
  --bg: #F4F6FA; --surface: #FFFFFF; --ink: #0E1A33; --muted: #55627A; --line: #D9E0EB;
  --accent: #1C56D4; --accent-soft: #E7EEFC;
  --ok: #12784A; --ok-soft: #E2F3E9; --warn: #9C5600; --warn-soft: #FBEFDD; --bad: #BD2D26; --bad-soft: #FBE6E4;
  --code-bg: #0E1A31; --code-fg: #DCE5F7; --code-key: #91B6FF; --code-str: #A4E3BC; --code-lit: #F6C27E; --code-dim: #8494B2;
  --font-display: "Archivo", "Helvetica Neue", Arial, sans-serif;
  --font-body: "Source Sans 3", -apple-system, "Segoe UI", system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  color-scheme: light;
  padding-top: env(safe-area-inset-top, 0px);
  padding-bottom: env(safe-area-inset-bottom, 0px);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0A1222; --surface: #101B31; --ink: #E5EBF6; --muted: #98A6C0; --line: #233253;
    --accent: #7AA8FF; --accent-soft: #16274B;
    --ok: #4CCB8E; --ok-soft: #0F2E22; --warn: #F2AB4E; --warn-soft: #33240E; --bad: #FF7B71; --bad-soft: #3A1714;
    --code-bg: #060D1B; --code-fg: #D8E2F6; --code-key: #8DB3FF; --code-str: #9BDDB4; --code-lit: #F3BE78; --code-dim: #72819F;
    color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --bg: #0A1222; --surface: #101B31; --ink: #E5EBF6; --muted: #98A6C0; --line: #233253;
  --accent: #7AA8FF; --accent-soft: #16274B;
  --ok: #4CCB8E; --ok-soft: #0F2E22; --warn: #F2AB4E; --warn-soft: #33240E; --bad: #FF7B71; --bad-soft: #3A1714;
  --code-bg: #060D1B; --code-fg: #D8E2F6; --code-key: #8DB3FF; --code-str: #9BDDB4; --code-lit: #F3BE78; --code-dim: #72819F;
  color-scheme: dark;
}
*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
@media (prefers-reduced-motion: no-preference) { html { scroll-behavior: smooth; } }
body { margin: 0; background: var(--bg); color: var(--ink); font: 400 1.0625rem/1.62 var(--font-body); }
img { max-width: 100%; }
[hidden] { display: none !important; }
a { color: var(--accent); text-underline-offset: 3px; }
a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
.wrap { max-width: 1240px; margin: 0 auto;
  padding-left: max(16px, env(safe-area-inset-left, 0px)); padding-right: max(16px, env(safe-area-inset-right, 0px)); }

.masthead { background: var(--surface); border-bottom: 1px solid var(--line); }
.masthead .wrap { padding-block: clamp(28px, 5vw, 60px) clamp(24px, 4vw, 44px); display: grid; gap: 16px; }
.kicker { display: flex; flex-wrap: wrap; gap: 6px 18px; font: 600 .74rem/1.3 var(--font-mono); letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
h1 { font-family: var(--font-display); font-stretch: 112%; font-weight: 800; font-size: clamp(2.1rem, 1.3rem + 3.4vw, 3.4rem);
  line-height: 1.02; letter-spacing: -.012em; margin: 0; max-width: 20ch; text-wrap: balance; }
.lede { margin: 0; font-size: clamp(1.05rem, 1rem + .35vw, 1.25rem); line-height: 1.5; color: var(--muted); max-width: 64ch; }
.lede p { margin: 0 0 6px; }
.meta { font-size: .92rem; color: var(--muted); margin: 0; }

.layout { display: grid; gap: 32px; padding-block: 32px 80px; }
@media (min-width: 1080px) { .layout { grid-template-columns: 230px minmax(0, 1fr); gap: 52px; } }
main { min-width: 0; max-width: 940px; }
.toc { font-size: .93rem; }
.toc-title { font: 600 .72rem/1 var(--font-mono); letter-spacing: .1em; text-transform: uppercase; color: var(--muted); margin: 0 0 10px; }
.toc ol { list-style: none; margin: 0; padding: 0; display: grid; gap: 1px; }
.toc a { display: grid; grid-template-columns: 2.7em 1fr; gap: 4px; padding: 5px 10px; border-radius: 8px; color: var(--ink); text-decoration: none; line-height: 1.35; }
.toc a span { font: 600 .76rem/1.75 var(--font-mono); color: var(--muted); }
.toc a:hover { background: var(--surface); }
.toc a[aria-current="true"] { background: var(--accent-soft); color: var(--accent); }
.toc a[aria-current="true"] span { color: var(--accent); }
@media (min-width: 1080px) {
  .toc { position: sticky; top: calc(env(safe-area-inset-top, 0px) + 24px); align-self: start; max-height: calc(100vh - 48px); overflow: auto; }
}
@media (max-width: 1079px) { .toc ol { grid-template-columns: repeat(auto-fill, minmax(min(100%, 240px), 1fr)); } }

section { border-top: 1px solid var(--line); padding-block: 26px 30px; }
section:first-child { border-top: 0; padding-top: 0; }
h2 { font-family: var(--font-display); font-stretch: 108%; font-weight: 750; font-size: clamp(1.45rem, 1.2rem + 1vw, 1.85rem);
  line-height: 1.15; margin: 0 0 14px; text-wrap: balance; display: flex; gap: .55em; align-items: baseline; scroll-margin-top: 16px; }
h2 .num { font: 600 .9rem/1 var(--font-mono); color: var(--accent); flex: none; }
h3 { font-family: var(--font-display); font-weight: 700; font-size: 1.15rem; line-height: 1.3; margin: 26px 0 8px; text-wrap: balance; }
h4 { font-weight: 700; font-size: 1rem; margin: 18px 0 6px; }
p, li { max-width: 72ch; }
p { margin: 10px 0; }
ul, ol { padding-left: 1.25em; margin: 10px 0; }
li { margin: 5px 0; }
li::marker { color: var(--muted); }
strong { font-weight: 700; }
blockquote { margin: 14px 0; padding: 12px 16px; background: var(--accent-soft); border-radius: 12px; }
blockquote p { margin: 4px 0; }

code { font-family: var(--font-mono); font-size: .86em; background: var(--accent-soft); color: var(--ink); padding: .08em .36em; border-radius: 5px; overflow-wrap: anywhere; }
td code { overflow-wrap: break-word; }
pre { margin: 16px 0; background: var(--code-bg); color: var(--code-fg); padding: 16px 18px; border-radius: 12px; overflow-x: auto;
  font: 400 .82rem/1.62 var(--font-mono); tab-size: 2; }
pre code { background: none; color: inherit; padding: 0; font-size: inherit; overflow-wrap: normal; }
pre.diagram { background: var(--surface); color: var(--ink); border: 1px solid var(--line); font-size: .76rem; line-height: 1.24; }
.k { color: var(--code-key); } .s { color: var(--code-str); } .l { color: var(--code-lit); } .c { color: var(--code-dim); }
pre.diagram .c { color: var(--muted); }
.mermaid-box { margin: 16px 0; padding: 16px; background: var(--surface); border: 1px solid var(--line); border-radius: 12px; overflow-x: auto; }
pre.mermaid { margin: 0; padding: 0; background: none; color: var(--muted); border-radius: 0; text-align: center; font-size: .78rem; line-height: 1.5; }

.table-wrap { overflow-x: auto; margin: 16px 0; border: 1px solid var(--line); border-radius: 12px; background: var(--surface); }
table { border-collapse: collapse; width: 100%; font-size: .94rem; line-height: 1.5; }
th, td { text-align: left; vertical-align: top; padding: 10px 14px; border-bottom: 1px solid var(--line); }
th { font: 600 .7rem/1.3 var(--font-mono); letter-spacing: .07em; text-transform: uppercase; color: var(--muted); background: var(--bg); }
tbody tr:last-child td { border-bottom: 0; }
td:first-child { font-weight: 600; }
.wide-table table { min-width: 680px; }
figure.img { margin: 16px 0; }
figure.img img { display: block; border-radius: 12px; border: 1px solid var(--line); background: var(--surface); }
figure.img figcaption { font-size: .88rem; color: var(--muted); margin-top: 6px; }
footer.wrap { padding-block: 0 48px; color: var(--muted); font-size: .88rem; }
"""

SCRIPT = r"""
(() => {
  const esc = s => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  for (const code of document.querySelectorAll("pre code.language-json")) {
    code.innerHTML = esc(code.textContent).replace(
      /("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|(-?\b\d+(?:\.\d+)?\b)/g,
      (m, str, colon, lit, num) => str
        ? (colon ? `<span class="k">${str}</span>${colon}` : `<span class="s">${str}</span>`)
        : `<span class="l">${lit || num}</span>`);
  }
  for (const code of document.querySelectorAll("pre code:not(.language-json)")) {
    code.innerHTML = code.textContent.split("\n").map(line => {
      const m = line.match(/(^|\s)#\s/);
      if (!m) return esc(line);
      const i = m.index + m[1].length;
      return esc(line.slice(0, i)) + `<span class="c">${esc(line.slice(i))}</span>`;
    }).join("\n");
  }
  if (window.mermaid) {
    const css = getComputedStyle(document.documentElement);
    const v = name => css.getPropertyValue(name).trim();
    window.mermaid.initialize({
      startOnLoad: false, theme: "base", securityLevel: "strict", fontFamily: v("--font-body"),
      flowchart: { useMaxWidth: false }, sequence: { useMaxWidth: false },   // natural size; wide ones scroll in their box
      themeVariables: {
        background: v("--surface"), primaryColor: v("--accent-soft"), primaryTextColor: v("--ink"),
        primaryBorderColor: v("--accent"), lineColor: v("--muted"), textColor: v("--ink"),
        secondaryColor: v("--ok-soft"), tertiaryColor: v("--bg"), clusterBkg: v("--bg"), clusterBorder: v("--line"),
        edgeLabelBackground: v("--surface"), noteBkgColor: v("--warn-soft"), noteTextColor: v("--ink"),
        actorBkg: v("--accent-soft"), actorBorder: v("--accent"), actorTextColor: v("--ink"), signalColor: v("--muted"),
        signalTextColor: v("--ink"), labelBoxBkgColor: v("--surface"), labelTextColor: v("--ink"), fontSize: "14px"
      }
    });
    window.mermaid.run({ querySelector: "pre.mermaid" }).catch(() => {});
  }
  const links = new Map([...document.querySelectorAll(".toc a")].map(a => [a.getAttribute("href").slice(1), a]));
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver(entries => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        const id = e.target.querySelector("h2")?.id;
        links.forEach(a => a.removeAttribute("aria-current"));
        links.get(id)?.setAttribute("aria-current", "true");
      }
    }, { rootMargin: "-15% 0px -70% 0px" });
    document.querySelectorAll("main section").forEach(s => io.observe(s));
  }
})();
"""

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{title}</title>
<meta name="claude:viewport-fit-sides" content="cover">
<meta name="description" content="{description}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@75..125,500..800&family=JetBrains+Mono:wght@400;600&family=Source+Sans+3:ital,wght@0,400;0,600;0,700;1,400&display=swap">
<style>{css}</style>
</head>
<body>
<header class="masthead">
  <div class="wrap">
    <div class="kicker">{kicker}</div>
    <h1>{heading}</h1>
    <div class="lede">{lede}</div>
    <p class="meta">{meta}</p>
  </div>
</header>
<div class="wrap layout">
  <nav class="toc" aria-label="Sections">
    <p class="toc-title">Contents</p>
    <ol>
{toc}
    </ol>
  </nav>
  <main class="doc">
{sections}
  </main>
</div>
<footer class="wrap"><p>{footer}</p></footer>
<script src="{mermaid_js}"></script>
<script>{script}</script>
</body>
</html>
"""


def _md():
    return markdown.Markdown(extensions=["tables", "fenced_code", "sane_lists", "toc"],
                             extension_configs={"toc": {"toc_depth": "2-2"}})


def _embed_images(body: str, base: Path) -> str:
    def fix(m):
        src = html.unescape(m.group(2))
        path = (base / src).resolve()
        if src.startswith(("http:", "https:", "data:")) or not path.is_file():
            return m.group(0)
        mime = mimetypes.guess_type(path.name)[0] or "image/png"
        data = base64.b64encode(path.read_bytes()).decode()
        return f'{m.group(1)}data:{mime};base64,{data}{m.group(3)}'
    body = re.sub(r'(<img[^>]*\bsrc=")([^"]+)(")', fix, body)
    # a paragraph holding only an image becomes a figure with its alt text as the caption
    return re.sub(r'<p>(<img [^>]*alt="([^"]*)"[^>]*/?>)</p>',
                  lambda m: f'<figure class="img">{m.group(1)}<figcaption>{m.group(2)}</figcaption></figure>', body)


def _relink(body: str, base: Path) -> str:
    def fix(m):
        href, text = m.group(1), m.group(2)
        target, _, frag = href.partition("#")
        if target.endswith(".md") and not target.startswith(("http:", "https:")) and (base / target).with_suffix(".html").is_file():
            new = target[:-3] + ".html"
            href = new + (f"#{frag}" if frag else "")
            if text == target:                       # link text that is the file name follows the link
                text = new
        return f'<a href="{href}">{text}</a>'
    return re.sub(r'<a href="([^"]+)">(.*?)</a>', fix, body, flags=re.S)


def _gfm_lists(text: str) -> str:
    """GitHub starts a list right after a paragraph line; Python-Markdown needs a blank line first."""
    out, fence, in_list, prev = [], False, False, ""
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fence = not fence
        item = not fence and re.match(r"\s*(?:[-*+]|\d+[.)])\s+\S", line)
        if item and not in_list and prev.strip() and not prev.lstrip().startswith(("|", ">", "#", "```")):
            out.append("")
        if not line.strip():
            in_list = False
        elif item:
            in_list = True
        out.append(line)
        prev = line
    return "\n".join(out)


def _blocks(body: str) -> str:
    def code(m):
        lang, src = (m.group(1) or ""), m.group(2)
        if lang == "mermaid":
            return f'<div class="mermaid-box"><pre class="mermaid">{src}</pre></div>'
        cls = ' class="diagram"' if BOX_DRAWING.search(html.unescape(src)) else ""
        lang_attr = f' class="language-{lang}"' if lang else ""
        return f"<pre{cls}><code{lang_attr}>{src}</code></pre>"
    body = re.sub(r'<pre><code(?: class="language-([\w-]+)")?>(.*?)</code></pre>', code, body, flags=re.S)

    def table(m):
        cols = len(re.findall(r"<th[ >]", m.group(0).split("</tr>", 1)[0]))
        cls = "table-wrap wide-table" if cols >= 4 else "table-wrap"
        return f'<div class="{cls}">{m.group(0)}</div>'
    return re.sub(r"<table>.*?</table>", table, body, flags=re.S)


def render(md_path: Path) -> str:
    text = md_path.read_text(encoding="utf-8")
    base = md_path.parent
    h1 = re.match(r"#\s+(.+?)\s*\n", text)
    title_text = h1.group(1) if h1 else md_path.stem
    rest = text[h1.end():] if h1 else text
    quote = re.match(r"\s*((?:>.*\n?)+)", rest)
    lede_md = re.sub(r"^>\s?", "", quote.group(1), flags=re.M) if quote else ""
    if quote:
        rest = rest[quote.end():]

    md = _md()
    body = md.convert(_gfm_lists(rest))
    lede = _relink(_md().convert(lede_md), base)
    body = re.sub(r"<hr\s*/?>", "", body)
    body = _relink(_embed_images(_blocks(body), base), base)

    toc, sections = [], []
    for chunk in re.split(r"(?=<h2 )", body):
        m = re.match(r'<h2 id="([^"]+)">(?:(\d+(?:\.\d+)*)\.?\s+)?(.*?)</h2>', chunk, flags=re.S)
        if not m:
            if chunk.strip():
                sections.append(f"<section>{chunk}</section>")
            continue
        sid, num, heading = m.groups()
        label = re.sub(r"<[^>]+>", "", heading).split(" (")[0].strip()
        numtxt = f"§{num}" if num else "—"
        toc.append(f'      <li><a href="#{sid}"><span>{numtxt}</span>{label}</a></li>')
        h2 = f'<h2 id="{sid}">' + (f'<span class="num">§{num}</span>' if num else "") + f"{heading}</h2>"
        sections.append(f"<section>{h2}{chunk[m.end():]}</section>")

    name, _, sub = title_text.partition(" — ")
    heading = sub or name
    page_title = f"AI-EDR {name}" if sub and "AI-EDR" in sub else title_text
    d = dt.date.today()
    today = f"{d.day} {d:%b %Y}"
    return PAGE.format(
        title=html.escape(page_title),
        description=html.escape(f"HTML edition of {md_path.name}: {heading}."),
        css=CSS, script=SCRIPT, mermaid_js=MERMAID_JS,
        kicker="".join(f"<span>{html.escape(k)}</span>" for k in (name if sub else "Document", "AI-EDR · CheckPoint Zero", "Samsung Digithon 2026")),
        heading=html.escape(heading), lede=lede,
        meta=f"Living document · rendered from <code>{html.escape(md_path.name)}</code> on {today}",
        toc="\n".join(toc), sections="\n".join(sections),
        footer=f"HTML edition of <code>{html.escape(md_path.name)}</code>, generated by <code>scripts/md_to_html.py</code>. Edit the Markdown, then re-run the script.",
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("markdown_file", type=Path)
    ap.add_argument("-o", "--output", type=Path, help="default: same name with .html")
    a = ap.parse_args()
    out = a.output or a.markdown_file.with_suffix(".html")
    out.write_text(render(a.markdown_file), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
