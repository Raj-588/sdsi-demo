"""2-minute narrated demo video for the executive deck: presentation/AI-EDR_2min_Demo.mp4

    ./scripts/start_live_demo.sh          # fresh gateway on :8080
    python presentation/build_exec_video.py          # 2-minute version
    python presentation/build_exec_video.py --50s    # 50-second version (used in the executive deck)

Each segment is a fresh screen recording of the real console / browser extension, trimmed to its
narration (macOS `say`), plus title and end cards in the executive deck's palette.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_video as bv  # noqa: E402  (reuses ffmpeg, say and duration helpers)

OUT = HERE / "build" / "exec"
CONSOLE = "http://localhost:8080/console"
NAVY, BLUE, SKY = "#1B2A6B", "#2E6FD6", "#4AA3F0"

SEGMENTS = [
    dict(id="title", card=("AI-EDR in 2 minutes", "Team CheckPoint Zero · Samsung Digithon 2026"),
         say="This is A I E D R in two minutes, from team CheckPoint Zero. One inline guard that stops prompt injection "
             "before any AI model reads a single token."),
    dict(id="resume", actions=[("click", "#sc-4", 9000)],
         say="An HR assistant is asked about a resume that hides white text telling the AI to approve the candidate. "
             "Without A I E D R, on the left, the model obeys: approved, immediate hire. With A I E D R, on the right, the "
             "three hidden layers are stripped, and the model gives the honest verdict: not qualified."),
    dict(id="jailbreak_dlp", actions=[("click", "#sc-2", 6500), ("click", "#sc-9", 7500)],
         say="A typed jailbreak is blocked in about two milliseconds and never reaches the model. And when a developer "
             "pastes Samsung confidential code with a cloud access key into A I Pro, it is stopped before it leaves the company."),
    dict(id="agent", actions=[("click", "#sc-10", 9000)],
         say="A coding agent reads a README with a hidden command to upload the developer's SSH key. Without protection the "
             "agent runs it. A I E D R removes that one command, and the tests simply run."),
    dict(id="extension", clip="extension",
         say="For Claude and Gemini in the browser, our extension holds every prompt and upload. The jailbreak is never sent, "
             "and the poisoned resume is replaced by a clean copy before it is uploaded. A clean file passes untouched."),
    dict(id="falcon", actions=[("click", "#sc-11", 5000), ("click", "#sc-12", 5500), ("click", "#sc-13", 5500)],
         say="And it learns. A new Korean attack passes once on Gemini. Then the same attack, hidden in a document on "
             "ChatGPT, is caught and learned. Seconds later, it is blocked on Gemini too. Learn once, protect everywhere."),
    dict(id="console", actions=[("nav", "feed", 1500), ("first_item", "#feed-list .item", 2000), ("tab", "Content", 3000),
                                ("nav", "vault", 1200), ("first_item", "#vault-list .item", 3500)],
         say="For the security team, every decision is explained: which detector fired, the text before and after cleaning, "
             "and a forensic quarantine vault where analysts confirm or release."),
    dict(id="end", card=("Every AI. One guard.", "70% of never-seen attacks blocked · 0% false positives · ~17 ms per prompt"),
         say="Seventy percent of never-seen attacks blocked, zero false positives, about seventeen milliseconds per prompt. "
             "A I E D R: every A I, one guard. Thank you."),
]

# 50-second cut: same recordings, tighter narration, fewer beats.
SEGMENTS_50 = [
    dict(id="s_title", card=("AI-EDR", "Team CheckPoint Zero · Samsung Digithon 2026"),
         say="A I E D R, from team CheckPoint Zero.", pad=2.2),
    dict(id="s_resume", actions=[("click", "#sc-4", 6500)],
         say="This resume hides white text telling the AI to approve the candidate. Without A I E D R, the model obeys. "
             "With it, the hidden commands are stripped, and the verdict is honest."),
    dict(id="s_block", actions=[("click", "#sc-2", 3800), ("click", "#sc-9", 4200)],
         say="Jailbreaks are blocked in milliseconds, and confidential code never leaves the company."),
    dict(id="s_agent", actions=[("click", "#sc-10", 6000)],
         say="A hidden command to steal a developer's SSH key is removed before the coding agent can run it."),
    dict(id="s_extension", clip="extension", skip=9.5,
         say="In the browser, a poisoned file is swapped for a clean copy before upload."),
    dict(id="s_falcon", actions=[("click", "#sc-11", 2600), ("click", "#sc-12", 2800), ("click", "#sc-13", 3200)],
         say="And it learns: an attack caught on one platform is blocked on every platform."),
    dict(id="s_end", card=("Every AI. One guard.", "70% of never-seen attacks blocked · 0% false positives · ~17 ms"),
         say="A I E D R. Every AI, one guard.", pad=2.5),
]

CARD = """<html><head><style>
body{{margin:0;width:1920px;height:1080px;background:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
position:relative;overflow:hidden;color:#0f172a}}
.r1{{position:absolute;right:0;top:0;bottom:0;width:560px;background:#E8EEF8}}
.r2{{position:absolute;right:0;top:0;bottom:0;width:420px;background:{sky}}}
.r3{{position:absolute;right:0;top:0;bottom:0;width:250px;background:{blue}}}
.r4{{position:absolute;right:0;top:0;bottom:0;width:130px;background:{navy}}}
.eyebrow{{position:absolute;left:120px;top:300px;font-size:28px;font-weight:800;letter-spacing:4px;color:{blue}}}
h1{{position:absolute;left:120px;top:350px;margin:0;font-size:104px;letter-spacing:-2px;color:{navy};max-width:1200px;line-height:1.05}}
p{{position:absolute;left:120px;top:{sub_top}px;margin:0;font-size:38px;color:#5B6B82;max-width:1180px;line-height:1.35}}
</style></head><body><div class="r1"></div><div class="r2"></div><div class="r3"></div><div class="r4"></div>
<div class="eyebrow">AI-EDR INLINE GUARDRAIL</div><h1>{title}</h1><p>{sub}</p></body></html>"""


async def render_card(seg: dict) -> Path:
    from playwright.async_api import async_playwright
    title, sub = seg["card"]
    html = OUT / f"{seg['id']}.html"
    html.write_text(CARD.format(title=bv.esc(title), sub=bv.esc(sub), navy=NAVY, blue=BLUE, sky=SKY,
                                sub_top=500 if len(title) < 22 else 600))
    png = OUT / f"{seg['id']}.png"
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1920, "height": 1080})
        await pg.goto(f"file://{html}")
        await pg.screenshot(path=str(png))
        await b.close()
    return png


async def record_console(seg: dict) -> Path:
    """Record one segment of the real console performing the segment's actions."""
    from playwright.async_api import async_playwright
    vids = OUT / f"rec_{seg['id']}"
    vids.mkdir(exist_ok=True)
    for f in vids.glob("*.webm"):
        f.unlink()
    async with async_playwright() as p:
        b = await p.chromium.launch()
        ctx = await b.new_context(viewport={"width": 1600, "height": 900}, record_video_dir=str(vids),
                                  record_video_size={"width": 1600, "height": 900})
        pg = await ctx.new_page()
        await pg.goto(CONSOLE + "#playground")
        await pg.wait_for_timeout(1200)
        for kind, target, wait in seg["actions"]:
            if kind == "click":
                await pg.click(target)
            elif kind == "nav":
                await pg.click(f".nav[data-page={target}]")
            elif kind == "first_item":
                items = await pg.query_selector_all(target)
                if items:
                    await items[0].click()
            elif kind == "tab":
                await pg.click(f"button.tab:has-text('{target}')")
            await pg.wait_for_timeout(wait)
        await ctx.close()
        await b.close()
    return next(vids.glob("*.webm"))


def to_segment(seg: dict, visual: Path, is_image: bool, skip: float = 0.0, rate: int = 172) -> Path:
    audio = OUT / f"{seg['id']}.aiff"
    bv.subprocess.run(["say", "-v", bv.VOICE, "-r", str(rate), "-o", str(audio), seg["say"]], check=True)
    total = bv.duration(audio) + seg.get("pad", 2.0)
    out = OUT / f"seg_{seg['id']}.mp4"
    scale = "scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:color=0xffffff"
    if is_image:
        inputs = ["-loop", "1", "-i", str(visual)]
        vf = f"[0:v]{scale},format=yuv420p[v]"
    else:
        inputs = ["-ss", f"{skip:.2f}", "-i", str(visual)]
        vf = f"[0:v]{scale},fps=30,tpad=stop_mode=clone:stop_duration=30,format=yuv420p[v]"
    bv.run([bv.FFMPEG, "-y", *inputs, "-i", str(audio), "-filter_complex", f"{vf};[1:a]adelay=300|300,apad[a]",
            "-map", "[v]", "-map", "[a]", "-t", f"{total:.2f}", "-c:v", "libx264", "-r", "30",
            "-c:a", "aac", "-ar", "44100", "-ac", "2", str(out)])
    return out


def main() -> None:
    short = "--50s" in sys.argv
    segments, rate = (SEGMENTS_50, 176) if short else (SEGMENTS, 172)
    OUT.mkdir(parents=True, exist_ok=True)
    parts = []
    for seg in segments:
        print("segment:", seg["id"])
        if short:
            seg.setdefault("pad", 2.0)
        if "card" in seg:
            parts.append(to_segment(seg, asyncio.run(render_card(seg)), True, rate=rate))
        elif seg.get("clip") == "extension":
            clip = asyncio.run(bv.record_extension())
            parts.append(to_segment(seg, clip, False, skip=seg.get("skip", 0.8), rate=rate))
        else:
            parts.append(to_segment(seg, asyncio.run(record_console(seg)), False, skip=1.0, rate=rate))
    lst = OUT / "concat.txt"
    lst.write_text("".join(f"file '{p}'\n" for p in parts))
    final = HERE / ("AI-EDR_50s_Demo.mp4" if short else "AI-EDR_2min_Demo.mp4")
    bv.run([bv.FFMPEG, "-y", "-f", "concat", "-safe", "0", "-i", str(lst), "-c:v", "libx264", "-pix_fmt", "yuv420p",
            "-c:a", "aac", "-movflags", "+faststart", str(final)])
    print(f"done: {final} ({bv.duration(final):.0f} s)")


if __name__ == "__main__":
    main()
