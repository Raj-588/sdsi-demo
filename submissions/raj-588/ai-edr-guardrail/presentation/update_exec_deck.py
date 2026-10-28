"""Adds the team block to slide 1 and a 50-second demo-video slide to the executive deck (in place).

    python presentation/update_exec_deck.py

Idempotent: always rebuilds from presentation/backup/<original>.pptx, so re-running is safe.
Edit the original in backup/ if the base deck itself changes.
"""
from __future__ import annotations

import copy
import shutil
import subprocess
from pathlib import Path

import imageio_ffmpeg
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.dml import MSO_THEME_COLOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.util import Inches, Pt

HERE = Path(__file__).resolve().parent
DECK = HERE / "AI-EDR_Guardrail_Executive_28Oct.pptx"
BACKUP = HERE / "backup" / "AI-EDR_Guardrail_Executive_28Oct_original.pptx"
VIDEO = HERE / "AI-EDR_50s_Demo.mp4"
POSTER = HERE / "build" / "exec" / "poster.png"
INSERT_AFTER = 8          # new slide becomes slide 9 (after "One engine, every AI platform")
TAG = "AIEDR_TEAM_BLOCK"  # shape-name prefix, so re-runs replace instead of duplicating

TEAM_ROWS = [
    ("Team Name:", "CheckPoint Zero"),
    ("Functional Idea By:", "Raj Kumar Singh"),
    ("Implemented By:", "Rajkumar Pareek, Raj Kumar Singh, Shubham Kumar Mishra, Nikita Singh, Chandan Kumar"),
    ("Mentor:", "Deepti Kaushal"),
]
LABEL = RGBColor(0x5B, 0x6B, 0x82)


def add_text(slide, name, x, y, w, h, text, size, bold=False, color=None, theme=None):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tb.name = name
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    r = tf.paragraphs[0].add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.bold = bold
    if theme is not None:
        r.font.color.theme_color = theme
    elif color is not None:
        r.font.color.rgb = color
    return tb


def team_block(slide) -> None:
    for sh in list(slide.shapes):
        if sh.name.startswith(TAG):
            sh._element.getparent().remove(sh._element)
    panel = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.55), Inches(4.98), Inches(7.6), Inches(1.95))
    panel.name = f"{TAG} panel"
    panel.adjustments[0] = 0.06
    panel.fill.solid()
    panel.fill.fore_color.rgb = RGBColor(0xF5, 0xF8, 0xFC)
    panel.line.color.rgb = RGBColor(0xE1, 0xE7, 0xF0)
    panel.shadow.inherit = False
    accent = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(1.55), Inches(4.98), Inches(0.07), Inches(1.95))
    accent.name = f"{TAG} accent"
    accent.fill.solid()
    accent.fill.fore_color.theme_color = MSO_THEME_COLOR.ACCENT_1
    accent.line.fill.background()
    y = 5.12
    for label, value in TEAM_ROWS:
        tall = len(value) > 60
        add_text(slide, f"{TAG} {label}", Inches(1.8), Inches(y), Inches(2.05), Inches(0.35), label, 12, True, LABEL)
        if label == "Team Name:":
            add_text(slide, f"{TAG} value", Inches(3.85), Inches(y - 0.03), Inches(5.15), Inches(0.38), value, 16, True,
                     theme=MSO_THEME_COLOR.ACCENT_1)
        else:
            add_text(slide, f"{TAG} value", Inches(3.85), Inches(y), Inches(5.15), Inches(0.6 if tall else 0.35), value, 12,
                     theme=MSO_THEME_COLOR.TEXT_1)
        y += 0.62 if tall else 0.42


def video_slide(prs) -> None:
    # remove a previously inserted video slide
    for idx, s in enumerate(prs.slides):
        if any(sh.name == "AIEDR 2min video" for sh in s.shapes):
            rid = prs.slides._sldIdLst[idx].rId
            prs.part.drop_rel(rid)
            del prs.slides._sldIdLst[idx]
            break
    ref = next(s for s in prs.slides if any(sh.name == "Playground video" for sh in s.shapes))  # existing video slide
    slide = prs.slides.add_slide(ref.slide_layout)
    for sh in slide.placeholders:
        if sh.placeholder_format.idx == 100:
            sh.text_frame.text = "DEMO VIDEO"
        elif sh.placeholder_format.idx == 101:
            sh.text_frame.text = "AI-EDR in 50 seconds"
    for sh in ref.shapes:   # same frame, caption and slide number as the existing video slide
        if sh.name in ("Video frame", "Text 3") or "Slide Number" in sh.name:
            el = copy.deepcopy(sh._element)
            slide.shapes._spTree.append(el)
    for sh in slide.shapes:
        if sh.name == "Text 3":
            sh.text_frame.paragraphs[0].runs[0].text = "Narrated product demo (0:50)  ·  click to play"
            for r in sh.text_frame.paragraphs[0].runs[1:]:
                r.text = ""
    frame = next(sh for sh in ref.shapes if sh.name == "Playground video")
    movie = slide.shapes.add_movie(str(VIDEO), frame.left, frame.top, frame.width, frame.height,
                                   poster_frame_image=str(POSTER), mime_type="video/mp4")
    movie.name = "AIEDR 2min video"
    notes = slide.notes_slide
    if notes.notes_text_frame is None:   # this template's notes master has no body placeholder: borrow ref's
        notes.shapes._spTree.append(copy.deepcopy(ref.notes_slide.notes_placeholder._element))
    notes.notes_text_frame.text = (
        "Play the 50-second video. It shows: the poisoned resume (without vs. with AI-EDR), a jailbreak and an AI Pro "
        "data leak being blocked, a coding-agent attack being stripped, the browser extension swapping a poisoned file, "
        "and the Falcon Loop blocking a learned attack on another platform. After it ends, continue with the next slide.")
    ids = prs.slides._sldIdLst
    el = ids[-1]
    ids.remove(el)
    ids.insert(INSERT_AFTER, el)


def main() -> None:
    if not BACKUP.exists():
        BACKUP.parent.mkdir(exist_ok=True)
        shutil.copy2(DECK, BACKUP)
    POSTER.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(), "-y", "-ss", "2", "-i", str(VIDEO), "-frames:v", "1", str(POSTER)],
                   check=True, capture_output=True)
    prs = Presentation(BACKUP)   # always start from the untouched original, so re-runs never stack edits
    team_block(prs.slides[0])
    video_slide(prs)
    # Slide numbers are fields (PowerPoint recalculates them); refresh the cached values for every viewer.
    for n, sl in enumerate(prs.slides, 1):
        for sh in sl.shapes:
            for t in sh._element.iter("{http://schemas.openxmlformats.org/drawingml/2006/main}fld"):
                if t.get("type") == "slidenum":
                    for tt in t.iter("{http://schemas.openxmlformats.org/drawingml/2006/main}t"):
                        tt.text = str(n)
    prs.save(DECK)
    print(f"updated {DECK.name}: {len(prs.slides)} slides")


if __name__ == "__main__":
    main()
