"""Builds the MD brief: the executive deck's cover plus 8 short slides in the same design.

    python presentation/build_md_deck.py

Only reads AI-EDR_Guardrail_Executive_28Oct.pptx, for the cover with the team block, the theme, layouts, icons
and the speaker-notes frame. Writes AI-EDR_Guardrail_MD_Brief_03Nov.pptx here and in the repo root, next to
the .md files. Safe to re-run.

The endpoint agent leads, and the ask is 60 days and one security team member. No latency figure appears
on purpose: speed is measured in the pilot and reported on day 60.
"""
from __future__ import annotations

import copy
import io
import shutil
import uuid
from pathlib import Path

from lxml import etree
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.dml import MSO_THEME_COLOR
from pptx.enum.shapes import MSO_SHAPE, MSO_SHAPE_TYPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.util import Emu, Inches, Pt

HERE = Path(__file__).resolve().parent
BASE = HERE / "AI-EDR_Guardrail_Executive_28Oct.pptx"
OUT = HERE / "AI-EDR_Guardrail_MD_Brief_03Nov.pptx"
ROOT_COPY = HERE.parent / OUT.name

ACCENT, LIGHT_BLUE, NAVY, INK = (MSO_THEME_COLOR.ACCENT_1, MSO_THEME_COLOR.ACCENT_2, MSO_THEME_COLOR.TEXT_2,
                                 MSO_THEME_COLOR.TEXT_1)
WHITE, TINT, GREEN, RED = (MSO_THEME_COLOR.BACKGROUND_1, MSO_THEME_COLOR.BACKGROUND_2, MSO_THEME_COLOR.ACCENT_5,
                           MSO_THEME_COLOR.ACCENT_6)
MUTED, BORDER, HILITE = RGBColor(0x5B, 0x6B, 0x82), RGBColor(0xD6, 0xE0, 0xEF), RGBColor(0x4F, 0x8B, 0xF5)
ON_NAVY, ON_BLUE = RGBColor(0xA9, 0xC8, 0xFF), RGBColor(0xDC, 0xE8, 0xFF)   # labels that stay readable on fills
L, W = 0.60, 12.13      # content left edge and width in inches: the executive deck's grid

A = "http://schemas.openxmlformats.org/drawingml/2006/main"
P14 = "http://schemas.microsoft.com/office/powerpoint/2010/main"
SHADOW = (f'<a:effectLst xmlns:a="{A}"><a:outerShdw blurRad="101600" dist="25400" dir="5400000" algn="bl" '
          'rotWithShape="0"><a:srgbClr val="1A2B4C"><a:alpha val="10000"/></a:srgbClr></a:outerShdw></a:effectLst>')
DECORATIVE = (f'<a:extLst xmlns:a="{A}"><a:ext uri="{{C183D7F6-B498-43B3-948B-1728B52AA6E4}}"><adec:decorative '
              'xmlns:adec="http://schemas.microsoft.com/office/drawing/2017/decorative" val="1"/></a:ext></a:extLst>')

# Icons already in the executive deck (/ppt/media/imageN.png): white glyphs, 256 px.
# "ok", "no" and "ok_white" carry their own circle; the rest sit on one.
ICONS = {"doc": 8, "robot": 9, "spy": 7, "shield": 2, "lock": 16, "eye": 18, "scales": 11, "bolt": 19,
         "server": 22, "chart": 3, "flag": 5, "handshake": 4, "gears": 32, "rocket": 29, "layers": 21,
         "chevron": 14, "no": 24, "ok": 25, "ok_white": 28}
SECTIONS = [("Introduction", 1), ("Problem", 2), ("Solution", 3), ("Scope, pilot and ask", 3)]
KIT: dict = {}          # filled from the executive deck in main(): icon blobs, slide and notes templates


def paint(color_format, color) -> None:
    if isinstance(color, RGBColor):
        color_format.rgb = color
    else:
        color_format.theme_color = color


def box(slide, name, x, y, w, h, fill=WHITE, line=BORDER, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.04331,
        shadow=True):
    sp = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    sp.name = name
    sp._element.remove(sp._element.find(qn("p:style")))    # no theme style: only the look set here applies
    if shape == MSO_SHAPE.ROUNDED_RECTANGLE:
        sp.adjustments[0] = radius
    sp.fill.solid()
    paint(sp.fill.fore_color, fill)
    if line is None:
        sp.line.fill.background()
    else:
        sp.line.width = Emu(9525)
        paint(sp.line.color, line)
    if shadow:
        sp._element.spPr.append(etree.fromstring(SHADOW))
    return sp


def text(slide, name, x, y, w, h, paras, size=16, bold=False, color=MUTED, align=PP_ALIGN.LEFT,
         anchor=MSO_ANCHOR.TOP, spc=None, shape=None):
    """paras: a string, or a list of paragraphs; a paragraph is a string or a list of (text, overrides) runs."""
    if shape is None:
        shape = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
        shape.name = name
    tf = shape.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    tf.vertical_anchor = anchor
    for i, para in enumerate([paras] if isinstance(paras, str) else paras):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        for run in [para] if isinstance(para, str) else para:
            t, o = (run, {}) if isinstance(run, str) else run
            r = p.add_run()
            r.text = t
            r.font.size = Pt(o.get("size", size))
            r.font.bold = o.get("bold", bold)
            paint(r.font.color, o.get("color", color))
            if o.get("spc", spc):
                r._r.get_or_add_rPr().set("spc", str(o.get("spc", spc)))
    return shape


def icon(slide, key, x, y, d, circle=ACCENT):
    """An icon glyph centred on a filled circle; circle=None places the image as it is."""
    if circle is not None:
        box(slide, "Icon circle", x, y, d, d, fill=circle, line=None, shape=MSO_SHAPE.OVAL, shadow=False)
        x, y, d = x + d / 4, y + d / 4, d / 2
    pic = slide.shapes.add_picture(io.BytesIO(KIT["media"][key]), Inches(x), Inches(y), Inches(d), Inches(d))
    pic.name = f"Icon {key}"
    cnv = pic._element.nvPicPr.cNvPr
    cnv.set("descr", "")
    cnv.append(etree.fromstring(DECORATIVE))
    return pic


def pill(slide, x, y, label, h=0.32, right=False):
    w = 0.3 + 0.09 * len(label)
    sp = box(slide, "Pill", x - w if right else x, y, w, h, fill=TINT, line=None, radius=0.5, shadow=False)
    text(slide, None, 0, 0, 0, 0, label, size=10.5, bold=True, color=ACCENT, spc=100, align=PP_ALIGN.CENTER,
         anchor=MSO_ANCHOR.MIDDLE, shape=sp)


def card(slide, x, y, w, h, key, label, title, body):
    box(slide, "Card", x, y, w, h)
    icon(slide, key, x + 0.3, y + 0.3, 0.7)
    text(slide, "Card label", x + 0.3, y + 1.25, w - 0.6, 0.3, label, size=11, bold=True, color=ACCENT, spc=200)
    text(slide, "Card title", x + 0.3, y + 1.58, w - 0.6, 0.45, title, size=20, bold=True, color=NAVY)
    text(slide, "Card text", x + 0.3, y + 2.13, w - 0.55, h - 2.3, body, size=17)


def takeaway(slide, y, lead, rest, key):
    h = 0.6
    box(slide, "Takeaway", L, y, W, h, fill=TINT, line=None, radius=0.16667, shadow=False)
    icon(slide, key, L + 0.15, y + (h - 0.38) / 2, 0.38)
    text(slide, "Takeaway text", L + 0.7, y, W - 0.9, h, [[(lead, {"bold": True}), rest]], color=NAVY,
         anchor=MSO_ANCHOR.MIDDLE)


def set_notes(slide, notes) -> None:
    ns = slide.notes_slide
    if ns.notes_text_frame is None:      # this deck's notes master has no placeholders to inherit
        for el in KIT["notes"]:
            ns.shapes._spTree.append(copy.deepcopy(el))
    ns.notes_text_frame.text = notes


def new_slide(prs, eyebrow, title, notes):
    slide = prs.slides.add_slide(KIT["layout"])
    for ph in list(slide.placeholders):  # use the executive deck's own eyebrow, title and slide number
        ph._element.getparent().remove(ph._element)
    for tpl, value in ((KIT["eyebrow"], eyebrow), (KIT["title"], title), (KIT["sldnum"], None)):
        el = copy.deepcopy(tpl)
        if value is not None:
            el.find(f".//{{{A}}}t").text = value
        slide.shapes._spTree.append(el)
    set_notes(slide, notes)
    return slide


def cover(slide) -> None:
    for sh in slide.shapes:
        if not sh.has_text_frame:
            continue
        runs = sh.text_frame.paragraphs[0].runs
        if sh.text_frame.text.startswith("Stopping prompt injection"):
            runs[0].text = "Stopping hijacked AI agents on every device"
        elif sh.text_frame.text == "Universal pre-LLM security for":
            runs[0].text = "Protects AI agents and platforms"
    chips(slide, ["Claude Code", "Gemini CLI", "Cursor", "Copilot", "FabriX", "AI Pro"])
    set_notes(slide, "Good morning. We are team CheckPoint Zero. In eight slides: the problem we solve, our agent, "
                     "what already works, what is in and out of scope, and a small ask: 60 days and one security "
                     "team member.")


def chips(slide, names) -> None:
    """Swap the platform chips for agent-first ones in the same style (each chip and its label share a frame)."""
    tree = slide.shapes._spTree
    old = [sh for sh in slide.shapes if sh.name == "Platform chip"]
    labels = [next(t for t in slide.shapes if t.shape_type == MSO_SHAPE_TYPE.TEXT_BOX
                   and (t.left, t.top) == (c.left, c.top)) for c in old]
    chip_tpl, label_tpl = copy.deepcopy(old[0]._element), copy.deepcopy(labels[0]._element)
    pos = tree.index(old[0]._element)
    for sh in old + labels:
        tree.remove(sh._element)
    next_id = max(int(e.get("id")) for e in tree.iter(qn("p:cNvPr"))) + 1
    x = 0.69
    for name in names:
        w = 0.4 + 0.09 * len(name)
        for tpl in (chip_tpl, label_tpl):
            el = copy.deepcopy(tpl)
            el.find(f".//{qn('p:cNvPr')}").set("id", str(next_id))
            next_id += 1
            xfrm = el.find(f".//{qn('a:xfrm')}")
            xfrm.find(qn("a:off")).set("x", str(Inches(x)))
            xfrm.find(qn("a:ext")).set("cx", str(Inches(w)))
            if tpl is label_tpl:
                el.find(f".//{qn('a:t')}").text = name
            tree.insert(pos, el)
            pos += 1
        x += w + 0.15


def problem(prs) -> None:
    s = new_slide(prs, "WHAT WE ARE SOLVING", "AI agents act for our people, and can be hijacked",
                  "AI coding agents such as Claude Code, Cursor and Copilot now run commands and read files with the "
                  "employee's own access. An attacker hides an instruction in something the agent reads: a README, a "
                  "PDF, a web page. No person sees it, but the agent follows it and sends out keys or source code. "
                  "That is what we solve: stopping the hijacked action on the device, before it runs.")
    w = 3.69
    gap = (W - 3 * w) / 2
    steps = [("doc", "A poisoned file", "A README, PDF or web page hides an instruction that no person sees."),
             ("robot", "The AI agent obeys", "Claude Code, Cursor or Copilot follows it, with the employee's "
                                             "own access."),
             ("spy", "Data leaves the company", "Keys, source code or customer data are sent out, or harmful "
                                                "commands run.")]
    for i, (key, title, body) in enumerate(steps):
        x = L + i * (w + gap)
        card(s, x, 1.85, w, 3.75, key, f"STEP {i + 1}", title, body)
        if i:
            icon(s, "chevron", x - gap / 2 - 0.11, 1.85 + 3.75 / 2 - 0.11, 0.22, circle=None)
    takeaway(s, 6.0, "What we solve: ", "stop a hijacked AI agent on the device, before it acts.", "shield")


def gap(prs) -> None:
    s = new_slide(prs, "THE GAP", "Why today's security tools miss it",
                  "Why don't existing tools catch this? Antivirus and EDR see a legitimate developer tool doing "
                  "normal-looking work. DLP and proxies watch data leaving, not the instruction that caused it. Each "
                  "AI vendor has its own filter, and reworded attacks get through. Training cannot help when no person "
                  "ever sees the hidden text. Nothing today checks what an AI agent does on the device.")
    items = [("shield", "Antivirus and EDR", "See a trusted developer tool at work, not a hijack."),
             ("lock", "DLP and web proxy", "Watch data leaving, not the hidden instruction behind it."),
             ("robot", "AI vendors' own filters", "Differ for every tool; reworded attacks slip through."),
             ("doc", "Policy and training", "Cannot stop text that no person ever sees.")]
    w, h = (W - 0.25) / 2, 1.8
    for i, (key, title, body) in enumerate(items):
        x, y = L + (i % 2) * (w + 0.25), 1.85 + (i // 2) * (h + 0.25)
        box(s, "Card", x, y, w, h)
        icon(s, key, x + 0.3, y + 0.3, 0.62)
        text(s, "Card title", x + 1.15, y + 0.32, w - 1.45, 0.4, title, size=20, bold=True, color=NAVY)
        text(s, "Card text", x + 1.15, y + 0.82, w - 1.45, 0.8, body)
    takeaway(s, 6.0, "The gap: ", "nothing checks what an AI agent does on the device.", "eye")


def solution(prs) -> None:
    s = new_slide(prs, "OUR SOLUTION", "CheckPoint Zero: a security agent on every device",
                  "Our major solution is the CheckPoint Zero agent. It runs on every laptop, desktop and server, on "
                  "Windows, Linux and macOS. It finds AI tools, approved or not. It checks the commands, file reads "
                  "and network connections they start. It kills hijacked commands, cleans poisoned "
                  "files, and reports to one console. It works offline. Agent first, not agent only: AI with no "
                  "device to install on, such as FabriX workflows, AI Pro and RAG pipelines, is covered by our gateway "
                  "with the same engine.")
    box(s, "Agent panel", L, 1.85, 4.45, 3.95, fill=NAVY, line=None)
    icon(s, "shield", L + 0.35, 2.2, 0.7)
    text(s, "Panel label", L + 0.35, 3.15, 3.8, 0.3, "OUR MAJOR SOLUTION", size=11, bold=True, color=ON_NAVY,
         spc=200)
    text(s, "Panel statement", L + 0.35, 3.5, 3.8, 1.3, "One agent that guards what AI tools do", size=26,
         bold=True, color=WHITE)
    text(s, "Panel platforms", L + 0.35, 5.15, 3.8, 0.4, "Windows · Linux · macOS · works offline", size=15,
         color=ON_NAVY)
    rows = [("eye", "Finds every AI tool", "Spots AI agents on the device, approved or not."),
            ("scales", "Checks every action", "Commands, file reads and network connections started by AI."),
            ("bolt", "Stops and cleans", "Kills a hijacked command and cleans poisoned files."),
            ("server", "Reports to one console", "Every block, with the full chain of who started what.")]
    x, w, h = L + 4.7, W - 4.7, 0.875
    for i, (key, title, body) in enumerate(rows):
        y = 1.85 + i * (h + 0.15)
        box(s, "Row", x, y, w, h)
        icon(s, key, x + 0.25, y + (h - 0.52) / 2, 0.52)
        text(s, "Row title", x + 1.0, y + 0.13, w - 1.3, 0.34, title, size=18, bold=True, color=NAVY)
        text(s, "Row text", x + 1.0, y + 0.49, w - 1.3, 0.3, body, size=15)
    takeaway(s, 6.05, "Agent first: ", "a gateway covers AI with no device to install on: FabriX, AI Pro and RAG.",
             "layers")


def how_it_works(prs) -> None:
    s = new_slide(prs, "HOW IT WORKS", "Four steps, all on the device",
                  "Four steps. An AI tool tries to act. The agent intercepts the action at the operating system; on "
                  "Linux, inside the kernel. Our engine decides on the device: fast rules first, then an AI model. "
                  "Safe work continues; a hijack is stopped and poisoned files are cleaned. There is no cloud call, "
                  "so it keeps working offline.")
    box(s, "Flow panel", L, 1.85, W, 3.75)
    step, d = W / 4, 1.0
    centers = [L + step * (i + 0.5) for i in range(4)]
    box(s, "Flow line", centers[0], 2.3 + d / 2 - 0.025, centers[-1] - centers[0], 0.05, fill=LIGHT_BLUE, line=None,
        shape=MSO_SHAPE.RECTANGLE, shadow=False)
    steps = [("robot", "AI tool acts", "Runs a command, opens a file or connects out."),
             ("eye", "Agent intercepts", "At the operating system; inside the kernel on Linux."),
             ("scales", "Engine decides", "Rules first, then an AI model, all on the device."),
             ("shield", "Allow, block or clean", "Safe work goes on. Hijacks stop; files are cleaned.")]
    for i, (cx, (key, title, body)) in enumerate(zip(centers, steps)):
        icon(s, key, cx - d / 2, 2.3, d, circle=GREEN if i == 3 else ACCENT)
        text(s, "Step label", cx - 1.4, 3.5, 2.8, 0.3, f"STEP {i + 1}", size=11, bold=True, color=ACCENT, spc=200,
             align=PP_ALIGN.CENTER)
        text(s, "Step title", cx - 1.4, 3.82, 2.8, 0.45, title, size=20, bold=True, color=NAVY, align=PP_ALIGN.CENTER)
        text(s, "Step text", cx - 1.35, 4.32, 2.7, 1.1, body, align=PP_ALIGN.CENTER)
    takeaway(s, 6.0, "No cloud call: ", "decisions are made on the device, and the agent keeps working offline.",
             "lock")


def proof(prs) -> None:
    s = new_slide(prs, "PROOF", "Built and tested on Windows, Linux and macOS",
                  "This is built and tested, not a design. On Windows, on GitHub's test machines, our installer set the "
                  "agent up as a system service. A simulated hijacked agent tried to send the SSH key out; the agent "
                  "stopped it and cleaned two poisoned files. On Linux, blocking happens inside the OS kernel: 8 of 8 "
                  "live tests passed. On macOS the same attack was stopped, and a poisoned PDF and README were cleaned. "
                  "If asked: the Windows kernel driver is built, and needs Microsoft driver signing before it can be "
                  "loaded.")
    w = (W - 0.5) / 3
    cards = [("Windows", "LIVE TEST · GITHUB CI", ["Installs as a system service",
                                                   "Stopped a hijacked agent before it sent the SSH key",
                                                   "Cleaned 2 poisoned files"]),
             ("Linux", "KERNEL-LEVEL", ["Blocks inside the OS kernel", "8 of 8 live kernel tests passed",
                                        "Refused a key theft before any data left"]),
             ("macOS", "LIVE TEST", ["Stopped a hijacked agent's data theft", "Cleaned a poisoned PDF and README"])]
    for i, (name, status, lines) in enumerate(cards):
        x = L + i * (w + 0.25)
        box(s, "Card", x, 1.85, w, 3.9)
        text(s, "OS", x + 0.35, 2.12, w - 0.7, 0.5, name, size=26, bold=True, color=NAVY)
        pill(s, x + 0.35, 2.75, status)
        for j, line in enumerate(lines):
            y = 3.4 + j * 0.72
            icon(s, "ok", x + 0.35, y + 0.02, 0.3, circle=None)
            text(s, "Result", x + 0.8, y, w - 1.15, 0.65, line, color=INK)
    takeaway(s, 6.05, "120 automated tests. ", "The agent is re-tested on Windows and Linux at every code change.",
             "chart")


def scope(prs) -> None:
    s = new_slide(prs, "SCOPE", "What the pilot covers, and what it does not",
                  "The pilot covers text-based attacks: hidden instructions in prompts, documents, code and web pages. "
                  "It covers what AI agents do: commands, file access and network connections. It also catches keys, "
                  "source code and personal data leaking through AI. Not in this pilot: instructions hidden inside "
                  "images, which come next with text extraction from images; voice and audio, later; checking the AI's "
                  "answers, next; and mobile phones.")
    cols = [("ok", "In the pilot", GREEN,
             [("Hidden instructions in text", "Prompts, PDF and Word files, code, web pages, RAG", None),
              ("What AI agents do", "Commands, file access and network connections", None),
              ("Leaks through AI", "Keys, passwords, source code and personal data", None),
              ("Windows, Linux and macOS", "Plus FabriX and AI Pro through the gateway", None)]),
            ("no", "Not in this pilot", RED,
             [("Image-based injection", "Instructions hidden inside pictures", "NEXT PHASE"),
              ("Voice and audio injection", "Spoken or hidden audio commands", "LATER"),
              ("Checking the AI's answers", "Model output is not inspected yet", "NEXT PHASE"),
              ("Mobile phones", "Android and iOS devices", "LATER")])]
    w = (W - 0.25) / 2
    for i, (key, head, color, rows) in enumerate(cols):
        x = L + i * (w + 0.25)
        box(s, "Card", x, 1.85, w, 4.0)
        icon(s, key, x + 0.35, 2.15, 0.5, circle=None)
        text(s, "Column title", x + 1.0, 2.15, w - 1.35, 0.5, head, size=22, bold=True, color=color,
             anchor=MSO_ANCHOR.MIDDLE)
        box(s, "Divider", x + 0.35, 2.9, w - 0.7, 0.015, fill=BORDER, line=None, shape=MSO_SHAPE.RECTANGLE,
            shadow=False)
        for j, (title, detail, tag) in enumerate(rows):
            y = 3.08 + j * 0.66
            icon(s, key, x + 0.4, y + 0.04, 0.24, circle=None)
            text(s, "Row title", x + 0.8, y, w - 2.6 if tag else w - 1.15, 0.3, title, color=INK, bold=True)
            text(s, "Row text", x + 0.8, y + 0.3, w - 1.15, 0.3, detail, size=14)
            if tag:
                pill(s, x + w - 0.35, y, tag, h=0.28, right=True)
    takeaway(s, 6.1, "Images and voice: ", "not in this pilot. Image checks are next on the roadmap; voice after that.",
             "flag")


def pilot(prs) -> None:
    s = new_slide(prs, "60-DAY PILOT", "A 60-day pilot in three steps",
                  "Days 1 to 15: install the agent on one R&D team's laptops, and the gateway on one FabriX workflow "
                  "and one AI Pro team, in monitor-only mode, so nothing is blocked. Days 16 to 45: with the security "
                  "team member, review every alert, run attack tests and remove false alarms. Days 46 to 60: turn on "
                  "blocking for a small group and report. If asked about latency: we measure it on real use and report "
                  "it on day 60, rather than promise a number today.")
    w = (W - 0.5) / 3
    phases = [("eye", "DAYS 1–15", LIGHT_BLUE, "Install and watch",
               "Agent on one R&D team's laptops; gateway on one FabriX workflow and one AI Pro team. Monitor only."),
              ("gears", "DAYS 16–45", ACCENT, "Tune and test",
               "With the security member: review alerts, run attack tests, remove false alarms."),
              ("rocket", "DAYS 46–60", NAVY, "Enforce and report",
               "Blocking on for a small group. Results and a go/no-go decision on day 60.")]
    for i, (key, days, fill, title, body) in enumerate(phases):
        x = L + i * (w + 0.25)
        arrow = box(s, "Phase", x, 1.85, w, 0.6, fill=fill, line=None,
                    shape=MSO_SHAPE.PENTAGON if i == 0 else MSO_SHAPE.CHEVRON, shadow=False)
        text(s, None, 0, 0, 0, 0, days, size=14, bold=True, color=WHITE, spc=150, align=PP_ALIGN.CENTER,
             anchor=MSO_ANCHOR.MIDDLE, shape=arrow)
        box(s, "Card", x, 2.7, w, 3.05)
        icon(s, key, x + 0.3, 3.0, 0.62)
        text(s, "Card title", x + 0.3, 3.8, w - 0.6, 0.45, title, size=20, bold=True, color=NAVY)
        text(s, "Card text", x + 0.3, 4.3, w - 0.55, 1.35, body, size=17)
    takeaway(s, 6.05, "Day 60 report: ", "detection, false alarms and speed, measured on real use.", "chart")


def ask(prs) -> None:
    s = new_slide(prs, "OUR ASK", "Our ask: 60 days and one security team member",
                  "Our ask is small: 60 days, and one member of the security team to set policy, review alerts and "
                  "sign off the results. By day 60 you get measured results on Samsung devices, policies tuned with "
                  "the security team, and a clear go/no-go for wider rollout. We ask you to approve the 60-day pilot "
                  "today.")
    w = (W - 0.5) / 3
    for i, (number, label, body) in enumerate([
            ("60", "days", "To run the pilot on real devices and AI platforms."),
            ("1", "security team member", "To set policy, review alerts and sign off the results.")]):
        x = L + i * (w + 0.25)
        box(s, "Card", x, 1.85, w, 3.95)
        text(s, "Number", x + 0.35, 2.4, w - 0.7, 1.35, number, size=80, bold=True, color=ACCENT)
        text(s, "Number label", x + 0.35, 3.85, w - 0.7, 0.45, label, size=24, bold=True, color=NAVY)
        text(s, "Card text", x + 0.35, 4.45, w - 0.7, 0.9, body, size=17)
    x = L + 2 * (w + 0.25)
    box(s, "Ask card", x, 1.85, w, 3.95, fill=ACCENT, line=None)
    icon(s, "handshake", x + 0.35, 2.15, 0.7, circle=NAVY)
    text(s, "Ask label", x + 0.35, 3.1, w - 0.7, 0.3, "BY DAY 60, YOU GET", size=11, bold=True, color=ON_BLUE, spc=200)
    for j, line in enumerate(["Measured results on Samsung devices", "Policies tuned with the security team",
                              "A clear go/no-go for wider rollout"]):
        y = 3.55 + j * 0.68
        icon(s, "ok_white", x + 0.35, y + 0.03, 0.3, circle=None)
        text(s, "Ask item", x + 0.8, y, w - 1.1, 0.62, line, bold=True, color=WHITE)
    takeaway(s, 6.05, "Decision requested: ", "approve the 60-day pilot and name one security team member.", "flag")


def keep_cover_only(prs) -> None:
    ids = prs.slides._sldIdLst
    for sld in list(ids)[1:]:
        prs.part.drop_rel(sld.rId)
        ids.remove(sld)


def set_sections(prs) -> None:
    lst = prs.part._element.find(f".//{{{P14}}}sectionLst")
    for sec in list(lst):
        lst.remove(sec)
    ids = iter(sl.slide_id for sl in prs.slides)
    for name, count in SECTIONS:
        guid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ai-edr/md-brief/{name}")).upper()
        sec = etree.SubElement(lst, f"{{{P14}}}section", name=name, id=f"{{{guid}}}")
        sl = etree.SubElement(sec, f"{{{P14}}}sldIdLst")
        for _ in range(count):
            etree.SubElement(sl, f"{{{P14}}}sldId", id=str(next(ids)))


def main() -> None:
    prs = Presentation(BASE)
    ref = prs.slides[1]                  # an executive content slide: eyebrow, title, slide number, notes frame
    shapes = list(ref.shapes)
    media = {p.partname: p.blob for p in prs.part.package.iter_parts() if p.partname.startswith("/ppt/media/image")}
    KIT.update(layout=ref.slide_layout,
               eyebrow=copy.deepcopy(shapes[0]._element), title=copy.deepcopy(shapes[1]._element),
               sldnum=copy.deepcopy(next(sh for sh in shapes if sh.name.startswith("Slide Number"))._element),
               notes=[copy.deepcopy(sh._element) for sh in ref.notes_slide.shapes],
               media={key: media[f"/ppt/media/image{n}.png"] for key, n in ICONS.items()})
    keep_cover_only(prs)
    cover(prs.slides[0])
    for build in (problem, gap, solution, how_it_works, proof, scope, pilot, ask):
        build(prs)
    set_sections(prs)
    # Slide numbers are fields (PowerPoint recalculates them); refresh the cached values for every viewer.
    for n, sl in enumerate(prs.slides, 1):
        for sh in sl.shapes:
            for t in sh._element.iter(f"{{{A}}}fld"):
                if t.get("type") == "slidenum":
                    for tt in t.iter(f"{{{A}}}t"):
                        tt.text = str(n)
    prs.save(OUT)
    shutil.copy2(OUT, ROOT_COPY)
    print(f"wrote {OUT.name} ({len(prs.slides)} slides) and its copy in the repo root")


if __name__ == "__main__":
    main()
