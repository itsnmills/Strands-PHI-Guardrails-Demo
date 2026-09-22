#!/usr/bin/env python3
"""Generate the README's vector overview and synthetic feature-tour GIF.

Requires macOS (AppKit) and ffmpeg. Re-run with `python3 scripts/generate_readme_visuals.py`.
"""

from __future__ import annotations

import html
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
FRAMES = DOCS / "readme-visuals"
WIDTH, HEIGHT = 1440, 860

INK = "#152721"
MUTED = "#63736d"
GREEN = "#0d8b68"
MINT = "#d9f4e9"
RED = "#c84943"
PALE_RED = "#fce9e7"
AMBER = "#a96d12"
PALE_AMBER = "#fff2d9"
SURFACE = "#ffffff"
CANVAS = "#f3f7f5"
LINE = "#dce6e1"
MONO = "SFMono-Regular, Menlo, Consolas, monospace"
SANS = "Inter, Arial, sans-serif"


def esc(value: str) -> str:
    return html.escape(value, quote=True)


def text(
    x: int,
    y: int,
    value: str,
    *,
    size: int = 16,
    fill: str = INK,
    weight: int = 500,
    family: str = SANS,
    spacing: float = 0,
    anchor: str = "start",
) -> str:
    return (
        f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}" letter-spacing="{spacing}" '
        f'text-anchor="{anchor}">{esc(value)}</text>'
    )


def box(
    x: int,
    y: int,
    w: int,
    h: int,
    *,
    fill: str = SURFACE,
    stroke: str = LINE,
    radius: int = 18,
    stroke_width: int = 1,
) -> str:
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width}"/>'
    )


def pill(x: int, y: int, label: str, *, color: str = GREEN, bg: str = MINT) -> str:
    width = max(76, 18 + len(label) * 7)
    return (
        f'<rect x="{x}" y="{y - 17}" width="{width}" height="25" rx="12.5" fill="{bg}"/>'
        + text(x + width // 2, y, label, size=10, fill=color, weight=700, family=MONO, spacing=0.7, anchor="middle")
    )


def shield_icon(x: int = 56, y: int = 37) -> str:
    return (
        f'<path d="M{x + 15} {y} L{x + 29} {y + 5} V{y + 18} '
        f'C{x + 29} {y + 28} {x + 22} {y + 34} {x + 15} {y + 38} '
        f'C{x + 8} {y + 34} {x + 1} {y + 28} {x + 1} {y + 18} V{y + 5} Z" '
        f'fill="{MINT}" stroke="{GREEN}" stroke-width="1.5"/>'
        f'<path d="M{x + 8} {y + 18} l5 5 9 -10" fill="none" stroke="{GREEN}" '
        'stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>'
    )


def background(width: int, height: int) -> str:
    return (
        f'<rect width="{width}" height="{height}" fill="{CANVAS}"/>'
        '<circle cx="1360" cy="38" r="210" fill="#e7f4ee" opacity=".72"/>'
        '<circle cx="15" cy="850" r="220" fill="#eaf1ee" opacity=".58"/>'
    )


def svg_document(body: str, *, width: int = WIDTH, height: int = HEIGHT) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">'
        '<title id="title">PHI Guardrails system overview</title>'
        '<desc id="desc">Synthetic-data illustration of deterministic policy enforcement before a tool runs.</desc>'
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">'
        '<path d="M0 0 L8 4 L0 8 Z" fill="#0d8b68"/></marker>'
        '<filter id="shadow" x="-20%" y="-20%" width="140%" height="150%">'
        '<feDropShadow dx="0" dy="5" stdDeviation="8" flood-color="#163b2f" flood-opacity=".07"/>'
        '</filter></defs>'
        + body
        + '</svg>'
    )


def card_title(x: int, y: int, label: str, *, tag: str = "") -> str:
    content = text(x + 22, y + 31, label, size=11, fill=MUTED, weight=700, family=MONO, spacing=0.85)
    if tag:
        content += pill(x + 22, y + 61, tag, color=GREEN, bg=MINT)
        content += text(x + 22, y + 92, "Structured request context", size=15, weight=600)
    return content


def build_control_path() -> str:
    out = [background(1440, 920), shield_icon()]
    out += [
        text(98, 52, "PHI GUARDRAILS", size=13, weight=750, spacing=1.5),
        text(98, 74, "POLICY-AS-CODE · HEALTHCARE AI", size=10, fill=MUTED, weight=600, family=MONO, spacing=0.7),
        pill(1214, 53, "SYNTHETIC DATA ONLY", color=GREEN, bg=MINT),
        text(56, 139, "The verdict stays in policy code.", size=35, weight=700),
        text(56, 174, "An agent can request a tool call. Six deterministic checks decide whether it runs.", size=17, fill=MUTED, weight=450),
    ]

    # Connectors sit behind the cards so the system path remains clear.
    out += [
        f'<path d="M318 399 H342" fill="none" stroke="{GREEN}" stroke-width="2.5" marker-end="url(#arrow)"/>',
        f'<path d="M770 399 H790" fill="none" stroke="{GREEN}" stroke-width="2.5" marker-end="url(#arrow)"/>',
        f'<path d="M1056 399 H1074" fill="none" stroke="{GREEN}" stroke-width="2.5" marker-end="url(#arrow)"/>',
    ]
    # Request card.
    x, y, w, h = 48, 218, 270, 376
    out += [box(x, y, w, h), card_title(x, y, "REQUEST", tag="BEFORE TOOL EXECUTION")]
    request_rows = [
        ("ROLE", "Registered nurse"),
        ("PURPOSE", "Treatment"),
        ("TOOL", "query_patient_record"),
        ("TARGET", "P003 · restricted tier"),
    ]
    for i, (label, value) in enumerate(request_rows):
        ry = y + 137 + i * 54
        out += [text(x + 22, ry, label, size=9, fill=MUTED, weight=700, family=MONO, spacing=0.7)]
        out += [text(x + 22, ry + 22, value, size=13 if i >= 2 else 14, weight=600, family=MONO if i >= 2 else SANS)]
        if i < len(request_rows) - 1:
            out += [f'<path d="M{x + 22} {ry + 34} H{x + w - 22}" stroke="{LINE}"/>']

    # Six deterministic controls.
    x, y, w, h = 348, 196, 422, 398
    out += [box(x, y, w, h), text(x + 22, y + 34, "DETERMINISTIC POLICY ENGINE", size=11, fill=MUTED, weight=700, family=MONO, spacing=0.65)]
    out += [pill(x + 300, y + 31, "FIRST BLOCK WINS", color=GREEN, bg=MINT)]
    controls = [
        ("01", "Role-based access", "Role scope"),
        ("02", "Purpose of use", "Purpose + reason"),
        ("03", "Sensitivity tier", "Patient category"),
        ("04", "BAA registry", "Approved destination"),
        ("05", "PHI content scan", "Outbound content"),
        ("06", "Minimum necessary", "Request + session rate"),
    ]
    for i, (number, label, detail) in enumerate(controls):
        ry = y + 78 + i * 48
        out += [
            f'<circle cx="{x + 39}" cy="{ry - 5}" r="13" fill="{MINT}"/>',
            text(x + 39, ry - 1, number, size=8, fill=GREEN, weight=700, family=MONO, anchor="middle"),
            text(x + 63, ry, label, size=14, weight=650),
            text(x + w - 20, ry, detail, size=10, fill=MUTED, weight=500, family=MONO, anchor="end"),
        ]
        if i < len(controls) - 1:
            out += [f'<path d="M{x + 22} {ry + 19} H{x + w - 22}" stroke="{LINE}"/>']

    # Decision card.
    x, y, w, h = 792, 218, 264, 376
    out += [box(x, y, w, h), text(x + 22, y + 35, "DECISION", size=11, fill=MUTED, weight=700, family=MONO, spacing=0.8)]
    out += [
        box(x + 18, y + 76, w - 36, 91, fill="#eff8f3", stroke="#cde7d9", radius=14),
        f'<circle cx="{x + 43}" cy="{y + 107}" r="10" fill="{GREEN}"/>',
        text(x + 43, y + 111, "✓", size=12, fill="#ffffff", weight=700, anchor="middle"),
        text(x + 64, y + 111, "ALLOW", size=13, fill=GREEN, weight=750, family=MONO, spacing=0.7),
        text(x + 64, y + 140, "Tool may execute", size=13, weight=550),
        box(x + 18, y + 186, w - 36, 103, fill=PALE_RED, stroke="#f0cecb", radius=14),
        f'<circle cx="{x + 43}" cy="{y + 217}" r="10" fill="{RED}"/>',
        text(x + 43, y + 221, "×", size=14, fill="#ffffff", weight=700, anchor="middle"),
        text(x + 64, y + 221, "BLOCK", size=13, fill=RED, weight=750, family=MONO, spacing=0.7),
        text(x + 64, y + 250, "Tool call stops here", size=13, weight=550),
        text(x + 22, y + 326, "Outcome and rule stay deterministic.", size=11, fill=MUTED, weight=500),
    ]

    # Reviewable event card.
    x, y, w, h = 1074, 218, 318, 376
    out += [box(x, y, w, h), text(x + 22, y + 35, "AUDIT EVENT", size=11, fill=MUTED, weight=700, family=MONO, spacing=0.8)]
    out += [
        text(x + 22, y + 82, "Every decision is recorded", size=17, weight=650),
        text(x + 22, y + 109, "allow · block · warn · break-glass", size=11, fill=MUTED, family=MONO),
        box(x + 18, y + 139, w - 36, 100, fill="#132923", stroke="#132923", radius=14),
        text(x + 36, y + 171, "HMAC-SHA256 CHAIN", size=10, fill="#a8e8ca", weight=700, family=MONO, spacing=0.7),
        text(x + 36, y + 200, "event[n]  →  prev_hash", size=12, fill="#f1f7f4", family=MONO),
        text(x + 36, y + 221, "tamper check  →  verify_chain()", size=10, fill="#c5d6ce", family=MONO),
        text(x + 22, y + 275, "Disclosure report", size=13, weight=650),
        text(x + 22, y + 298, "External sends + emergency grants", size=11, fill=MUTED),
        text(x + 22, y + 324, "Exportable for review · §164.528", size=10, fill=MUTED, family=MONO),
    ]

    # Three feature cards.
    cards = [
        (48, 625, 422, "SESSION VELOCITY", "5-minute rolling window", "Warn at role budget · block at 2× budget", GREEN),
        (509, 625, 422, "BREAK-GLASS", "Scoped emergency access", "One patient + role · 20+ char justification · 15-minute expiry", AMBER),
        (970, 625, 422, "JEV ADVISORY", "Ambiguity only", "Adds annotations. Code keeps the lane and verdict.", GREEN),
    ]
    for cx, cy, cw, heading, line1, line2, color in cards:
        out += [box(cx, cy, cw, 204), f'<circle cx="{cx + 28}" cy="{cy + 31}" r="6" fill="{color}"/>']
        out += [text(cx + 45, cy + 35, heading, size=10, fill=color, weight=750, family=MONO, spacing=0.8)]
        out += [text(cx + 22, cy + 83, line1, size=17, weight=650), text(cx + 22, cy + 117, line2, size=11, fill=MUTED)]
        if heading == "JEV ADVISORY":
            out += [pill(cx + 22, cy + 163, "NO VERDICT OVERRIDE", color=GREEN, bg=MINT)]
        elif heading == "BREAK-GLASS":
            out += [pill(cx + 22, cy + 163, "FLAGGED FOR REVIEW", color=AMBER, bg=PALE_AMBER)]
        else:
            out += [pill(cx + 22, cy + 163, "REQUESTS + SENDS", color=GREEN, bg=MINT)]

    out += [
        text(48, 876, "Synthetic examples · policy checks run before the tool call · no model answer can override a block", size=11, fill=MUTED, weight=500),
        text(1392, 876, "STRANDS PHI GUARDRAILS", size=9, fill=MUTED, weight=700, family=MONO, spacing=0.8, anchor="end"),
    ]
    return svg_document("".join(out), width=1440, height=920)


def header(step: int, title_line: str, subtitle: str) -> list[str]:
    out = [background(WIDTH, HEIGHT), shield_icon()]
    out += [
        text(98, 52, "PHI GUARDRAILS", size=13, weight=750, spacing=1.5),
        text(98, 74, "SYNTHETIC FEATURE WALKTHROUGH", size=10, fill=MUTED, weight=600, family=MONO, spacing=0.65),
        pill(1215, 53, f"{step:02d} / 04", color=GREEN, bg=MINT),
        text(56, 133, title_line, size=30, weight=700),
        text(56, 163, subtitle, size=14, fill=MUTED, weight=450),
    ]
    return out


def request_card(*, unknown_vendor: bool = False) -> list[str]:
    x, y, w, h = 54, 194, 320, 444
    out = [box(x, y, w, h), text(x + 22, y + 34, "REQUEST CONTEXT", size=10, fill=MUTED, weight=700, family=MONO, spacing=0.8)]
    if unknown_vendor:
        rows = [
            ("ACTOR", "Physician"),
            ("PURPOSE", "Treatment"),
            ("TOOL", "send_data_to_vendor"),
            ("DESTINATION", "healthstart-ai"),
        ]
        summary = "Separate example: an unknown destination."
    else:
        rows = [
            ("ACTOR", "Registered nurse"),
            ("PURPOSE", "Treatment"),
            ("TOOL", "query_patient_record"),
            ("RECORD", "P003 · restricted tier"),
        ]
        summary = "Synthetic request. No real patient data."
    for i, (label, value) in enumerate(rows):
        ry = y + 87 + i * 69
        out += [text(x + 22, ry, label, size=9, fill=MUTED, weight=700, family=MONO, spacing=0.7)]
        out += [text(x + 22, ry + 24, value, size=12 if i >= 2 else 14, weight=600, family=MONO if i >= 2 else SANS)]
        if i < 3:
            out += [f'<path d="M{x + 22} {ry + 42} H{x + w - 22}" stroke="{LINE}"/>']
    out += [
        box(x + 18, y + 374, w - 36, 51, fill="#f4f8f6", stroke="#e7efeb", radius=12),
        text(x + 31, y + 405, summary, size=10, fill=MUTED, weight=500),
    ]
    return out


def policy_card(*, blocked: bool, advisory: bool = False) -> list[str]:
    x, y, w, h = 394, 194, 566, 444
    out = [box(x, y, w, h), text(x + 22, y + 34, "DETERMINISTIC CONTROL TRACE", size=10, fill=MUTED, weight=700, family=MONO, spacing=0.8)]
    if advisory:
        out += [
            box(x + 18, y + 67, w - 36, 91, fill=PALE_AMBER, stroke="#f0dcaf", radius=14),
            text(x + 38, y + 97, "AMBIGUITY FLAG", size=10, fill=AMBER, weight=700, family=MONO, spacing=0.6),
            text(x + 38, y + 129, "unknown_vendor", size=18, fill=INK, weight=650, family=MONO),
            box(x + 18, y + 174, w - 36, 116, fill="#f4f8f6", stroke="#e4ede8", radius=14),
            text(x + 38, y + 206, "JEV ANNOTATION", size=10, fill=GREEN, weight=700, family=MONO, spacing=0.6),
            text(x + 38, y + 239, "Destination classified as external egress", size=14, weight=600),
            text(x + 38, y + 266, "Typed signal only · no policy authority", size=11, fill=MUTED),
            box(x + 18, y + 307, w - 36, 104, fill=PALE_RED, stroke="#f0cecb", radius=14),
            text(x + 38, y + 340, "ENGINE OUTCOME", size=10, fill=RED, weight=700, family=MONO, spacing=0.6),
            text(x + 38, y + 376, "BLOCKED · escalate for review", size=16, fill=RED, weight=700),
            text(x + 38, y + 397, "Jev cannot change the outcome, rule, or reason.", size=10, fill=MUTED),
        ]
        return out

    controls = [
        ("01", "Role authorization", "PASS", "pass"),
        ("02", "Purpose of use", "PASS", "pass"),
        ("03", "Sensitivity tier", "BLOCK" if blocked else "CHECK", "block" if blocked else "check"),
        ("04", "BAA registry", "SKIP" if blocked else "WAIT", "skip" if blocked else "wait"),
        ("05", "PHI content scan", "SKIP" if blocked else "WAIT", "skip" if blocked else "wait"),
        ("06", "Minimum necessary", "SKIP" if blocked else "WAIT", "skip" if blocked else "wait"),
    ]
    for i, (number, label, status, kind) in enumerate(controls):
        ry = y + 91 + i * 50
        color, tint = {
            "pass": (GREEN, MINT),
            "block": (RED, PALE_RED),
            "skip": (MUTED, "#eef2f0"),
            "check": (AMBER, PALE_AMBER),
            "wait": (MUTED, "#eef2f0"),
        }[kind]
        out += [
            f'<circle cx="{x + 39}" cy="{ry - 5}" r="12" fill="{tint}"/>',
            text(x + 39, ry - 2, number, size=8, fill=color, weight=700, family=MONO, anchor="middle"),
            text(x + 63, ry, label, size=14, weight=600),
            pill(x + w - 105, ry - 1, status, color=color, bg=tint),
        ]
        if i < 5:
            out += [f'<path d="M{x + 22} {ry + 18} H{x + w - 22}" stroke="{LINE}"/>']
    return out


def result_card(step: int) -> list[str]:
    x, y, w, h = 980, 194, 406, 444
    out = [box(x, y, w, h), text(x + 22, y + 34, "OUTCOME", size=10, fill=MUTED, weight=700, family=MONO, spacing=0.8)]
    if step == 1:
        out += [
            box(x + 18, y + 70, w - 36, 138, fill="#f4f8f6", stroke="#e4ede8", radius=14),
            pill(x + 38, y + 104, "HELD AT THE GATE", color=AMBER, bg=PALE_AMBER),
            text(x + 38, y + 154, "No tool has run yet.", size=19, weight=650),
            text(x + 38, y + 181, "Policy checks happen before execution.", size=11, fill=MUTED),
            text(x + 22, y + 260, "MODEL ROLE", size=9, fill=MUTED, weight=700, family=MONO),
            text(x + 22, y + 286, "Requests a tool. Does not grant access.", size=13, weight=550),
        ]
    elif step == 2:
        out += [
            box(x + 18, y + 70, w - 36, 150, fill=PALE_RED, stroke="#f0cecb", radius=14),
            pill(x + 38, y + 104, "BLOCKED", color=RED, bg="#f7d8d5"),
            text(x + 38, y + 158, "Sensitivity Tier: Access Denied", size=16, weight=700),
            text(x + 38, y + 190, "The restricted record is out of scope.", size=11, fill=MUTED),
            text(x + 22, y + 270, "TOOL EXECUTION", size=9, fill=MUTED, weight=700, family=MONO),
            text(x + 22, y + 298, "query_patient_record  ·  not called", size=12, fill=RED, weight=650, family=MONO),
        ]
    elif step == 3:
        out += [
            box(x + 18, y + 70, w - 36, 150, fill="#132923", stroke="#132923", radius=14),
            text(x + 38, y + 108, "POLICY_EVAL", size=10, fill="#a8e8ca", weight=700, family=MONO, spacing=0.7),
            text(x + 38, y + 146, "outcome    BLOCKED", size=13, fill="#f1f7f4", family=MONO),
            text(x + 38, y + 177, "rule       Sensitivity Tier", size=11, fill="#c5d6ce", family=MONO),
            text(x + 38, y + 203, "chain      HMAC-SHA256", size=11, fill="#c5d6ce", family=MONO),
            text(x + 22, y + 269, "REVIEW", size=9, fill=MUTED, weight=700, family=MONO),
            text(x + 22, y + 296, "Verify edits, deletions, and ordering.", size=12, weight=550),
            text(x + 22, y + 327, "Disclosure report can be exported.", size=11, fill=MUTED),
        ]
    else:
        out += [
            box(x + 18, y + 70, w - 36, 150, fill=PALE_AMBER, stroke="#f0dcaf", radius=14),
            pill(x + 38, y + 104, "ESCALATE", color=AMBER, bg="#fae6bd"),
            text(x + 38, y + 158, "Jev adds an annotation.", size=17, weight=650),
            text(x + 38, y + 190, "The engine's block stays in force.", size=11, fill=MUTED),
            text(x + 22, y + 270, "CONTROL OWNER", size=9, fill=MUTED, weight=700, family=MONO),
            text(x + 22, y + 298, "Policy code sets lane + verdict.", size=13, weight=600),
            text(x + 22, y + 328, "No model override branch exists.", size=11, fill=MUTED),
        ]
    return out


def build_frame(step: int) -> str:
    titles = {
        1: ("A request reaches policy before a tool.", "The model proposes an action. The policy engine receives structured context."),
        2: ("The first failing control stops execution.", "A nurse requests a restricted record. The sensitivity check blocks the call."),
        3: ("The decision leaves a verifiable trail.", "The audit chain records the block and supports disclosure review."),
        4: ("Jev annotates ambiguity. Policy keeps the verdict.", "For a separate unknown-vendor case, Jev adds context without changing the block."),
    }
    title_line, subtitle = titles[step]
    out = header(step, title_line, subtitle)
    out += request_card(unknown_vendor=(step == 4))
    out += policy_card(blocked=(step in (2, 3)), advisory=(step == 4))
    out += result_card(step)

    # Fixed feature ribbon connects the animated case to the rest of the demo.
    out += [box(54, 669, 1332, 127, fill="#132923", stroke="#132923", radius=18)]
    ribbon = [
        (78, "SESSION VELOCITY", "5-minute rolling window", "#a8e8ca"),
        (505, "BREAK-GLASS", "Scoped · 20+ char justification · 15-minute expiry", "#f3d59b"),
        (965, "POLICY MATRIX", "16 synthetic regression cases", "#a8e8ca"),
    ]
    for x, heading, detail, color in ribbon:
        out += [
            f'<circle cx="{x + 5}" cy="{710}" r="5" fill="{color}"/>',
            text(x + 20, 714, heading, size=9, fill=color, weight=700, family=MONO, spacing=0.65),
            text(x, 750, detail, size=12, fill="#f1f7f4", weight=550),
        ]
    out += [
        text(54, 830, "Synthetic walkthrough · no real patient data", size=10, fill=MUTED, weight=500),
        text(1386, 830, "DECISION FLOW  /  FEATURES", size=9, fill=MUTED, weight=700, family=MONO, spacing=0.6, anchor="end"),
    ]
    return svg_document("".join(out), width=WIDTH, height=HEIGHT)


def main() -> None:
    FRAMES.mkdir(parents=True, exist_ok=True)
    (DOCS / "control-path.svg").write_text(build_control_path(), encoding="utf-8")
    for step in range(1, 5):
        (FRAMES / f"demo-{step:02d}.svg").write_text(build_frame(step), encoding="utf-8")

    output = DOCS / "demo.gif"
    renderer = ROOT / "scripts" / "render_svg_to_png.swift"
    with tempfile.TemporaryDirectory(prefix="phi-readme-visuals-") as temp:
        temp_dir = Path(temp)
        for step in range(1, 5):
            source = FRAMES / f"demo-{step:02d}.svg"
            target = temp_dir / f"frame-{step:02d}.png"
            subprocess.run(["swift", str(renderer), str(source), str(target)], check=True, capture_output=True)
        cmd = [
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
            "-framerate", "1", "-start_number", "1",
            "-i", str(temp_dir / "frame-%02d.png"),
            "-filter_complex", "[0:v]split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=3",
            "-loop", "0", str(output),
        ]
        subprocess.run(cmd, check=True)
    print(f"Wrote {DOCS / 'control-path.svg'}")
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
