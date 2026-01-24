#!/usr/bin/env python3
# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0
"""
Render a short TBOM demo video from the showcase log using ffmpeg.
Outputs an MP4 in build/showcase/ by default.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import textwrap
from pathlib import Path
from typing import Iterable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
WIDTH = 1280
HEIGHT = 720
BG_COLOR = "0x0c1f2a"
ACCENT = "0x0b7285"
ACCENT2 = "0xf29f05"


def run(cmd: list[str]) -> None:
    result = subprocess.run(cmd, cwd=str(REPO_ROOT), check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(shlex.quote(c) for c in cmd)}\n{result.stderr}")


def ensure_showcase(showcase_dir: Path, strict: bool) -> None:
    demo_log = showcase_dir / "demo.log"
    if demo_log.exists():
        return
    cmd = [str(REPO_ROOT / "scripts" / "showcase.py"), "--output-dir", str(showcase_dir)]
    if strict:
        cmd.append("--strict")
    venv_python = REPO_ROOT / ".venv" / "bin" / "python"
    python_cmd = str(venv_python) if venv_python.exists() else "python3"
    run([python_cmd] + cmd)


def scrub_paths(line: str) -> str:
    repo_root = str(REPO_ROOT)
    line = line.replace(repo_root + "/", "")
    line = line.replace(repo_root, ".")
    line = line.replace(".venv/bin/python", "python")
    line = line.replace("python3", "python")
    line = line.replace("'", "")
    return line


def sanitize_line(line: str) -> str:
    line = scrub_paths(line)
    replacements = {
        "✓": "OK",
        "✗": "X",
        "–": "-",
        "—": "-",
    }
    for old, new in replacements.items():
        line = line.replace(old, new)
    return line.encode("ascii", "replace").decode("ascii")


def wrap_lines(lines: Iterable[str], width: int) -> list[str]:
    wrapped: list[str] = []
    for line in lines:
        line = sanitize_line(line.rstrip())
        if not line:
            wrapped.append("")
            continue
        chunks = textwrap.wrap(line, width=width, replace_whitespace=False, drop_whitespace=False)
        wrapped.extend(chunks if chunks else [""])
    return wrapped


def parse_sections(demo_log: Path) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    current_title = ""
    for line in demo_log.read_text(encoding="utf-8").splitlines():
        if line.startswith("== ") and line.endswith(" =="):
            current_title = line.strip("= ").strip()
            current = sections.setdefault(current_title, [])
            continue
        if current is not None:
            current.append(line)
    return sections


def pick_font() -> str | None:
    candidates = [
        "/System/Library/Fonts/Menlo.ttc",
        "/Library/Fonts/Menlo.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return path
    return None


def escape_drawtext(text: str) -> str:
    text = text.replace("\\", "\\\\")
    text = text.replace(":", "\\:")
    text = text.replace("'", "\\'")
    text = text.replace("%", "\\%")
    return text


def clamp_lines(lines: Sequence[str], limit: int) -> list[str]:
    return list(lines[:limit])


def format_metric(label: str, value: str | None) -> str | None:
    if not value:
        return None
    return f"{label}: {value}"


def render_slide(
    output_path: Path,
    title: str,
    body_lines: list[str],
    duration: float,
    terminal_mode: bool,
    subtitle: str | None = None,
    badge: str | None = None,
) -> None:
    title_text = escape_drawtext(sanitize_line(title))
    subtitle_text = escape_drawtext(sanitize_line(subtitle)) if subtitle else ""
    fontfile = pick_font()
    textfile = output_path.with_suffix(".txt")
    textfile.write_text("\n".join(body_lines) + "\n", encoding="utf-8")

    drawtext_font = f"fontfile='{fontfile}':" if fontfile else ""
    filters: list[str] = []
    filters.append(f"drawbox=x=0:y=0:w={WIDTH}:h=6:color={ACCENT2}@0.95:t=fill")
    progress = f"w={WIDTH}*min(t/{duration}\\,1)"
    filters.append(f"drawbox=x=0:y={HEIGHT - 12}:{progress}:h=12:color={ACCENT}@0.9:t=fill")
    filters.append(
        f"drawtext={drawtext_font}text='{title_text}':fontcolor=white:fontsize=50:x=60:y=55"
    )
    if subtitle_text:
        filters.append(
            f"drawtext={drawtext_font}text='{subtitle_text}':fontcolor=white@0.85:fontsize=24:x=60:y=112"
        )
    filters.append(
        f"drawtext={drawtext_font}text='TBOM v1.0.2':fontcolor=white@0.35:fontsize=16:x=1000:y=680"
    )

    if badge:
        badge_text = escape_drawtext(sanitize_line(badge))
        filters.append("drawbox=x=980:y=50:w=220:h=34:color=0x101a20@0.85:t=fill")
        filters.append("drawbox=x=980:y=50:w=220:h=34:color=0xffffff@0.15:t=2")
        filters.append(
            f"drawtext={drawtext_font}text='{badge_text}':fontcolor=white:fontsize=18:x=1000:y=58"
        )

    if terminal_mode:
        filters.append("drawbox=x=72:y=172:w=1140:h=470:color=0x000000@0.35:t=fill")
        filters.append("drawbox=x=60:y=160:w=1160:h=490:color=0x11161b@0.97:t=fill")
        filters.append("drawbox=x=60:y=160:w=1160:h=490:color=0xffffff@0.12:t=2")
        filters.append("drawbox=x=60:y=160:w=1160:h=32:color=0x1a232a@0.9:t=fill")
        filters.append(
            f"drawtext={drawtext_font}text='tbomctl':fontcolor=white@0.7:fontsize=18:x=90:y=166"
        )
        filters.append(
            f"drawtext={drawtext_font}textfile='{textfile}':fontcolor=white:fontsize=22:x=90:y=210:line_spacing=6"
        )
    else:
        filters.append(
            f"drawtext={drawtext_font}textfile='{textfile}':fontcolor=white:fontsize=26:x=60:y=170:line_spacing=10"
        )

    filters.append(f"fade=t=in:st=0:d=0.4,fade=t=out:st={max(duration - 0.6, 0)}:d=0.4")

    cmd = [
        "ffmpeg",
        "-y",
        "-f",
        "lavfi",
        "-i",
        f"color=c={BG_COLOR}:s={WIDTH}x{HEIGHT}:d={duration}",
        "-vf",
        ",".join(filters),
        "-r",
        "30",
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        str(output_path),
    ]
    run(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render TBOM demo video from showcase log")
    parser.add_argument("--output", default="build/showcase/tbom-demo.mp4", help="Output MP4 path")
    parser.add_argument("--showcase-dir", default="build/showcase", help="Showcase output directory")
    parser.add_argument("--strict", action="store_true", help="Run showcase in strict mode if needed")
    args = parser.parse_args()

    if subprocess.run(["ffmpeg", "-version"], capture_output=True, text=True).returncode != 0:
        raise SystemExit("ffmpeg is required to render the demo video.")

    showcase_dir = Path(args.showcase_dir)
    showcase_dir.mkdir(parents=True, exist_ok=True)
    ensure_showcase(showcase_dir, args.strict)

    demo_log = showcase_dir / "demo.log"
    if not demo_log.exists():
        raise SystemExit(f"Missing demo log at {demo_log}")

    sections = parse_sections(demo_log)
    metrics_path = showcase_dir / "metrics.json"
    metrics: Mapping[str, object] = {}
    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

    ai_summary = metrics.get("aiEval") if isinstance(metrics, Mapping) else None
    mutation_summary = metrics.get("mutation") if isinstance(metrics, Mapping) else None
    ai_text = None
    mutation_text = None
    if isinstance(ai_summary, Mapping):
        total = ai_summary.get("total")
        passed = ai_summary.get("passed")
        if isinstance(total, int) and isinstance(passed, int):
            ai_text = f"{passed}/{total} passed"
    if isinstance(mutation_summary, Mapping):
        score = mutation_summary.get("score")
        if isinstance(score, (int, float)):
            mutation_text = f"{score * 100:.0f}% killed"

    slides_dir = showcase_dir / "slides"
    slides_dir.mkdir(parents=True, exist_ok=True)

    intro_lines = wrap_lines(
        [
            "Trustable tool metadata for MCP.",
            "Proves what shipped. Detects drift in seconds.",
            "",
            "build -> sign -> verify -> trust",
        ],
        width=56,
    )
    render_slide(
        slides_dir / "slide-1.mp4",
        "TBOM demo",
        intro_lines,
        5.5,
        False,
        subtitle="A 60-second walkthrough",
        badge="STEP 1/8",
    )

    problem_lines = wrap_lines(
        [
            "Problem: tool metadata is a control plane.",
            "Small text changes can silently change behavior.",
            "Traditional SBOMs do not cover tool semantics.",
        ],
        width=60,
    )
    render_slide(
        slides_dir / "slide-2.mp4",
        "Why TBOM exists",
        problem_lines,
        5.0,
        False,
        subtitle="Metadata drift is a risk multiplier",
        badge="STEP 2/8",
    )

    solution_lines = wrap_lines(
        [
            "TBOM signs tool definitions + digests.",
            "Verifier compares live tools to signed metadata.",
            "Mismatch => DRIFT and policy block.",
        ],
        width=60,
    )
    render_slide(
        slides_dir / "slide-3.mp4",
        "How it works",
        solution_lines,
        5.0,
        False,
        subtitle="build -> sign -> verify -> trust",
        badge="STEP 3/8",
    )

    verify_lines = wrap_lines(sections.get("Verify TBOM", ["(no log output)"]), width=70)
    render_slide(
        slides_dir / "slide-4.mp4",
        "Verify the TBOM",
        clamp_lines(verify_lines, 18),
        6.0,
        True,
        subtitle="Schema + digest verification",
        badge="STEP 4/8",
    )

    drift_ok_lines = wrap_lines(sections.get("Drift Check (expected OK)", ["(no log output)"]), width=70)
    render_slide(
        slides_dir / "slide-5.mp4",
        "Drift check (expected OK)",
        clamp_lines(drift_ok_lines, 18),
        6.0,
        True,
        subtitle="Live tools match signed metadata",
        badge="STEP 5/8",
    )

    drift_lines = wrap_lines(sections.get("Drift Check (expected DRIFT)", ["(no log output)"]), width=70)
    render_slide(
        slides_dir / "slide-6.mp4",
        "Drift detected",
        clamp_lines(drift_lines, 18),
        6.0,
        True,
        subtitle="Any change is immediately visible",
        badge="STEP 6/8",
    )

    evidence_lines = [
        "Evidence pack includes:",
        "- demo.log",
        "- metrics.json",
        "- ai-eval.json",
        "- mutation-report.json (strict mode)",
        "- tbom-demo.mp4",
        "",
    ]
    ai_metric = format_metric("AI evals", ai_text)
    mutation_metric = format_metric("Mutation score", mutation_text)
    if ai_metric:
        evidence_lines.append(ai_metric)
    if mutation_metric:
        evidence_lines.append(mutation_metric)
    evidence_lines.append("Output: build/showcase/")
    render_slide(
        slides_dir / "slide-7.mp4",
        "Evidence pack",
        wrap_lines(evidence_lines, width=56),
        5.5,
        False,
        subtitle="Logs + metrics in one bundle",
        badge="STEP 7/8",
    )

    closing_lines = wrap_lines(
        [
            "Re-run anytime:",
            "make showcase-strict",
            "make demo-video",
            "",
            "Output: build/showcase/tbom-demo.mp4",
        ],
        width=56,
    )
    render_slide(
        slides_dir / "slide-8.mp4",
        "Ready to share",
        closing_lines,
        4.5,
        False,
        subtitle="Single-command demo replay",
        badge="STEP 8/8",
    )

    concat_list = slides_dir / "concat.txt"
    concat_list.write_text(
        "\n".join(
            [
                "file slide-1.mp4",
                "file slide-2.mp4",
                "file slide-3.mp4",
                "file slide-4.mp4",
                "file slide-5.mp4",
                "file slide-6.mp4",
                "file slide-7.mp4",
                "file slide-8.mp4",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            "ffmpeg",
            "-y",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(concat_list),
            "-c",
            "copy",
            str(output_path),
        ]
    )

    print(f"Demo video written to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
