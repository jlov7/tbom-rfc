#!/usr/bin/env python3
# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0
"""
Render a short TBOM demo video from the showcase log using ffmpeg.
Outputs an MP4 in build/showcase/ by default.
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import textwrap
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent


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


def sanitize_line(line: str) -> str:
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


def render_slide(
    output_path: Path,
    title: str,
    body_lines: list[str],
    duration: float,
    terminal_mode: bool,
) -> None:
    bg_color = "0x0c1f2a"
    title_text = sanitize_line(title)
    fontfile = pick_font()
    textfile = output_path.with_suffix(".txt")
    textfile.write_text("\n".join(body_lines) + "\n", encoding="utf-8")

    drawtext_font = f"fontfile='{fontfile}':" if fontfile else ""
    title_filter = (
        f"drawtext={drawtext_font}text='{title_text}':fontcolor=white:fontsize=48:x=60:y=50"
    )

    filters = [title_filter]
    if terminal_mode:
        filters.append("drawbox=x=60:y=140:w=1160:h=500:color=0x11161b@0.95:t=fill")
        filters.append("drawbox=x=60:y=140:w=1160:h=500:color=0xffffff@0.12:t=2")
        filters.append(
            f"drawtext={drawtext_font}textfile='{textfile}':fontcolor=white:fontsize=22:x=80:y=170:line_spacing=6"
        )
    else:
        filters.append(
            f"drawtext={drawtext_font}textfile='{textfile}':fontcolor=white:fontsize=26:x=60:y=150:line_spacing=10"
        )

    filters.append(f"fade=t=in:st=0:d=0.4,fade=t=out:st={max(duration - 0.6, 0)}:d=0.4")

    cmd = [
        "ffmpeg",
        "-y",
        "-f",
        "lavfi",
        "-i",
        f"color=c={bg_color}:s=1280x720:d={duration}",
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

    slides_dir = showcase_dir / "slides"
    slides_dir.mkdir(parents=True, exist_ok=True)

    intro_lines = wrap_lines(
        [
            "TBOM makes tool metadata tamper-evident.",
            "If anything changes after release, drift detection flags it immediately.",
            "",
            "build -> sign -> verify -> trust",
        ],
        width=52,
    )
    render_slide(slides_dir / "slide-1.mp4", "TBOM in 60 seconds", intro_lines, 5.5, False)

    verify_lines = wrap_lines(sections.get("Verify TBOM", ["(no log output)"]), width=64)
    render_slide(slides_dir / "slide-2.mp4", "Verify the TBOM", verify_lines[:18], 6.0, True)

    drift_ok_lines = wrap_lines(sections.get("Drift Check (expected OK)", ["(no log output)"]), width=64)
    render_slide(slides_dir / "slide-3.mp4", "Drift check (expected OK)", drift_ok_lines[:18], 6.0, True)

    drift_lines = wrap_lines(sections.get("Drift Check (expected DRIFT)", ["(no log output)"]), width=64)
    render_slide(slides_dir / "slide-4.mp4", "Drift detected", drift_lines[:18], 6.0, True)

    outro_lines = wrap_lines(
        [
            "Evidence pack includes:",
            "- demo.log",
            "- metrics.json",
            "- ai-eval.json",
            "- mutation-report.json (strict mode)",
            "",
            "Output: build/showcase/",
        ],
        width=52,
    )
    render_slide(slides_dir / "slide-5.mp4", "Evidence pack", outro_lines, 5.5, False)

    concat_list = slides_dir / "concat.txt"
    concat_list.write_text(
        "\n".join(
            [
                "file slide-1.mp4",
                "file slide-2.mp4",
                "file slide-3.mp4",
                "file slide-4.mp4",
                "file slide-5.mp4",
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
