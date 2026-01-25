#!/usr/bin/env python3
# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0
"""
Render a polished TBOM demo video from the showcase log using ffmpeg.
Outputs an MP4 in build/showcase/ by default.
"""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import textwrap
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_WIDTH = 1280
BASE_HEIGHT = 720


@dataclass(frozen=True)
class Theme:
    name: str
    bg: str
    accent: str
    accent2: str
    text: str
    text_muted: str
    badge_bg: str
    badge_border: str
    terminal_bg: str
    terminal_shadow: str
    terminal_header: str
    terminal_border: str
    terminal_text: str
    terminal_title: str


THEMES: dict[str, Theme] = {
    "dark": Theme(
        name="dark",
        bg="0x0c1f2a",
        accent="0x0b7285",
        accent2="0xf29f05",
        text="white",
        text_muted="white@0.75",
        badge_bg="0x101a20@0.85",
        badge_border="0xffffff@0.15",
        terminal_bg="0x11161b@0.97",
        terminal_shadow="0x000000@0.35",
        terminal_header="0x1a232a@0.9",
        terminal_border="0xffffff@0.12",
        terminal_text="white",
        terminal_title="white@0.7",
    ),
    "light": Theme(
        name="light",
        bg="0xf7f2ea",
        accent="0x0b7285",
        accent2="0xf29f05",
        text="0x0c1f2a",
        text_muted="0x0c1f2a@0.7",
        badge_bg="0xece5db@0.95",
        badge_border="0x0c1f2a@0.15",
        terminal_bg="0xffffff@0.98",
        terminal_shadow="0x0c1f2a@0.08",
        terminal_header="0xece5db@0.95",
        terminal_border="0x0c1f2a@0.12",
        terminal_text="0x0c1f2a",
        terminal_title="0x0c1f2a@0.6",
    ),
}


@dataclass(frozen=True)
class Layout:
    width: int
    height: int
    scale: float
    margin_x: int
    title_y: int
    subtitle_y: int
    body_y: int
    title_size: int
    subtitle_size: int
    body_size: int
    terminal_size: int
    terminal_title_size: int
    badge_size: int
    watermark_size: int
    line_spacing_body: int
    line_spacing_terminal: int
    terminal_x: int
    terminal_y: int
    terminal_w: int
    terminal_h: int
    terminal_header_h: int
    terminal_shadow_x: int
    terminal_shadow_y: int
    terminal_shadow_w: int
    terminal_shadow_h: int
    terminal_text_x: int
    terminal_text_y: int
    badge_x: int
    badge_y: int
    badge_w: int
    badge_h: int
    watermark_x: int
    watermark_y: int
    top_bar_h: int
    bottom_bar_h: int


@dataclass(frozen=True)
class Slide:
    name: str
    title: str
    subtitle: str | None
    body_lines: list[str]
    duration: float
    terminal_mode: bool
    reveal_lines: bool = False


@dataclass(frozen=True)
class TTSEngine:
    name: str
    args: list[str]
    ext: str


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
    run([python_cmd, *cmd])


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
        "\u2713": "OK",
        "\u2717": "X",
        "\u2013": "-",
        "\u2014": "-",
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
    for line in demo_log.read_text(encoding="utf-8").splitlines():
        if line.startswith("== ") and line.endswith(" =="):
            current = sections.setdefault(line.strip("= ").strip(), [])
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


def escape_textfile(path: Path) -> str:
    text = str(path)
    text = text.replace("\\", "\\\\")
    text = text.replace(":", "\\:")
    text = text.replace("'", "\\'")
    return text


def clamp_lines(lines: Sequence[str], limit: int) -> list[str]:
    return list(lines[:limit])


def format_metric(label: str, value: str | None) -> str | None:
    if not value:
        return None
    return f"{label}: {value}"


def parse_size(value: str) -> tuple[int, int]:
    parts = value.lower().split("x")
    if len(parts) != 2:
        raise ValueError("size must be WIDTHxHEIGHT")
    width = int(parts[0])
    height = int(parts[1])
    if width % 2:
        width += 1
    if height % 2:
        height += 1
    return width, height


def make_layout(width: int, height: int) -> Layout:
    scale = width / BASE_WIDTH

    def s(value: int) -> int:
        return round(value * scale)

    margin_x = s(60)
    title_y = s(55)
    subtitle_y = s(112)
    body_y = s(170)

    title_size = s(50)
    subtitle_size = s(24)
    body_size = s(26)
    terminal_size = s(24)
    terminal_title_size = s(18)
    badge_size = s(18)
    watermark_size = s(16)
    line_spacing_body = s(10)
    line_spacing_terminal = s(5)

    terminal_x = s(60)
    terminal_y = s(160)
    terminal_w = width - s(120)
    terminal_h = s(490)
    terminal_header_h = s(32)
    terminal_shadow_x = s(72)
    terminal_shadow_y = s(172)
    terminal_shadow_w = width - s(140)
    terminal_shadow_h = s(470)
    terminal_text_x = s(90)
    terminal_text_y = s(210)

    badge_w = s(220)
    badge_h = s(34)
    badge_x = width - badge_w - s(60)
    badge_y = s(50)

    watermark_x = width - s(280)
    watermark_y = height - s(40)

    top_bar_h = s(6)
    bottom_bar_h = s(12)

    return Layout(
        width=width,
        height=height,
        scale=scale,
        margin_x=margin_x,
        title_y=title_y,
        subtitle_y=subtitle_y,
        body_y=body_y,
        title_size=title_size,
        subtitle_size=subtitle_size,
        body_size=body_size,
        terminal_size=terminal_size,
        terminal_title_size=terminal_title_size,
        badge_size=badge_size,
        watermark_size=watermark_size,
        line_spacing_body=line_spacing_body,
        line_spacing_terminal=line_spacing_terminal,
        terminal_x=terminal_x,
        terminal_y=terminal_y,
        terminal_w=terminal_w,
        terminal_h=terminal_h,
        terminal_header_h=terminal_header_h,
        terminal_shadow_x=terminal_shadow_x,
        terminal_shadow_y=terminal_shadow_y,
        terminal_shadow_w=terminal_shadow_w,
        terminal_shadow_h=terminal_shadow_h,
        terminal_text_x=terminal_text_x,
        terminal_text_y=terminal_text_y,
        badge_x=badge_x,
        badge_y=badge_y,
        badge_w=badge_w,
        badge_h=badge_h,
        watermark_x=watermark_x,
        watermark_y=watermark_y,
        top_bar_h=top_bar_h,
        bottom_bar_h=bottom_bar_h,
    )


def terminal_line_capacity(layout: Layout) -> int:
    line_height = layout.terminal_size + layout.line_spacing_terminal
    usable = layout.terminal_h - layout.terminal_header_h - layout.line_spacing_terminal
    return max(1, int(usable // line_height))


def terminal_slide_duration(lines: Sequence[str]) -> float:
    visible = sum(1 for line in lines if line.strip())
    return min(max(5.5, 2.5 + visible * 0.35), 11.0)


def render_slide(
    output_path: Path,
    theme: Theme,
    layout: Layout,
    title: str,
    body_lines: list[str],
    duration: float,
    terminal_mode: bool,
    subtitle: str | None = None,
    badge: str | None = None,
    reveal_lines: bool = False,
) -> None:
    title_text = escape_drawtext(sanitize_line(title))
    subtitle_text = escape_drawtext(sanitize_line(subtitle)) if subtitle else ""
    fontfile = pick_font()
    textfile_escaped = ""
    if not (terminal_mode and reveal_lines):
        textfile = output_path.with_suffix(".txt")
        textfile.write_text("\n".join(body_lines) + "\n", encoding="utf-8")
        textfile_escaped = escape_textfile(textfile)

    drawtext_font = f"fontfile='{fontfile}':" if fontfile else ""
    filters: list[str] = []

    filters.append(f"drawbox=x=0:y=0:w={layout.width}:h={layout.top_bar_h}:color={theme.accent2}@0.95:t=fill")
    progress = f"w={layout.width}*min(t/{duration}\\,1)"
    filters.append(
        f"drawbox=x=0:y={layout.height - layout.bottom_bar_h}:{progress}:h={layout.bottom_bar_h}:"
        f"color={theme.accent}@0.9:t=fill"
    )

    filters.append(
        f"drawtext={drawtext_font}text='{title_text}':fontcolor={theme.text}:fontsize={layout.title_size}:x={layout.margin_x}:y={layout.title_y}"
    )
    if subtitle_text:
        filters.append(
            f"drawtext={drawtext_font}text='{subtitle_text}':fontcolor={theme.text_muted}:fontsize={layout.subtitle_size}:x={layout.margin_x}:y={layout.subtitle_y}"
        )

    filters.append(
        f"drawtext={drawtext_font}text='TBOM v1.0.2':fontcolor={theme.text_muted}:"
        f"fontsize={layout.watermark_size}:x={layout.watermark_x}:y={layout.watermark_y}"
    )

    if badge:
        badge_text = escape_drawtext(sanitize_line(badge))
        filters.append(
            f"drawbox=x={layout.badge_x}:y={layout.badge_y}:w={layout.badge_w}:h={layout.badge_h}:color={theme.badge_bg}:t=fill"
        )
        filters.append(
            f"drawbox=x={layout.badge_x}:y={layout.badge_y}:w={layout.badge_w}:h={layout.badge_h}:color={theme.badge_border}:t=2"
        )
        badge_text_x = layout.badge_x + layout.margin_x // 3
        badge_text_y = layout.badge_y + layout.badge_h // 4
        filters.append(
            f"drawtext={drawtext_font}text='{badge_text}':fontcolor={theme.text}:"
            f"fontsize={layout.badge_size}:x={badge_text_x}:y={badge_text_y}"
        )

    if terminal_mode:
        filters.append(
            f"drawbox=x={layout.terminal_shadow_x}:y={layout.terminal_shadow_y}:w={layout.terminal_shadow_w}:h={layout.terminal_shadow_h}:color={theme.terminal_shadow}:t=fill"
        )
        filters.append(
            f"drawbox=x={layout.terminal_x}:y={layout.terminal_y}:w={layout.terminal_w}:h={layout.terminal_h}:color={theme.terminal_bg}:t=fill"
        )
        filters.append(
            f"drawbox=x={layout.terminal_x}:y={layout.terminal_y}:w={layout.terminal_w}:h={layout.terminal_h}:color={theme.terminal_border}:t=2"
        )
        filters.append(
            f"drawbox=x={layout.terminal_x}:y={layout.terminal_y}:w={layout.terminal_w}:h={layout.terminal_header_h}:color={theme.terminal_header}:t=fill"
        )
        terminal_title_y = layout.terminal_y + layout.line_spacing_terminal
        filters.append(
            f"drawtext={drawtext_font}text='tbomctl':fontcolor={theme.terminal_title}:"
            f"fontsize={layout.terminal_title_size}:x={layout.terminal_text_x}:y={terminal_title_y}"
        )
        if reveal_lines:
            line_height = layout.terminal_size + layout.line_spacing_terminal
            reveal_window = max(duration - 1.0, 0.6)
            reveal_step = reveal_window / max(len(body_lines), 1)
            start_offset = 0.4

            for idx, line in enumerate(body_lines):
                if not line.strip():
                    continue
                line_text = escape_drawtext(sanitize_line(line))
                line_upper = line.upper()
                if line.startswith("$ ") or "DRIFT" in line_upper or "ERROR" in line_upper or "X " in line_upper:
                    line_color = theme.accent2
                elif "OK" in line_upper or "NO DRIFT" in line_upper:
                    line_color = theme.accent
                else:
                    line_color = theme.terminal_text
                line_y = layout.terminal_text_y + idx * line_height
                start_time = min(start_offset + idx * reveal_step, max(duration - 0.5, 0))
                filters.append(
                    f"drawtext={drawtext_font}text='{line_text}':fontcolor={line_color}:"
                    f"fontsize={layout.terminal_size}:x={layout.terminal_text_x}:y={line_y}:"
                    f"enable='gte(t,{start_time:.2f})'"
                )
        else:
            filters.append(
                f"drawtext={drawtext_font}textfile='{textfile_escaped}':fontcolor={theme.terminal_text}:"
                f"fontsize={layout.terminal_size}:x={layout.terminal_text_x}:y={layout.terminal_text_y}:"
                f"line_spacing={layout.line_spacing_terminal}"
            )
    else:
        filters.append(
            f"drawtext={drawtext_font}textfile='{textfile_escaped}':fontcolor={theme.text}:fontsize={layout.body_size}:x={layout.margin_x}:y={layout.body_y}:line_spacing={layout.line_spacing_body}"
        )

    filters.append(f"fade=t=in:st=0:d=0.4,fade=t=out:st={max(duration - 0.6, 0)}:d=0.4")

    cmd = [
        "ffmpeg",
        "-y",
        "-f",
        "lavfi",
        "-i",
        f"color=c={theme.bg}:s={layout.width}x{layout.height}:d={duration}",
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


def find_tts_engine(voice: str | None, rate: int | None) -> TTSEngine | None:
    if shutil.which("say"):
        args = []
        if voice:
            args += ["-v", voice]
        if rate:
            args += ["-r", str(rate)]
        return TTSEngine(name="say", args=args, ext="aiff")

    if shutil.which("espeak-ng"):
        args = []
        if voice:
            args += ["-v", voice]
        if rate:
            args += ["-s", str(rate)]
        return TTSEngine(name="espeak-ng", args=args, ext="wav")

    if shutil.which("espeak"):
        args = []
        if voice:
            args += ["-v", voice]
        if rate:
            args += ["-s", str(rate)]
        return TTSEngine(name="espeak", args=args, ext="wav")

    return None


def synthesize_tts(engine: TTSEngine, text: str, output_path: Path) -> None:
    text = sanitize_line(text)
    if engine.name == "say":
        cmd = ["say", *engine.args, "-o", str(output_path), text]
    else:
        cmd = [engine.name, *engine.args, "-w", str(output_path), text]
    run(cmd)


def normalize_audio(input_path: Path, output_path: Path) -> None:
    run(
        [
            "ffmpeg",
            "-y",
            "-i",
            str(input_path),
            "-ac",
            "2",
            "-ar",
            "48000",
            str(output_path),
        ]
    )


def audio_duration(path: Path) -> float:
    result = subprocess.run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=nw=1:nk=1",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        return float(result.stdout.strip())
    except ValueError:
        return 0.0


def pad_audio(input_path: Path, output_path: Path, duration: float) -> None:
    run(
        [
            "ffmpeg",
            "-y",
            "-i",
            str(input_path),
            "-af",
            f"apad,atrim=duration={duration}",
            str(output_path),
        ]
    )


def concat_audio(segments: Sequence[Path], output_path: Path) -> None:
    concat_list = output_path.with_suffix(".txt")
    lines: list[str] = []
    for path in segments:
        resolved = str(path.resolve())
        resolved = resolved.replace("'", "\\'")
        lines.append(f"file '{resolved}'")
    concat_list.write_text("\n".join(lines) + "\n", encoding="utf-8")
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


def render_voiceover(
    narration: Sequence[str],
    durations: Sequence[float],
    output_dir: Path,
    mode: str,
    voice: str | None,
    rate: int | None,
) -> Path | None:
    if mode == "off":
        return None
    engine = find_tts_engine(voice, rate)
    if engine is None:
        if mode == "on":
            raise SystemExit("No TTS engine found. Install 'say' (macOS) or 'espeak'.")
        return None

    audio_dir = output_dir / "audio"
    audio_dir.mkdir(parents=True, exist_ok=True)
    segments: list[Path] = []

    for idx, (text, target_duration) in enumerate(zip(narration, durations), start=1):
        raw_path = audio_dir / f"narration-{idx}.{engine.ext}"
        wav_path = audio_dir / f"narration-{idx}.wav"
        padded_path = audio_dir / f"segment-{idx}.wav"
        synthesize_tts(engine, text, raw_path)
        normalize_audio(raw_path, wav_path)
        actual = audio_duration(wav_path)
        if actual <= 0:
            pad_audio(wav_path, padded_path, target_duration)
        else:
            pad_audio(wav_path, padded_path, target_duration)
        segments.append(padded_path)

    narration_path = output_dir / "narration.wav"
    concat_audio(segments, narration_path)
    return narration_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Render TBOM demo video from showcase log")
    parser.add_argument("--output", default="build/showcase/tbom-demo.mp4", help="Output MP4 path")
    parser.add_argument("--showcase-dir", default="build/showcase", help="Showcase output directory")
    parser.add_argument("--strict", action="store_true", help="Run showcase in strict mode if needed")
    parser.add_argument("--theme", choices=["dark", "light"], default="dark", help="Video theme")
    parser.add_argument("--size", default="1280x720", help="Video size (WIDTHxHEIGHT)")
    parser.add_argument(
        "--voiceover",
        choices=["auto", "on", "off"],
        default="auto",
        help="Voiceover mode (auto, on, off)",
    )
    parser.add_argument("--voice", help="TTS voice (optional)")
    parser.add_argument("--voice-rate", type=int, help="TTS rate (optional)")
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

    width, height = parse_size(args.size)
    theme = THEMES[args.theme]
    layout = make_layout(width, height)

    slides_dir = showcase_dir / "slides"
    slides_dir.mkdir(parents=True, exist_ok=True)

    slides: list[Slide] = []
    terminal_limit = terminal_line_capacity(layout)

    slides.append(
        Slide(
            name="intro",
            title="TBOM demo",
            subtitle="A 60-second walkthrough",
            body_lines=wrap_lines(
                [
                    "Trustable tool metadata for MCP.",
                    "Proves what shipped. Detects drift in seconds.",
                    "",
                    "build -> sign -> verify -> trust",
                ],
                width=56,
            ),
            duration=4.0,
            terminal_mode=False,
        )
    )

    slides.append(
        Slide(
            name="problem",
            title="Why TBOM exists",
            subtitle="Metadata drift is a risk multiplier",
            body_lines=wrap_lines(
                [
                    "Problem: tool metadata is a control plane.",
                    "Small text edits can silently change behavior.",
                    "Traditional SBOMs do not cover tool semantics.",
                ],
                width=60,
            ),
            duration=4.0,
            terminal_mode=False,
        )
    )

    slides.append(
        Slide(
            name="solution",
            title="How it works",
            subtitle="build -> sign -> verify -> trust",
            body_lines=wrap_lines(
                [
                    "TBOM signs tool definitions and digests.",
                    "Verifier compares live tools to signed metadata.",
                    "Mismatch => DRIFT and policy block.",
                ],
                width=60,
            ),
            duration=4.0,
            terminal_mode=False,
        )
    )

    verify_lines = clamp_lines(
        wrap_lines(sections.get("Verify TBOM", ["(no log output)"]), width=66),
        terminal_limit,
    )
    drift_ok_lines = clamp_lines(
        wrap_lines(sections.get("Drift Check (expected OK)", ["(no log output)"]), width=66),
        terminal_limit,
    )
    drift_lines = clamp_lines(
        wrap_lines(sections.get("Drift Check (expected DRIFT)", ["(no log output)"]), width=66),
        terminal_limit,
    )

    slides.append(
        Slide(
            name="verify",
            title="Verify the TBOM",
            subtitle="Schema + digest verification",
            body_lines=verify_lines,
            duration=terminal_slide_duration(verify_lines),
            terminal_mode=True,
            reveal_lines=True,
        )
    )

    slides.append(
        Slide(
            name="drift_ok",
            title="Drift check (expected OK)",
            subtitle="Live tools match signed metadata",
            body_lines=drift_ok_lines,
            duration=terminal_slide_duration(drift_ok_lines),
            terminal_mode=True,
            reveal_lines=True,
        )
    )

    slides.append(
        Slide(
            name="drift",
            title="Drift detected",
            subtitle="Any change is immediately visible",
            body_lines=drift_lines,
            duration=terminal_slide_duration(drift_lines),
            terminal_mode=True,
            reveal_lines=True,
        )
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

    slides.append(
        Slide(
            name="evidence",
            title="Evidence pack",
            subtitle="Logs + metrics in one bundle",
            body_lines=wrap_lines(evidence_lines, width=56),
            duration=4.5,
            terminal_mode=False,
        )
    )

    slides.append(
        Slide(
            name="closing",
            title="Ready to share",
            subtitle="Single-command demo replay",
            body_lines=wrap_lines(
                [
                    "Re-run anytime:",
                    "make showcase-strict",
                    "make demo-video",
                    "",
                    "Output: build/showcase/tbom-demo.mp4",
                ],
                width=56,
            ),
            duration=3.5,
            terminal_mode=False,
        )
    )

    total_steps = len(slides)
    for index, slide in enumerate(slides, start=1):
        badge = f"STEP {index}/{total_steps}"
        render_slide(
            slides_dir / f"slide-{index}.mp4",
            theme,
            layout,
            slide.title,
            slide.body_lines,
            slide.duration,
            slide.terminal_mode,
            subtitle=slide.subtitle,
            badge=badge,
            reveal_lines=slide.reveal_lines,
        )

    concat_list = slides_dir / "concat.txt"
    concat_list.write_text(
        "\n".join(f"file slide-{i}.mp4" for i in range(1, total_steps + 1)) + "\n",
        encoding="utf-8",
    )

    output_path = Path(args.output)
    if args.theme == "light" and args.output == "build/showcase/tbom-demo.mp4":
        output_path = Path("build/showcase/tbom-demo-light.mp4")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    base_video = output_path.with_suffix(".silent.mp4")
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
            "-movflags",
            "+faststart",
            str(base_video),
        ]
    )

    narration = [
        "TBOM makes tool metadata tamper-evident. It proves what shipped and detects drift in seconds.",
        "Metadata is a control plane. Small text edits can silently change behavior.",
        "TBOM signs tool definitions and digests. Verifiers compare live tools to signed metadata.",
        "First, validate the TBOM against the schema and internal digests.",
        "Next, confirm drift checks are clean when tools match.",
        "Now introduce drift. The digest mismatch triggers a warning.",
        "The evidence pack bundles logs, metrics, and test results.",
        "Re-run the demo anytime with a single command.",
    ]
    durations = [slide.duration for slide in slides]
    narration_path = render_voiceover(
        narration,
        durations,
        showcase_dir,
        args.voiceover,
        args.voice,
        args.voice_rate,
    )

    if narration_path:
        run(
            [
                "ffmpeg",
                "-y",
                "-i",
                str(base_video),
                "-i",
                str(narration_path),
                "-c:v",
                "copy",
                "-c:a",
                "aac",
                "-b:a",
                "192k",
                "-shortest",
                "-movflags",
                "+faststart",
                str(output_path),
            ]
        )
    else:
        run(["ffmpeg", "-y", "-i", str(base_video), "-c", "copy", str(output_path)])

    print(f"Demo video written to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
