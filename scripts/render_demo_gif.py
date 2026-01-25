#!/usr/bin/env python3
# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0
"""
Render a short teaser GIF from the TBOM demo video using ffmpeg.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def run(cmd: list[str]) -> None:
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a teaser GIF from the demo video")
    parser.add_argument("--input", default="build/showcase/tbom-demo.mp4", help="Input MP4")
    parser.add_argument("--output", default="build/showcase/tbom-demo.gif", help="Output GIF")
    parser.add_argument("--start", type=float, default=0.0, help="Start time in seconds")
    parser.add_argument("--duration", type=float, default=12.0, help="Duration in seconds")
    parser.add_argument("--fps", type=int, default=12, help="Frames per second")
    parser.add_argument("--width", type=int, default=960, help="Output width in pixels")
    args = parser.parse_args()

    if subprocess.run(["ffmpeg", "-version"], capture_output=True, text=True).returncode != 0:
        raise SystemExit("ffmpeg is required to render the demo GIF.")

    input_path = Path(args.input)
    if not input_path.exists():
        raise SystemExit(f"Missing input video at {input_path}")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    palette = output_path.with_suffix(".palette.png")
    vf_base = f"fps={args.fps},scale={args.width}:-1:flags=lanczos"
    run(
        [
            "ffmpeg",
            "-y",
            "-ss",
            str(args.start),
            "-t",
            str(args.duration),
            "-i",
            str(input_path),
            "-vf",
            f"{vf_base},palettegen=stats_mode=single",
            "-frames:v",
            "1",
            str(palette),
        ]
    )
    run(
        [
            "ffmpeg",
            "-y",
            "-ss",
            str(args.start),
            "-t",
            str(args.duration),
            "-i",
            str(input_path),
            "-i",
            str(palette),
            "-lavfi",
            f"{vf_base}[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=5",
            str(output_path),
        ]
    )

    print(f"Demo GIF written to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
