import json
from pathlib import Path

import pytest

import scripts.render_demo_gif as render_demo_gif
import scripts.render_demo_video as render_demo_video


def test_render_demo_gif_missing_input(monkeypatch, tmp_path):
    class Result:
        returncode = 0
        stderr = ""

    monkeypatch.setattr(render_demo_gif.subprocess, "run", lambda *a, **k: Result())
    with pytest.raises(SystemExit):
        render_demo_gif.main(["--input", str(tmp_path / "missing.mp4")])


def test_render_demo_gif_success(monkeypatch, tmp_path):
    input_path = tmp_path / "demo.mp4"
    input_path.write_bytes(b"x")

    class Result:
        returncode = 0
        stderr = ""

    monkeypatch.setattr(render_demo_gif.subprocess, "run", lambda *a, **k: Result())
    monkeypatch.setattr(render_demo_gif, "run", lambda cmd: None)
    assert render_demo_gif.main(["--input", str(input_path), "--output", str(tmp_path / "out.gif")]) == 0


def test_render_demo_gif_run_error(monkeypatch):
    class Result:
        returncode = 1
        stderr = "boom"

    monkeypatch.setattr(render_demo_gif.subprocess, "run", lambda *a, **k: Result())
    with pytest.raises(RuntimeError):
        render_demo_gif.run(["ffmpeg", "-version"])


def test_render_demo_video_parse_size():
    assert render_demo_video.parse_size("101x99") == (102, 100)
    with pytest.raises(ValueError):
        render_demo_video.parse_size("bad")


def test_format_metric():
    assert render_demo_video.format_metric("x", None) is None
    assert render_demo_video.format_metric("x", "1") == "x: 1"


def test_sanitize_line():
    line = "✓ ok — test"
    assert "OK" in render_demo_video.sanitize_line(line)


def test_wrap_lines_ascii():
    lines = render_demo_video.wrap_lines(["hello\n"], width=10)
    assert lines[0].strip() == "hello"


def test_pick_font_none(monkeypatch):
    monkeypatch.setattr(render_demo_video.Path, "exists", lambda *_a, **_k: False)
    assert render_demo_video.pick_font() is None


def test_find_tts_engine_none(monkeypatch):
    monkeypatch.setattr(render_demo_video.shutil, "which", lambda *_a, **_k: None)
    assert render_demo_video.find_tts_engine(None, None) is None


def test_find_tts_engine_say(monkeypatch):
    def which(cmd):
        return "/bin/say" if cmd == "say" else None

    monkeypatch.setattr(render_demo_video.shutil, "which", which)
    engine = render_demo_video.find_tts_engine("Alex", 180)
    assert engine is not None and engine.name == "say"


def test_synthesize_tts_paths(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(render_demo_video, "run", lambda cmd: calls.append(cmd))
    engine = render_demo_video.TTSEngine(name="say", args=["-v", "Alex"], ext="aiff")
    render_demo_video.synthesize_tts(engine, "hello", tmp_path / "out.aiff")
    engine2 = render_demo_video.TTSEngine(name="espeak", args=["-v", "en"], ext="wav")
    render_demo_video.synthesize_tts(engine2, "hello", tmp_path / "out.wav")
    assert len(calls) == 2


def test_audio_duration_invalid(monkeypatch, tmp_path):
    class Result:
        stdout = "not-a-number"

    monkeypatch.setattr(render_demo_video.subprocess, "run", lambda *a, **k: Result())
    assert render_demo_video.audio_duration(tmp_path / "x.wav") == 0.0


def test_render_voiceover_modes(monkeypatch, tmp_path):
    monkeypatch.setattr(render_demo_video, "find_tts_engine", lambda *_a, **_k: None)
    assert render_demo_video.render_voiceover(["x"], [1.0], tmp_path, "off", None, None) is None
    assert render_demo_video.render_voiceover(["x"], [1.0], tmp_path, "auto", None, None) is None
    with pytest.raises(SystemExit):
        render_demo_video.render_voiceover(["x"], [1.0], tmp_path, "on", None, None)


def test_render_voiceover_success(monkeypatch, tmp_path):
    engine = render_demo_video.TTSEngine(name="say", args=[], ext="aiff")
    monkeypatch.setattr(render_demo_video, "find_tts_engine", lambda *_a, **_k: engine)
    monkeypatch.setattr(render_demo_video, "synthesize_tts", lambda *a, **k: None)
    monkeypatch.setattr(render_demo_video, "normalize_audio", lambda *a, **k: None)
    monkeypatch.setattr(render_demo_video, "audio_duration", lambda *a, **k: 0.0)
    monkeypatch.setattr(render_demo_video, "pad_audio", lambda *a, **k: None)
    monkeypatch.setattr(render_demo_video, "concat_audio", lambda *a, **k: None)

    out = render_demo_video.render_voiceover(["hi"], [1.0], tmp_path, "auto", None, None)
    assert out is not None


def test_render_slide_variants(monkeypatch, tmp_path):
    monkeypatch.setattr(render_demo_video, "run", lambda *a, **k: None)
    layout = render_demo_video.make_layout(1280, 720)
    theme = render_demo_video.THEMES["dark"]

    render_demo_video.render_slide(
        tmp_path / "slide-a.mp4",
        theme,
        layout,
        "Title",
        ["line1", "line2"],
        2.0,
        terminal_mode=False,
        subtitle="Sub",
        badge="BADGE",
        reveal_lines=False,
    )
    render_demo_video.render_slide(
        tmp_path / "slide-b.mp4",
        theme,
        layout,
        "Title",
        ["$ cmd", "OK"],
        2.0,
        terminal_mode=True,
        subtitle=None,
        badge=None,
        reveal_lines=True,
    )


def test_render_demo_video_main_minimal(monkeypatch, tmp_path):
    class Result:
        returncode = 0
        stdout = "1"

    monkeypatch.setattr(render_demo_video.subprocess, "run", lambda *a, **k: Result())
    monkeypatch.setattr(render_demo_video, "run", lambda cmd: None)
    monkeypatch.setattr(render_demo_video, "render_slide", lambda *a, **k: None)
    monkeypatch.setattr(render_demo_video, "render_voiceover", lambda *a, **k: None)
    monkeypatch.setattr(render_demo_video, "ensure_showcase", lambda *a, **k: None)

    showcase_dir = tmp_path / "showcase"
    showcase_dir.mkdir()
    (showcase_dir / "demo.log").write_text("== Verify TBOM ==\nOK\n", encoding="utf-8")
    (showcase_dir / "metrics.json").write_text(json.dumps({"aiEval": {"total": 1, "passed": 1}}))

    assert (
        render_demo_video.main(
            [
                "--output",
                str(tmp_path / "out.mp4"),
                "--showcase-dir",
                str(showcase_dir),
                "--voiceover",
                "off",
            ]
        )
        == 0
    )


def test_render_demo_video_main_with_audio(monkeypatch, tmp_path):
    class Result:
        returncode = 0
        stdout = "1"

    monkeypatch.setattr(render_demo_video.subprocess, "run", lambda *a, **k: Result())
    monkeypatch.setattr(render_demo_video, "run", lambda cmd: None)
    monkeypatch.setattr(render_demo_video, "render_slide", lambda *a, **k: None)
    monkeypatch.setattr(render_demo_video, "render_voiceover", lambda *a, **k: tmp_path / "narration.wav")
    monkeypatch.setattr(render_demo_video, "ensure_showcase", lambda *a, **k: None)

    showcase_dir = tmp_path / "showcase"
    showcase_dir.mkdir()
    (showcase_dir / "demo.log").write_text("== Verify TBOM ==\nOK\n", encoding="utf-8")

    assert (
        render_demo_video.main(
            [
                "--output",
                str(tmp_path / "out.mp4"),
                "--showcase-dir",
                str(showcase_dir),
                "--voiceover",
                "auto",
                "--theme",
                "light",
            ]
        )
        == 0
    )
