from pathlib import Path


def test_makefile_has_coverage_target():
    text = Path("Makefile").read_text(encoding="utf-8")
    assert "coverage:" in text
    assert "--cov-fail-under=100" in text
