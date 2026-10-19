from pathlib import Path

from sentinel.sandbox import SentinelSandboxAdapter


def test_adapter_runs_app_tests_against_patch_and_exposes_diagnostics(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "tests").mkdir()
    (source / "tests" / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_value():\n    assert VALUE == 'patched'\n",
        encoding="utf-8",
    )
    (source / "app.py").write_text("VALUE = 'original'\n", encoding="utf-8")

    result = SentinelSandboxAdapter(source).run({"app.py": "VALUE = 'patched'\n"})

    assert result.passed is True
    assert result.return_code == 0
    assert "1 passed" in result.stdout
    assert result.stderr == ""
    assert result.temp_path.is_dir()
    assert (source / "app.py").read_text(encoding="utf-8") == "VALUE = 'original'\n"


def test_adapter_reports_failed_tests_without_changing_source(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "tests").mkdir()
    (source / "tests" / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_value():\n    assert VALUE == 'patched'\n",
        encoding="utf-8",
    )
    original = source / "app.py"
    original.write_text("VALUE = 'original'\n", encoding="utf-8")

    result = SentinelSandboxAdapter(source).run({"app.py": "VALUE = 'still wrong'\n"})

    assert result.passed is False
    assert result.return_code != 0
    assert result.diagnostics
    assert original.read_text(encoding="utf-8") == "VALUE = 'original'\n"
