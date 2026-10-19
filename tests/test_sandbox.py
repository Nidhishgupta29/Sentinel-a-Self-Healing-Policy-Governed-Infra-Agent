import sys
from pathlib import Path

from sandbox.runner import LocalSandboxRunner


def test_runner_executes_command_against_patched_copy(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    module = source / "message.py"
    module.write_text("MESSAGE = 'original'\n", encoding="utf-8")

    result = LocalSandboxRunner().run(
        source_dir=source,
        patches={"message.py": "MESSAGE = 'patched'\n"},
        command=[sys.executable, "-c", "from message import MESSAGE; print(MESSAGE)"],
    )

    assert result.return_code == 0
    assert result.stdout.strip() == "patched"
    assert result.stderr == ""
    assert result.temp_path.is_dir()


def test_runner_executes_pytest_against_patched_copy(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "value.py").write_text("VALUE = 'original'\n", encoding="utf-8")
    (source / "test_value.py").write_text(
        "from value import VALUE\n\n\n"
        "def test_value_is_patched():\n"
        "    assert VALUE == 'patched'\n",
        encoding="utf-8",
    )

    result = LocalSandboxRunner().run(
        source_dir=source,
        patches={"value.py": "VALUE = 'patched'\n"},
        command=[sys.executable, "-m", "pytest", "-q"],
    )

    assert result.return_code == 0
    assert "1 passed" in result.stdout


def test_runner_captures_failed_execution(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()

    result = LocalSandboxRunner().run(
        source_dir=source,
        patches={},
        command=[
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)",
        ],
    )

    assert result.return_code == 7
    assert result.stdout.strip() == "out"
    assert result.stderr.strip() == "err"
    assert result.temp_path.is_dir()


def test_runner_never_mutates_source_even_when_patch_execution_fails(
    tmp_path: Path,
):
    source = tmp_path / "source"
    source.mkdir()
    original = source / "module.py"
    original.write_text("VALUE = 'original'\n", encoding="utf-8")

    result = LocalSandboxRunner().run(
        source_dir=source,
        patches={"module.py": "VALUE = 'patched'\n"},
        command=[
            sys.executable,
            "-c",
            "from pathlib import Path; Path('module.py').write_text('sandbox change'); raise SystemExit(1)",
        ],
    )

    assert result.return_code == 1
    assert original.read_text(encoding="utf-8") == "VALUE = 'original'\n"
    assert (result.temp_path / "module.py").read_text(encoding="utf-8") == "sandbox change"
