from pathlib import Path

from evals.run_evals import main


def test_run_evals_executes_end_to_end(tmp_path: Path):
    output = tmp_path / "results.md"

    exit_code = main(["--output", str(output), "--runs-per-fault", "5"])

    assert exit_code == 0
    content = output.read_text(encoding="utf-8")
    assert "# Eval results" in content
    assert "| fault type | total runs | fixed | blocked | rolled_back | needs_human_review | avg time |" in content
    assert "Overall success rate:" in content
    assert "sql_injection" in content
    assert "prompt_injection_log" in content
    assert "cascading_demo" in content


def test_run_evals_can_persist_dashboard_history(tmp_path: Path):
    output = tmp_path / "results.md"
    history = tmp_path / "history"

    assert main(
        [
            "--output",
            str(output),
            "--history-dir",
            str(history),
            "--runs-per-fault",
            "5",
        ]
    ) == 0

    assert (history / "sentinel" / "policy" / "audit.sqlite3").is_file()
    assert len(list((history / "postmortems").glob("*.md"))) >= 25
