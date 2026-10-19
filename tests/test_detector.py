from pathlib import Path

import pytest

from sentinel.detector.detector import Detector, LogInput


def test_detector_returns_critical_sql_injection_anomaly_from_text():
    anomaly = Detector().detect(
        "GET /search?q=' OR 1=1 -- returned unexpected users "
        "from faults/sql_injection.py"
    )

    assert anomaly is not None
    assert anomaly.severity == "critical"
    assert anomaly.fault == "sql_injection"
    assert "OR 1=1" in anomaly.evidence


def test_detector_reads_a_log_file(tmp_path: Path):
    log = tmp_path / "application.log"
    log.write_text("faults/sql_injection.py: query failed near OR 1=1 --", encoding="utf-8")

    anomaly = Detector().detect(log)

    assert anomaly is not None
    assert anomaly.severity == "critical"


def test_detector_ignores_unrelated_logs():
    assert Detector().detect("GET /health 200 database=ok") is None


def test_detector_rejects_missing_log_input():
    with pytest.raises(TypeError):
        Detector().detect(123)  # type: ignore[arg-type]


def test_log_input_accepts_text_or_path():
    assert LogInput("plain log").text == "plain log"
