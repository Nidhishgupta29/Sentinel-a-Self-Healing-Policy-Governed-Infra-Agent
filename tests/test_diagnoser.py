import pytest

from sentinel.detector.detector import Anomaly
from sentinel.diagnoser.diagnoser import DiagnosisError, Diagnoser


class FakeLLM:
    def __init__(self, response: str):
        self.response = response
        self.prompts: list[str] = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.response


def anomaly() -> Anomaly:
    return Anomaly(
        fault="sql_injection", severity="critical", evidence="OR 1=1 --", source="log"
    )


def test_diagnoser_calls_injected_client_and_returns_root_cause_and_confidence():
    llm = FakeLLM('{"root_cause":"Raw SQL interpolates request input", "confidence":97}')

    diagnosis = Diagnoser(llm).diagnose(anomaly())

    assert diagnosis.root_cause == "Raw SQL interpolates request input"
    assert diagnosis.confidence == 97
    assert llm.prompts and "OR 1=1" in llm.prompts[0]


@pytest.mark.parametrize(
    "response",
    [
        "not json",
        '{"root_cause":"missing confidence"}',
        '{"root_cause":"bad confidence", "confidence":101}',
    ],
)
def test_diagnoser_rejects_invalid_llm_responses(response: str):
    with pytest.raises(DiagnosisError):
        Diagnoser(FakeLLM(response)).diagnose(anomaly())
