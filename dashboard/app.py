"""FastAPI dashboard for historical Sentinel runs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from html import escape
from pathlib import Path
import re
from typing import Iterable

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from sentinel.policy import AuditLog


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT_LOG = PROJECT_ROOT / "sentinel" / "policy" / "audit.sqlite3"
DEFAULT_POSTMORTEMS = PROJECT_ROOT / "postmortems"
DEFAULT_RESULTS = PROJECT_ROOT / "evals" / "results.md"


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    fault_type: str
    timestamp: str
    status: str
    severity: str
    content: str
    postmortem_filename: str = ""
    actions: tuple[str, ...] = ()
    audit_events: tuple[dict[str, str], ...] = ()

    @property
    def policy_blocked(self) -> bool:
        return self.status == "blocked" or any(
            event.get("decision") == "block"
            and event.get("action", "").startswith("patch ")
            for event in self.audit_events
        )

    @property
    def rollback_occurred(self) -> bool:
        return self.status == "rolled_back" or any(
            event.get("action") == "rollback" for event in self.audit_events
        )


class DashboardStore:
    """Read-only view over audit records, postmortems, and eval summaries."""

    def __init__(
        self,
        audit_log_path: str | Path = DEFAULT_AUDIT_LOG,
        postmortems_dir: str | Path = DEFAULT_POSTMORTEMS,
        results_path: str | Path = DEFAULT_RESULTS,
    ) -> None:
        self.audit_log_path = Path(audit_log_path)
        self.postmortems_dir = Path(postmortems_dir)
        self.results_path = Path(results_path)

    def list_runs(self) -> list[RunRecord]:
        events = self._audit_events()
        records = self._postmortem_records(events)
        if not records:
            records = self._eval_records(events)
        return sorted(records, key=lambda record: (record.timestamp, record.run_id), reverse=True)

    def get_run(self, run_id: str) -> RunRecord | None:
        return next((run for run in self.list_runs() if run.run_id == run_id), None)

    def summary(self, runs: Iterable[RunRecord] | None = None) -> dict[str, float | int]:
        records = list(runs if runs is not None else self.list_runs())
        total = len(records)
        fixed = sum(record.status == "fixed" for record in records)
        blocked = sum(record.status == "blocked" for record in records)
        rolled_back = sum(record.status == "rolled_back" for record in records)
        return {
            "total": total,
            "fixed": fixed,
            "blocked": blocked,
            "rolled_back": rolled_back,
            "success_rate": (fixed / total * 100) if total else 0.0,
        }

    def read_postmortem(self, filename: str) -> str:
        if not self._safe_filename(filename):
            raise FileNotFoundError(filename)
        path = self.postmortems_dir / filename
        if not path.is_file():
            raise FileNotFoundError(filename)
        return path.read_text(encoding="utf-8")

    def _audit_events(self) -> list[dict[str, str]]:
        if not self.audit_log_path.is_file():
            return []
        try:
            return AuditLog(self.audit_log_path).query()
        except (OSError, ValueError):
            return []

    def _postmortem_records(self, events: list[dict[str, str]]) -> list[RunRecord]:
        if not self.postmortems_dir.is_dir():
            return []
        records: list[RunRecord] = []
        for path in sorted(self.postmortems_dir.rglob("*.md")):
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                continue
            record = self._parse_postmortem(path.name, content, events)
            if record is not None:
                records.append(record)
        return records

    def _parse_postmortem(
        self,
        filename: str,
        content: str,
        events: list[dict[str, str]],
    ) -> RunRecord | None:
        header = re.search(r"^# Postmortem: (.+?) — ([A-Za-z_]+)\s*$", content, re.MULTILINE)
        timestamp = re.search(r"^Timestamp:\s*(.+?)\s*$", content, re.MULTILINE)
        severity = re.search(r"^Severity:\s*(.+?)\s*$", content, re.MULTILINE)
        if header is None:
            return None
        fault_type, status = header.group(1), header.group(2)
        timestamp_value = timestamp.group(1) if timestamp else "unknown"
        actions = tuple(
            match.group(1).strip()
            for match in re.finditer(r"^-\s+(.+?)\s*$", content, re.MULTILINE)
        )
        return RunRecord(
            run_id=filename,
            fault_type=fault_type,
            timestamp=timestamp_value,
            status=status,
            severity=severity.group(1) if severity else "unknown",
            content=content,
            postmortem_filename=filename,
            actions=actions,
            audit_events=tuple(self._events_near(timestamp_value, events)),
        )

    def _eval_records(self, events: list[dict[str, str]]) -> list[RunRecord]:
        if not self.results_path.is_file():
            return []
        try:
            content = self.results_path.read_text(encoding="utf-8")
        except OSError:
            return []
        generated = re.search(r"^Generated:\s*(.+?)\s*$", content, re.MULTILINE)
        timestamp = generated.group(1) if generated else "unknown"
        records: list[RunRecord] = []
        details_started = False
        for line in content.splitlines():
            if line.startswith("## Run details"):
                details_started = True
                continue
            if not details_started or not line.startswith("|") or line.startswith("|---"):
                continue
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if len(cells) != 6 or cells[0] == "fault type":
                continue
            fault_type, variation, status, duration, policy, rollback = cells
            records.append(
                RunRecord(
                    run_id=f"eval-{fault_type}-{variation}",
                    fault_type=fault_type,
                    timestamp=timestamp,
                    status=status,
                    severity="unknown",
                    content="",
                    actions=(
                        f"Evaluation variation {variation} completed in {duration}.",
                        f"Policy blocked: {policy}; rollback occurred: {rollback}.",
                    ),
                    audit_events=tuple(events),
                )
            )
        return records

    @staticmethod
    def _events_near(timestamp: str, events: list[dict[str, str]]) -> list[dict[str, str]]:
        try:
            target = datetime.fromisoformat(timestamp)
        except ValueError:
            return []
        matched: list[dict[str, str]] = []
        for event in events:
            try:
                event_time = datetime.fromisoformat(event["timestamp"])
            except (KeyError, ValueError):
                continue
            if abs((event_time - target).total_seconds()) <= 5:
                matched.append(event)
        return matched

    @staticmethod
    def _safe_filename(filename: str) -> bool:
        path = Path(filename)
        return bool(filename) and path.name == filename and ".." not in path.parts


def _status_class(status: str) -> str:
    return {
        "fixed": "fixed",
        "blocked": "blocked",
        "rolled_back": "rolled-back",
        "needs_human_review": "human-review",
    }.get(status, "unknown")


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)} — Sentinel</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }}
    body {{ margin: 0; background: #f4f7fb; color: #172033; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 28px 20px 48px; }}
    h1, h2, h3 {{ margin-top: 0; }}
    a {{ color: #185abc; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .subtitle {{ color: #64748b; margin-top: -12px; }}
    .stats {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin: 24px 0; }}
    .stat, .card {{ background: #fff; border: 1px solid #dce3ee; border-radius: 12px; padding: 16px; box-shadow: 0 2px 8px #1b35570d; }}
    .stat strong {{ display: block; font-size: 28px; margin-top: 6px; }}
    .label {{ color: #64748b; font-size: 13px; text-transform: uppercase; letter-spacing: .04em; }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; overflow: hidden; background: #fff; border: 1px solid #dce3ee; border-radius: 12px; }}
    th, td {{ text-align: left; padding: 13px 14px; border-bottom: 1px solid #edf1f7; }}
    th {{ color: #64748b; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
    tr:last-child td {{ border-bottom: 0; }}
    .status {{ display: inline-flex; align-items: center; gap: 7px; font-weight: 650; }}
    .status::before {{ content: ""; width: 9px; height: 9px; border-radius: 50%; background: #94a3b8; }}
    .status.fixed::before {{ background: #16a34a; }}
    .status.blocked::before {{ background: #dc2626; }}
    .status.rolled-back::before {{ background: #f59e0b; }}
    .status.human-review::before {{ background: #eab308; }}
    .timeline {{ display: grid; gap: 10px; margin: 18px 0; }}
    .step {{ display: grid; grid-template-columns: 150px 1fr; gap: 12px; padding: 13px; background: #fff; border: 1px solid #dce3ee; border-radius: 10px; }}
    .step strong {{ color: #334155; }}
    pre {{ white-space: pre-wrap; background: #101827; color: #e5edf9; padding: 20px; border-radius: 12px; overflow: auto; line-height: 1.5; }}
    .empty {{ color: #64748b; padding: 20px 0; }}
    @media (max-width: 760px) {{ .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} .step {{ grid-template-columns: 1fr; }} table {{ font-size: 13px; }} }}
  </style>
</head>
<body><main>{body}</main></body>
</html>"""


def _timeline(record: RunRecord) -> list[tuple[str, str]]:
    actions = " ".join(record.actions)
    policy = "; ".join(
        f"{event.get('decision', 'unknown')}: {event.get('reason', '')}"
        for event in record.audit_events
        if event.get("action", "").startswith("patch ")
    )
    return [
        ("Detect", f"Detected {record.fault_type} ({record.severity})."),
        ("Diagnose", "Diagnosis recorded in the postmortem." if "Diagnosis" in record.content else "Diagnosis was skipped or unavailable."),
        ("Policy", policy or "No matching policy audit event recorded."),
        ("Sandbox", "Sandbox result recorded." if "sandbox" in actions.lower() else "No sandbox result recorded."),
        ("Apply", "Patch application recorded." if "applied" in actions.lower() else "No patch was applied."),
        ("Health check", "Health check and final validation recorded." if "health" in actions.lower() else "No health-check event recorded."),
        ("Rollback", "Rollback occurred." if record.rollback_occurred else "No rollback occurred."),
    ]


def create_app(
    *,
    audit_log_path: str | Path = DEFAULT_AUDIT_LOG,
    postmortems_dir: str | Path = DEFAULT_POSTMORTEMS,
    results_path: str | Path = DEFAULT_RESULTS,
) -> FastAPI:
    store = DashboardStore(audit_log_path, postmortems_dir, results_path)
    application = FastAPI(title="Sentinel Dashboard")

    @application.get("/", response_class=HTMLResponse)
    def home() -> HTMLResponse:
        runs = store.list_runs()
        stats = store.summary(runs)
        stat_cards = "".join(
            f'<div class="stat"><span class="label">{label}</span><strong>{value}</strong></div>'
            for label, value in (
                ("Total runs", stats["total"]),
                ("Success rate", f'{stats["success_rate"]:.1f}%'),
                ("Blocked", stats["blocked"]),
                ("Rollbacks", stats["rolled_back"]),
                ("Fixed", stats["fixed"]),
            )
        )
        if runs:
            rows = "".join(
                f"<tr><td><a href=\"/run/{escape(run.run_id)}\">{escape(run.fault_type)}</a></td>"
                f"<td>{escape(run.timestamp)}</td><td>{escape(run.severity)}</td>"
                f"<td><span class=\"status {_status_class(run.status)}\">{escape(run.status)}</span></td>"
                f"<td>{'yes' if run.policy_blocked else 'no'}</td>"
                f"<td>{'yes' if run.rollback_occurred else 'no'}</td></tr>"
                for run in runs
            )
            run_table = (
                "<table><thead><tr><th>Fault type</th><th>Timestamp</th><th>Severity</th>"
                "<th>Status</th><th>Policy blocked</th><th>Rollback</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
        else:
            run_table = '<p class="empty">No historical runs found yet.</p>'
        body = (
            "<h1>Sentinel Dashboard</h1>"
            '<p class="subtitle">Historical policy, orchestration, and postmortem activity</p>'
            f'<section class="stats">{stat_cards}</section>'
            "<h2>Recent runs</h2>"
            f"{run_table}"
        )
        return HTMLResponse(_page("Dashboard", body))

    @application.get("/run/{run_id}", response_class=HTMLResponse)
    def run_detail(run_id: str) -> HTMLResponse:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        steps = "".join(
            f'<div class="step"><strong>{escape(name)}</strong><span>{escape(detail)}</span></div>'
            for name, detail in _timeline(run)
        )
        postmortem_link = (
            f'<a href="/postmortem/{escape(run.postmortem_filename)}">View generated postmortem</a>'
            if run.postmortem_filename
            else "No postmortem file available for this record."
        )
        body = (
            f'<p><a href="/">← Back to dashboard</a></p>'
            f"<h1>Run: {escape(run.fault_type)}</h1>"
            f'<p><span class="status {_status_class(run.status)}">{escape(run.status)}</span></p>'
            f'<div class="card"><div class="label">Timestamp</div><div>{escape(run.timestamp)}</div>'
            f'<div class="label" style="margin-top:12px">Severity</div><div>{escape(run.severity)}</div>'
            f'<div style="margin-top:16px">{postmortem_link}</div></div>'
            "<h2>Run timeline</h2>"
            f'<section class="timeline">{steps}</section>'
        )
        return HTMLResponse(_page(f"Run {run.fault_type}", body))

    @application.get("/postmortem/{filename:path}", response_class=HTMLResponse)
    def postmortem(filename: str) -> HTMLResponse:
        try:
            content = store.read_postmortem(filename)
        except FileNotFoundError as error:
            raise HTTPException(status_code=404, detail="Postmortem not found") from error
        body = (
            '<p><a href="/">← Back to dashboard</a></p>'
            f"<h1>Postmortem</h1><pre>{escape(content)}</pre>"
        )
        return HTMLResponse(_page("Postmortem", body))

    return application


app = create_app()

__all__ = ["DashboardStore", "RunRecord", "app", "create_app"]
