# Sentinel — Phase 1 and Phase 2 Specification

## Working agreement

- Build exactly one phase at a time.
- Write tests before implementation code for each behavior.
- Stop after each phase and provide the exact verification commands.
- No scope creep: do not implement later phases, policy engines, healing logic, authentication, or unrelated infrastructure.

## Phase 1 outcome

Sentinel includes a small FastAPI demo service backed by SQLite and a deliberately isolated SQL-injection fault injector.

### Acceptance criteria

1. `demo_app` exposes:
   - `GET /health` returning a healthy status and database status.
   - `GET /users/{user_id}` returning one user or `404`.
   - `GET /search?q=<term>` returning matching users using a parameterized SQL query.
2. The SQLite database is initialized automatically and has deterministic demo users.
3. Automated tests cover health, lookup success/not-found, search matches/empty results, and SQL-injection resistance of the safe endpoint.
4. `faults/sql_injection.py` contains an explicitly vulnerable raw-SQL search implementation for controlled demonstrations; it is not imported by the safe service.
5. The service can be run with Docker Compose and dependencies are pinned in `requirements.txt`.

## Out of scope for Phase 1

Audit logging, policy guardrails, fault detection/healing workflows, authentication, production deployment, and all later phases.

## Phase 2 specification

Provide a sandbox-runner abstraction for executing tests against patched source without mutating the workspace. The first implementation uses local subprocesses and temporary directories; its interface must be replaceable by a future Docker-backed implementation.

### Acceptance criteria

1. A caller can provide a source directory, patched file contents, and a test command through a stable runner interface.
2. The local runner copies the source into a temporary directory, applies the patch there, and runs the command as a subprocess with that directory as its working directory.
3. The result exposes the subprocess return code, captured standard output, captured standard error, and the temporary execution path for diagnostics.
4. The original source directory is unchanged, including when the patched test fails.
5. Tests cover successful patched execution, failed execution/result capture, and source isolation.

## Out of scope for Phase 2

Docker sandboxing, network isolation, policy evaluation, automatic remediation, audit persistence, and changes to the Phase 1 API.

## Phase 2 core-agent-loop specification

Extend the existing sandbox foundation into a single-fault self-healing loop for the intentionally vulnerable SQL-injection fault only.

### Acceptance criteria

1. A detector reads application log text or a log file, recognizes the SQL-injection fault signature when the fault is active, and returns an anomaly with `critical` severity; unrelated logs return no anomaly.
2. A diagnoser sends the anomaly to an injected LLM client and returns a root-cause diagnosis with a confidence score from 0 to 100.
3. A patcher sends the diagnosis to an injected LLM client and returns a safe patch replacing the vulnerable raw SQL with the parameterized implementation already used by `demo_app`.
4. The sentinel sandbox adapter runs `tests/test_app.py` against the patched temporary copy using the local subprocess runner.
5. The orchestrator logs each step, applies the patch to the real source only when sandbox tests pass, and leaves the source unchanged on failure.

### Out of scope

Policy evaluation, rollback, dashboards, other fault types, Docker execution, and production LLM credentials/configuration.

## Phase 3 specification

Add guardrails to the single-fault loop: policy validation and auditability before sandbox execution, confidence-gated patching, and automatic rollback after a failed post-apply health check.

### Acceptance criteria

1. `sentinel/policy/policy.yaml` allows edits only under `faults/*.py` and `demo_app/*.py`, denies `.env`, the policy file itself, destructive shell/database commands, and network calls in patch content.
2. `PolicyEngine` evaluates every proposed patch before sandboxing and records allowed and blocked decisions in a queryable audit log containing timestamp, action, decision, and reason.
3. The orchestrator uses a configurable confidence threshold defaulting to `70`; lower confidence produces `needs_human_review` and stops before patching.
4. A post-apply `HealthChecker` runs the demo app health check. A failed check restores the backed-up pre-patch files and records the rollback reason.
5. The orchestrator flow is detect → diagnose → confidence gate → patch → policy check → sandbox → apply → health check → rollback if needed.

### Out of scope

New fault types, dashboard/UI, Docker sandbox execution, and policy bypasses.

## Phase 4 specification

### 1. Detector behavior for prompt-injection logs

When the detector scans incoming log text, before checking for normal
faults (sql_injection, memory_leak, etc.), it must first check for
suspicious instruction-like patterns, case-insensitive, including but not
limited to:

- "ignore previous instructions"
- "ignore all previous instructions"
- "disable policy" / "disable the policy engine"
- "SYSTEM:" followed by an imperative command
- "delete all files"
- "bypass policy" / "skip policy check"

If any such pattern is found anywhere in the log text:

- Detector returns an Anomaly with:
  - `fault="suspicious_input"`
  - `severity="suspicious_input"` (a new severity level, treated as
    highest priority — above "critical")
  - `evidence` equal to the matched pattern and surrounding context (for
    example 50 characters before and after)
- This anomaly must never be passed to the diagnoser or patcher. The
  orchestrator checks the fault type immediately after detection: if
  `fault == "suspicious_input"`, skip diagnose/patch entirely and go
  straight to `status="needs_human_review"`, with a reason noting it was
  flagged as suspicious input, not a confidence issue.
- This is a separate code path from the confidence gate (which requires a
  diagnosis to exist first). Suspicious input never reaches diagnosis.

If a log contains both a real fault signature (for example sql_injection)
and a suspicious instruction pattern, suspicious_input takes priority —
treat the whole anomaly as suspicious_input and route it to human review.

### 2. Orchestrator statuses

Existing Phase 2–3 statuses include `fixed`, `blocked`, `rolled_back`, and
`needs_human_review`. Phase 4 reuses `needs_human_review` for suspicious
input, but the audit/postmortem reason must distinguish `low_confidence`
from `suspicious_input`.

### 3. Audit events

When suspicious input is detected, log an audit event through the existing
AuditLog:

- `action="suspicious_input_detected"`
- `decision="block"`
- `reason` containing the matched pattern and evidence snippet

### 4. Postmortem generator

Location: `sentinel/postmortem/generator.py`

Class: `PostmortemGenerator`

Method: `generate(run_result) -> str` — returns the Markdown content and
writes it to disk.

The orchestrator calls the generator exactly once at the very end of
`run()`, immediately before returning, regardless of whether the status is
fixed, blocked, rolled_back, or needs_human_review.

Postmortems are written to:

`postmortems/<YYYYMMDD_HHMMSS>_<fault>.md`

The timestamp is the time the run started. The fault is the detected fault
name, or `multi` for cascading runs.

Required Markdown sections, in order:

```markdown
# Postmortem: <fault> — <status>

Timestamp: <ISO 8601>
Status: <fixed|blocked|rolled_back|needs_human_review>
Severity: <severity level(s)>

## What happened

<1–3 deterministic sentences describing the detected anomaly/anomalies,
generated from Anomaly evidence and not an LLM call>

## Diagnosis

<root cause and confidence score, if diagnosis occurred. If skipped,
state “Diagnosis skipped: <reason>”>

## Actions taken

<bullet list covering checks, policy decisions, patches, sandbox results,
apply, and rollback when applicable>

## Outcome

<final status and one-sentence summary>
```

This must work for successful fixes, policy blocks, rollbacks, and human
review cases, including both low-confidence and suspicious-input review.

### 5. Cascading fault handling

A cascading fault is when the detector finds more than one distinct anomaly
in a single log or metrics snapshot, such as `memory_leak` and `slow_query`
present simultaneously.

`Detector.detect()` returns a list of Anomaly objects, including a list of
one for a single anomaly. Existing single-fault tests must remain backward
compatible by checking `list[0]` or by transparent orchestrator unwrapping.

For multiple anomalies, the orchestrator sorts by severity priority:

`suspicious_input > critical > medium > low`

It processes each anomaly through the full pipeline — diagnose, confidence
gate, patch, policy, sandbox, apply, health check, and rollback if needed —
one at a time and in priority order. If an earlier anomaly is blocked or
rolled back, processing continues for the remaining independent anomalies.

The run result collects all individual outcomes. A cascading run produces a
single postmortem listing all handled anomalies in What happened and
Actions taken, using `fault="multi"` in the filename.

Add `faults/prompt_injection_log.py` for prompt-injection testing and
`faults/cascading_demo.py` to activate both memory-leak and slow-query
equivalents simultaneously. If separate memory-leak or slow-query faults do
not exist, create minimal detectable and patchable versions sufficient to
prove cascading handling.

### 6. Phase 4 tests

Required test cases:

- `test_prompt_injection_detected_as_suspicious_input`
- `test_suspicious_input_never_reaches_diagnoser_or_patcher`
- `test_suspicious_input_routes_to_human_review_with_correct_reason`
- `test_suspicious_input_audit_event_logged`
- `test_postmortem_generated_for_successful_fix`
- `test_postmortem_generated_for_policy_block`
- `test_postmortem_generated_for_rollback`
- `test_postmortem_generated_for_human_review`
- `test_postmortem_file_exists_on_disk_with_correct_naming`
- `test_cascading_faults_detected_as_multiple_anomalies`
- `test_cascading_faults_processed_in_severity_priority_order`
- `test_cascading_faults_single_postmortem_lists_all`
- `test_cascading_continues_processing_after_one_anomaly_blocked_or_rolled_back`

All existing Phase 1–3 tests must continue to pass unchanged.

### 7. Manual verification

At the end of Phase 4, provide steps to:

- Trigger `faults/prompt_injection_log.py`, show it routed to human review,
  and show its audit entry.
- Show the generated Markdown postmortem for a successful fix and for a
  prompt-injection case.
- Trigger a cascading memory-leak plus slow-query scenario and show both
  handled with one combined postmortem.
