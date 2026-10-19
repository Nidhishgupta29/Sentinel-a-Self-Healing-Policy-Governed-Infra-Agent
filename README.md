# Sentinel — Self-Healing, Policy-Governed Infra Agent

**Live demo:** https://sentinel-dashboard-sl63.onrender.com

Sentinel is an AI agent that watches over a running web app, catches bugs and
security problems on its own, figures out what's wrong, writes a fix, tests
it in a sandbox, and only applies it if the fix actually works.

The core idea isn't just "can the agent fix stuff" — it's "can you trust it
to run on a real system without babysitting it." Every action the agent
wants to take first passes through a policy engine. If it tries something
risky, like touching a file it shouldn't or running a command it has no
business running, it gets blocked right there and the decision gets logged
so you can see exactly why.

Built for the Frontier Buildathon — **Systems, Infra & Security** track
(with Agents & Automation woven in).

---

## Why this exists

Everyone's building agents that can "fix things automatically" right now,
but almost nobody trusts them enough to let them run on a real system
without someone babysitting it. That's the actual gap. Sentinel isn't just
another bug-fixing bot — it's an attempt at the part that's usually
missing: a way to let an agent work on its own while still keeping control
over what it's allowed to do.

## Features

- **Fault detection** — reads logs/metrics and flags anomalies with a severity level
- **Diagnosis + confidence scoring** — finds the root cause and rates how confident it is. Low confidence → flagged for human review instead of auto-applying
- **Policy engine** — every proposed action is checked against `policy.yaml` before it runs. Full audit log of every allow/block decision
- **Sandboxed testing** — patches are tested before anything touches the real app
- **Auto-rollback** — if a patch is applied and a post-apply health check fails, Sentinel reverts it automatically
- **Prompt-injection defense** — one fault type hides an instruction inside the logs trying to trick the agent directly ("ignore previous instructions", "disable policy", etc.). The detector flags this as `suspicious_input` and routes it straight to human review — it never reaches the diagnoser or patcher
- **Cascading fault handling** — multiple issues found in one snapshot (e.g. memory leak + slow query) are processed independently, in severity order, without one blocked/rolled-back issue stopping the rest
- **Postmortem generator** — after every run, Sentinel writes a short markdown incident report: what happened, root cause, what was blocked (if anything), and the outcome
- **Live dashboard** — shows detection, diagnosis, policy decisions, confidence scores, and test results, with links to full postmortems
- **Eval harness** — runs every fault scenario and reports success rate, blocks, rollbacks, and average time

## How it works

```
Fault Injector → Demo App (FastAPI) → Logs/Metrics
                                          │
                                          ▼
                                     Detector
                        (anomaly + severity, incl. suspicious_input)
                                          │
                              ┌───────────┴───────────┐
                     suspicious_input            normal fault
                              │                        │
                      needs_human_review          Diagnoser (LLM)
                                                   + confidence score
                                                        │
                                          confidence < threshold?
                                                        │
                                      yes ──► needs_human_review
                                                        │ no
                                                        ▼
                                                  Patcher (LLM)
                                                        │
                                                        ▼
                                              Policy Engine (allow/block)
                                                        │
                                       blocked ──► stop, log reason
                                                        │ allowed
                                                        ▼
                                           Sandbox (run tests on patch)
                                                        │
                                        fail ──► discard patch
                                                        │ pass
                                                        ▼
                                              Backup → Apply → Health Check
                                                        │
                                   fails ──► Auto-Rollback (restore backup)
                                                        │ passes
                                                        ▼
                                                      Fixed
                                                        │
                                                        ▼
                                            Postmortem Generator (.md)
                                                        │
                                                        ▼
                                              Live Dashboard (real-time)
```

Every step — allow, block, apply, rollback — is written to a SQLite audit
log, and every run (success, block, rollback, or human-review) ends with a
generated postmortem.

## Fault categories covered

- SQL injection
- Memory leak
- Slow query
- Prompt injection (hidden in logs, targets the agent itself)
- Cascading faults (multiple faults in one run)

Tested across 25 scenario runs in the included eval harness.

## Eval results

```
fault type              total   fixed   blocked   rolled_back   needs_human_review
sql_injection              5      3        1            1               0
memory_leak                5      3        1            1               0
slow_query                 5      3        1            1               0
prompt_injection_log       5      0        0            0               5
cascading_demo             5      3        1            1               0

Overall: 12/25 fixed (48%)
```

**Note on the 48% number:** this is intentional, not a weakness. The eval
set deliberately includes cases designed to test the guardrails
themselves — policy blocks, rollbacks, and human-review routing — not just
happy-path fixes. Every blocked and rolled-back run represents the safety
layer doing exactly what it's supposed to do. The 5/5 `prompt_injection_log`
cases routing to human review, with zero reaching the patcher, is the
result that matters most for this project.

Full per-run results: [`evals/results.md`](evals/results.md)

## Tech stack

- Python 3.12
- FastAPI (demo app + dashboard)
- Docker / docker-compose
- SQLite (audit log + state)
- GPT Astra (diagnosis + patch generation, injected via an LLM client interface — swappable and fully mockable for tests/evals)

## Project structure

```
demo_app/        FastAPI service being protected (the "patient")
faults/          Fault injectors (sql_injection, memory_leak, slow_query,
                  prompt_injection_log, cascading_demo)
sentinel/
  detector/      Anomaly + suspicious-input detection
  diagnoser/     LLM root-cause + confidence scoring
  patcher/       LLM patch generation
  policy/        policy.yaml + PolicyEngine + audit log
  sandbox/       Sandboxed test runner
  rollback/      HealthChecker + backup/restore
  postmortem/    Markdown incident report generator
  orchestrator.py  Ties the full pipeline together
dashboard/       Live web dashboard (FastAPI)
evals/           Eval harness + results.md
postmortems/     Generated incident reports
tests/           Full test suite (63 tests)
Dockerfile, docker-compose.yml, render.yaml, Makefile
```

## Setup

```bash
git clone https://github.com/Nidhishgupta29/Sentinel-a-Self-Healing-Policy-Governed-Infra-Agent.git
cd Sentinel-a-Self-Healing-Policy-Governed-Infra-Agent
pip install -r requirements.txt
```

## Running tests

```bash
make test
```

63 tests covering detection, diagnosis, patching, policy enforcement,
sandboxing, rollback, prompt-injection defense, cascading faults, the
postmortem generator, the eval harness, and the dashboard.

## Running the eval harness

```bash
make eval
```

Generates `evals/results.md` with a full breakdown by fault type, using
deterministic offline LLM clients by default (fast, free, reproducible).
Pass `--live` with `SENTINEL_LIVE_CLIENT_FACTORY` set to use a real LLM
client instead.

## Running with Docker (recommended — single command)

```bash
make up
```

or directly:

```bash
docker compose up --build
```

This starts two services:

- **Dashboard** — `http://localhost:8000`
- **Demo app** — `http://localhost:8001` (`/health` for a quick check)

The dashboard image ships with the bundled historical audit log and
postmortems, so it shows real data immediately on first start — no setup
required.

To run the eval first (if no history exists yet) and then start the
dashboard in one step:

```bash
make demo
```

## Smoke test

```bash
./scripts/smoke_test.sh
```

Builds both Docker images, starts them, checks the dashboard root and a
postmortem route, checks the demo app's health endpoint, then tears
everything down.

## Live deployment

Deployed on Render (free tier) directly from this repo's `Dockerfile` and
`render.yaml`:

**https://sentinel-dashboard-sl63.onrender.com**

Note: free-tier services spin down after inactivity, so the first request
after idle time may take 30–50 seconds to wake up.

## Honest limitations

Fault coverage and policy rules are solid but not exhaustive — six fault
categories across ~25 tested variations, not the full range of real-world
failure modes. The confidence model is rule-based rather than learned from
historical outcomes. This was built solo in a short window, so there's no
multi-service testing yet, just the single demo app. With more time, the
next steps would be testing against a larger, messier codebase and making
the policy engine configurable per project instead of hardcoded.
