"""Minimal inert slow-query fault marker for cascading detector tests."""


def generate_log_line() -> str:
    """Return a deterministic slow-query anomaly marker."""
    return "faults/slow_query.py: slow query detected; query latency exceeded threshold"


def inject() -> str:
    return generate_log_line()


activate = generate_log_line
log_line = generate_log_line
