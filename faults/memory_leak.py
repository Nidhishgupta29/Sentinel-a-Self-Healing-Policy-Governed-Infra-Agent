"""Minimal inert memory-leak fault marker for cascading detector tests."""


def generate_log_line() -> str:
    """Return a deterministic memory-leak anomaly marker."""
    return "faults/memory_leak.py: memory leak detected; resident memory increasing"


def inject() -> str:
    return generate_log_line()


activate = generate_log_line
log_line = generate_log_line
