"""Inert combined fault marker used to exercise cascading handling."""

from .memory_leak import generate_log_line as memory_leak_log
from .slow_query import generate_log_line as slow_query_log


CASCADING_LOG = f"{memory_leak_log()} | {slow_query_log()}"


def generate_log_line() -> str:
    """Return one snapshot containing both independent fault markers."""
    return CASCADING_LOG


def inject() -> str:
    return generate_log_line()


activate = generate_log_line
log_line = generate_log_line
