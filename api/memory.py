from __future__ import annotations

import ctypes
import os
from typing import Any


def load_libc() -> Any | None:
    if os.name != "posix":
        return None

    try:
        return ctypes.CDLL("libc.so.6")
    except OSError:
        return None


LIBC = load_libc()


def trim_process_memory() -> None:
    if LIBC is None:
        return

    malloc_trim = getattr(LIBC, "malloc_trim", None)
    if malloc_trim is None:
        return

    try:
        malloc_trim(0)
    except Exception:
        return


def read_int_file(path: str) -> int | None:
    try:
        with open(path, encoding="utf-8") as file:
            value = file.read().strip()
    except OSError:
        return None

    if value == "max":
        return None

    try:
        return int(value)
    except ValueError:
        return None


def get_memory_usage_bytes() -> int | None:
    for path in (
        "/sys/fs/cgroup/memory.current",
        "/sys/fs/cgroup/memory/memory.usage_in_bytes",
    ):
        value = read_int_file(path)
        if value is not None:
            return value

    return None


def get_memory_limit_bytes() -> int | None:
    for path in (
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ):
        value = read_int_file(path)
        if value is not None and value < 2**60:
            return value

    return None
