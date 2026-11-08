import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from log_lens.parser import LogEntry

TZ = timezone(timedelta(hours=5))


def make_entry(ip="192.0.2.1", t=None, method="GET", path="/", status=200, size=100,
               ua="Mozilla/5.0 Firefox", referer="-", rt=None):
    return LogEntry(ip=ip, time=t or datetime(2026, 11, 1, 12, 0, tzinfo=TZ), method=method, path=path,
                    protocol="HTTP/1.1", status=status, size=size, referer=referer, user_agent=ua,
                    request_time=rt)


def log_line(ip="192.0.2.1", t="01/Nov/2026:12:00:00 +0500", req="GET / HTTP/1.1", status=200,
             size=100, ref="-", ua="Mozilla/5.0", rt=None):
    s = f'{ip} - - [{t}] "{req}" {status} {size} "{ref}" "{ua}"'
    return s + (f" {rt}" if rt is not None else "")


@pytest.fixture
def entry():
    return make_entry


@pytest.fixture
def sample_log(tmp_path):
    from log_lens.generator import GeneratorConfig, write_log
    path = tmp_path / "access.log"
    with open(path, "w", encoding="utf-8") as fh:
        write_log(GeneratorConfig(lines=3000, days=3, seed=7), fh)
    return path
