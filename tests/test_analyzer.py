from datetime import datetime, timedelta

import pytest
from conftest import TZ

from log_lens.analyzer import Analyzer, bucket, choose_step, normalize_path, percentile


def test_percentile():
    assert percentile([], 50) is None
    assert percentile([5], 95) == 5
    assert percentile([1, 2, 3, 4], 50) == pytest.approx(2.5)
    assert percentile(list(range(101)), 95) == pytest.approx(95)


def test_normalize_path():
    assert normalize_path("/a?b=1") == "/a"
    assert normalize_path("?x") == "/"
    assert normalize_path("/a?b=1", strip_query=False) == "/a?b=1"


def test_choose_step():
    t = datetime(2026, 11, 1, tzinfo=TZ)
    assert choose_step(t, t + timedelta(hours=2)) == timedelta(minutes=1)
    assert choose_step(t, t + timedelta(days=1)) == timedelta(minutes=15)
    assert choose_step(t, t + timedelta(days=7)) == timedelta(hours=1)
    assert choose_step(t, t + timedelta(days=60)) == timedelta(days=1)
    assert choose_step(None, None) == timedelta(hours=1)


def test_bucket_uses_local_midnight():
    t = datetime(2026, 11, 3, 2, 30, tzinfo=TZ)
    assert bucket(t, timedelta(days=1)) == datetime(2026, 11, 3, tzinfo=TZ)
    assert bucket(t, timedelta(hours=1)) == datetime(2026, 11, 3, 2, tzinfo=TZ)
    assert bucket(t, timedelta(days=7)) == datetime(2026, 11, 2, tzinfo=TZ)  # понедельник


def test_stats(entry):
    t0 = datetime(2026, 11, 2, 10, 0, tzinfo=TZ)  # понедельник
    a = Analyzer()
    a.feed(entry(t=t0, path="/a?x=1", status=200, size=1000, rt=0.1, referer="https://g.com/"))
    a.feed(entry(t=t0 + timedelta(minutes=1), path="/a", status=404, size=10, rt=0.3, ip="192.0.2.2"))
    a.feed(entry(t=t0 + timedelta(hours=1), path="/b", status=503, size=0, ua="curl/8"))
    a.feed(entry(t=t0 + timedelta(hours=2), path="/b", status=301, size=0))
    s = a.result()
    assert s.total == 4 and s.unique_ips == 2 and s.bytes_total == 1010
    assert s.paths["/a"] == 2
    assert s.error_paths["/a"] == 1 and s.server_error_paths["/b"] == 1
    assert s.error_rate == 0.5
    assert s.bot_share == 0.25
    assert s.hours[10] == 2 and s.weekdays[0] == 4
    assert s.referers["https://g.com/"] == 1
    assert s.first == t0 and s.duration == timedelta(hours=2)
    rt = s.response_time_summary()
    assert rt["count"] == 2 and rt["avg"] == pytest.approx(0.2)
    assert s.slowest_paths(1)[0][0] == "/a"
    series = s.timeline_series()
    assert sum(c for _, c, _ in series) == 4
    assert sum(e for _, _, e in series) == 2
    # ряд непрерывный: шаг между соседними точками одинаковый
    steps = {b[0] - a_[0] for a_, b in zip(series, series[1:])}
    assert steps == {s.timeline_step}


def test_empty_stats():
    s = Analyzer().result()
    assert s.total == 0 and s.error_rate == 0 and s.timeline_series() == []
    assert s.response_time_summary() is None
