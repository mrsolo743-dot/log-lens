from datetime import datetime, timedelta, timezone

import pytest
from conftest import TZ

from log_lens.filters import (
    EntryFilter,
    is_bot,
    last_period,
    parse_datetime,
    parse_status_spec,
)


@pytest.mark.parametrize("spec,yes,no", [
    ("404", [404], [403, 200]),
    ("4xx", [400, 404, 499], [399, 500]),
    ("500-503", [500, 503], [504, 499]),
    ("4xx,301", [301, 404], [302, 500]),
    ("!2xx", [301, 404, 500], [200, 204]),
])
def test_status_spec(spec, yes, no):
    m = parse_status_spec(spec)
    assert all(m(s) for s in yes)
    assert not any(m(s) for s in no)


@pytest.mark.parametrize("bad", ["abc", "6xx", "500-400", ""])
def test_status_spec_errors(bad):
    with pytest.raises(ValueError):
        parse_status_spec(bad)


def test_parse_datetime():
    assert parse_datetime("2026-11-01", tz=TZ) == datetime(2026, 11, 1, tzinfo=TZ)
    end = parse_datetime("2026-11-01", end=True, tz=TZ)
    assert end.hour == 23 and end.minute == 59
    assert parse_datetime("2026-11-01 14:30").tzinfo == timezone.utc
    aware = parse_datetime("2026-11-01T10:00:00+03:00")
    assert aware.utcoffset() == timedelta(hours=3)
    with pytest.raises(ValueError):
        parse_datetime("вчера")


def test_last_period():
    now = datetime(2026, 11, 8, 12, 0, tzinfo=TZ)
    assert last_period("24h", now) == now - timedelta(hours=24)
    assert last_period("30m", now) == now - timedelta(minutes=30)
    assert last_period("7d", now) == now - timedelta(days=7)
    with pytest.raises(ValueError):
        last_period("неделя", now)


def test_is_bot():
    assert is_bot("Mozilla/5.0 (compatible; Googlebot/2.1)")
    assert is_bot("curl/8.5.0")
    assert is_bot("-")
    assert not is_bot("Mozilla/5.0 (Windows NT 10.0) Chrome/130.0")


def test_entry_filter_combined(entry):
    t0 = datetime(2026, 11, 1, 12, 0, tzinfo=TZ)
    items = [
        entry(t=t0, path="/api/x", status=500, method="POST", ip="203.0.113.5"),
        entry(t=t0 + timedelta(days=2), path="/api/y", status=500, ip="203.0.113.6"),
        entry(t=t0, path="/blog", status=500, ip="203.0.113.7"),
        entry(t=t0, path="/api/z", status=200, ip="203.0.113.8"),
        entry(t=t0, path="/api/b", status=502, ip="192.0.2.1", ua="curl/8"),
    ]
    f = EntryFilter(until=t0 + timedelta(hours=1), status="5xx", path="^/api/", ip="203.0.113.0/24")
    assert [e.path for e in f.apply(items)] == ["/api/x"]
    assert f.describe()[0].startswith("по ")
    assert [e.path for e in EntryFilter(only_bots=True).apply(items)] == ["/api/b"]
    assert len(list(EntryFilter(exclude_bots=True).apply(items))) == 4
    assert [e.path for e in EntryFilter(method="post").apply(items)] == ["/api/x"]
    assert not EntryFilter().active


def test_entry_filter_validation():
    with pytest.raises(ValueError):
        EntryFilter(path="([")
    with pytest.raises(ValueError):
        EntryFilter(ip="not-an-ip")
    with pytest.raises(ValueError):
        EntryFilter(exclude_bots=True, only_bots=True)
    t = datetime(2026, 1, 2, tzinfo=TZ)
    with pytest.raises(ValueError):
        EntryFilter(since=t, until=t - timedelta(days=1))


def test_ip_filter_ipv6(entry):
    f = EntryFilter(ip="2001:db8::/32")
    assert f(entry(ip="2001:db8::1"))
    assert not f(entry(ip="192.0.2.1"))
    assert not f(entry(ip="unknown"))
