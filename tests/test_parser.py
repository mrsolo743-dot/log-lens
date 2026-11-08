import gzip
from datetime import datetime, timedelta, timezone

import pytest
from conftest import log_line

from log_lens.parser import (
    LogFormatError,
    LogParser,
    compile_nginx_format,
    open_log,
    read_entries,
)

COMBINED = ('203.0.113.5 - alice [10/Oct/2026:13:55:36 -0700] "GET /index.html?x=1 HTTP/1.1" 200 2326 '
            '"https://example.com/start" "Mozilla/5.0 (X11; Linux x86_64)"')
COMMON = '198.51.100.2 - - [10/Oct/2026:13:55:36 +0000] "POST /api HTTP/1.0" 404 -'


def test_combined_line():
    e = LogParser().parse_line(COMBINED)
    assert e.ip == "203.0.113.5"
    assert e.user == "alice"
    assert e.method == "GET" and e.path == "/index.html?x=1" and e.protocol == "HTTP/1.1"
    assert e.status == 200 and e.size == 2326
    assert e.referer == "https://example.com/start"
    assert e.user_agent.startswith("Mozilla/5.0")
    assert e.time == datetime(2026, 10, 10, 13, 55, 36, tzinfo=timezone(timedelta(hours=-7)))
    assert e.request_time is None
    assert e.status_class == "2xx" and not e.is_error


def test_common_line_and_dash_size():
    e = LogParser().parse_line(COMMON)
    assert e.method == "POST" and e.status == 404 and e.size == 0
    assert e.referer == "-" and e.user_agent == "-"
    assert e.is_error


def test_timed_line_parses_request_time():
    e = LogParser().parse_line(log_line(rt="0.250"))
    assert e.request_time == pytest.approx(0.25)


def test_escaped_quotes_in_user_agent():
    line = log_line(ua='Evil \\"agent\\" 1.0')
    e = LogParser().parse_line(line)
    assert e.user_agent == 'Evil "agent" 1.0'


def test_garbage_request_is_kept():
    e = LogParser().parse_line(log_line(req="\\x16\\x03\\x01", status=400))
    assert e.method == "-" and e.status == 400


def test_malformed_lines_counted():
    p = LogParser()
    lines = [COMBINED, "это не лог", "", "   ", COMMON, '1.2.3.4 - - [bad date] "GET / HTTP/1.1" 200 1']
    entries = list(p.parse(lines))
    assert len(entries) == 2
    assert p.malformed == 2
    assert p.total_lines == 4
    assert p.bad_samples[0] == "это не лог"


def test_explicit_format_rejects_other():
    p = LogParser("common")
    assert p.parse_line(COMBINED) is None
    assert p.parse_line(COMMON) is not None


def test_unknown_format():
    with pytest.raises(LogFormatError):
        LogParser("xml")


def test_custom_nginx_format():
    fmt = '$remote_addr $host [$time_local] "$request" $status $body_bytes_sent $request_time "$http_user_agent" $upstream_addr'
    p = LogParser(fmt)
    e = p.parse_line('192.0.2.9 example.com [01/Nov/2026:10:00:00 +0500] "GET /a HTTP/2.0" 502 0 1.500 "curl/8" 10.0.0.1:8080')
    assert e is not None
    assert e.host == "example.com" and e.status == 502
    assert e.request_time == 1.5
    assert e.user_agent == "curl/8"
    assert e.extra["upstream_addr"] == "10.0.0.1:8080"


def test_custom_format_requires_fields():
    with pytest.raises(LogFormatError, match=r"\$status"):
        compile_nginx_format('$remote_addr [$time_local] "$request"')


def test_open_gzip_and_plain(tmp_path):
    plain = tmp_path / "a.log"
    plain.write_text(COMBINED + "\n", encoding="utf-8")
    gz = tmp_path / "b.log.1"  # сжатый файл без расширения .gz — определяется по сигнатуре
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write(COMMON + "\n")
    with open_log(str(plain)) as fh:
        assert fh.read().startswith("203.0.113.5")
    entries = list(read_entries([str(plain), str(gz)], LogParser()))
    assert [e.status for e in entries] == [200, 404]


def test_auto_switches_to_common_first():
    p = LogParser()
    p.parse_line(COMMON)
    p.parse_line(COMMON)
    assert p._patterns[0].pattern.endswith(r"\s*$")
    assert p.parse_line(COMBINED) is not None
