import json
import re
from datetime import datetime, timedelta
from html.parser import HTMLParser

from conftest import TZ

from log_lens.analyzer import Analyzer
from log_lens.detectors import Detector
from log_lens.html_report import to_html
from log_lens.parser import LogParser
from log_lens.report import Report, human_bytes, human_duration, to_json, to_text
from log_lens.svg import _nice_max, column_chart, donut_chart, timeline_chart


def build(entries, **kw):
    a, d = Analyzer(), Detector()
    for e in entries:
        a.feed(e)
        d.feed(e)
    return Report(stats=a.result(), findings=d.findings(), files=["x.log"], **kw)


def sample_entries(entry):
    t0 = datetime(2026, 11, 1, 12, tzinfo=TZ)
    out = [entry(t=t0 + timedelta(minutes=i), path=f"/p{i % 3}", status=200 if i % 4 else 404, rt=0.05)
           for i in range(40)]
    out += [entry(ip="198.51.100.66", t=t0 + timedelta(seconds=i), path=p, status=404)
            for i, p in enumerate(["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.sql"])]
    out.append(entry(path='/<script>alert(1)</script>', status=404, ua='<b>ua</b>'))
    return out


def test_helpers():
    assert human_bytes(500) == "500 Б"
    assert human_bytes(2048) == "2.0 КБ"
    assert human_bytes(5 * 1024 ** 3) == "5.0 ГБ"
    assert human_duration(90061) == "1 д 1 ч 1 мин"
    assert human_duration(5) == "0 мин"
    assert _nice_max(0) == 1 and _nice_max(7) == 10 and _nice_max(1300) == 2000


def test_text_report(entry):
    text = to_text(build(sample_entries(entry), top=3), color=False, width=100)
    assert "Запросов:        46" in text
    assert "Сканер" in text and "198.51.100.66" in text
    assert "Топ-3 путей" in text
    assert "\033[" not in text
    assert "\033[" in to_text(build(sample_entries(entry)), color=True, width=100)


def test_text_report_empty():
    text = to_text(Report(stats=Analyzer().result(), findings=[], files=["e.log"], malformed=3), width=80)
    assert "Нет записей" in text and "Не разобрано строк: 3" in text


def test_json_report(entry):
    data = json.loads(to_json(build(sample_entries(entry), top=2)))
    assert data["summary"]["requests"] == 46
    assert len(data["top_paths"]) == 2
    assert len(data["hours"]) == 24 and len(data["weekdays"]) == 7
    assert data["findings"][0]["kind"] == "scanner"
    assert data["response_time"]["count"] == 40


class _Checker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "script":
            self.scripts += 1


def test_html_report_is_self_contained_and_escaped(entry):
    html = to_html(build(sample_entries(entry)), title="Тест <отчёт>")
    assert html.startswith("<!doctype html>")
    assert "<title>Тест &lt;отчёт&gt;</title>" in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert not re.search(r'(src|href)="https?://', html)  # никаких внешних ресурсов
    c = _Checker()
    c.feed(html)
    assert c.scripts == 1
    assert c.tags.count("svg") >= 4
    assert 'id="t-paths"' in html and "Подозрительная активность" in html


def test_html_empty_report():
    html = to_html(Report(stats=Analyzer().result(), findings=[], files=["e.log"]))
    assert "Нет записей" in html


def test_svg_charts():
    col = column_chart(["a", "b"], [0, 5], title="t")
    assert col.count("<rect") == 2 and 'class="bar peak"' in col
    assert "Нет данных" in timeline_chart([], timedelta(hours=1), title="t")
    t0 = datetime(2026, 11, 1, tzinfo=TZ)
    line = timeline_chart([(t0, 5, 1), (t0 + timedelta(hours=1), 10, 0)], timedelta(hours=1), title="t")
    assert "s-main" in line and "s-err" in line
    donut = donut_chart([("2xx", 3), ("4xx", 1)], title="t")
    assert "c-2xx" in donut and "75.0%" in donut


def test_end_to_end_with_generated_log(sample_log):
    a, d, p = Analyzer(), Detector(), LogParser()
    with open(sample_log, encoding="utf-8") as fh:
        for e in p.parse(fh):
            a.feed(e)
            d.feed(e)
    kinds = {f.kind for f in d.findings()}
    assert {"scanner", "bruteforce", "404-burst", "rate", "spike"} <= kinds
    assert p.malformed == 0
