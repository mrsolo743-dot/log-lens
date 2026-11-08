import gzip
import json

import pytest

from log_lens.cli import main


def test_help_without_command(capsys):
    assert main([]) == 2
    assert "analyze" in capsys.readouterr().out


def test_version():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_generate_and_analyze_text(tmp_path, capsys):
    log = tmp_path / "a.log"
    assert main(["generate", "-n", "800", "--days", "2", "-o", str(log)]) == 0
    capsys.readouterr()
    assert main(["analyze", str(log), "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "Сводка" in out and "Подозрительная активность" in out


def test_output_by_extension(tmp_path, capsys):
    log = tmp_path / "a.log"
    main(["generate", "-n", "500", "--days", "1", "-o", str(log)])
    html, js = tmp_path / "r.html", tmp_path / "r.json"
    assert main(["analyze", str(log), "-o", str(html)]) == 0
    assert main(["a", str(log), "-o", str(js), "--top", "3"]) == 0
    assert html.read_text(encoding="utf-8").startswith("<!doctype html>")
    data = json.loads(js.read_text(encoding="utf-8"))
    assert len(data["top_paths"]) == 3
    assert "отчёт сохранён" in capsys.readouterr().err


def test_filters_and_gzip(tmp_path, capsys):
    log = tmp_path / "a.log.gz"
    plain = tmp_path / "p.log"
    main(["generate", "-n", "1000", "--days", "2", "-o", str(plain)])
    with open(plain, "rb") as src, gzip.open(log, "wb") as dst:
        dst.write(src.read())
    capsys.readouterr()
    assert main(["analyze", str(log), "--output", "json", "--status", "5xx", "--no-detect"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data["status_classes"]) == {"5xx"}
    assert data["findings"] == []
    assert data["filters"] == ["статус 5xx"]

    main(["analyze", str(log), "--output", "json", "--since", "2026-11-02", "--until", "2026-11-02"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["first"].startswith("2026-11-02")
    assert data["summary"]["last"].startswith("2026-11-02")

    main(["analyze", str(log), "--output", "json", "--last", "6h"])
    data = json.loads(capsys.readouterr().out)
    from datetime import datetime, timedelta
    first = datetime.fromisoformat(data["summary"]["first"])
    last = datetime.fromisoformat(data["summary"]["last"])
    assert timedelta(hours=5) < last - first <= timedelta(hours=6)


def test_fail_on(tmp_path):
    log = tmp_path / "a.log"
    main(["generate", "-n", "500", "--days", "1", "-o", str(log)])
    assert main(["analyze", str(log), "--fail-on", "high", "-o", str(tmp_path / "r.txt")]) == 3
    clean = tmp_path / "c.log"
    main(["generate", "-n", "300", "--days", "1", "--no-attacks", "-o", str(clean)])
    assert main(["analyze", str(clean), "--fail-on", "high", "-o", str(tmp_path / "r2.txt")]) == 0


def test_errors(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope.log")]) == 2
    assert "файл не найден" in capsys.readouterr().err
    log = tmp_path / "a.log"
    log.write_text("мусор\n", encoding="utf-8")
    assert main(["analyze", str(log), "--status", "9xx"]) == 2
    assert "неверный фильтр статуса" in capsys.readouterr().err
    assert main(["analyze", str(log)]) == 0
    assert "ни одна строка не разобрана" in capsys.readouterr().err
    assert main(["analyze", str(log), "--format", "$remote_addr"]) == 2


def test_stdin(monkeypatch, capsys):
    import io
    import sys
    line = '192.0.2.1 - - [01/Nov/2026:12:00:00 +0500] "GET / HTTP/1.1" 200 5 "-" "Mozilla/5.0"\n'
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(line.encode() * 3)))
    assert main(["analyze", "-", "--output", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["requests"] == 3
