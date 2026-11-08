"""Командная строка log-lens."""

from __future__ import annotations

import argparse
import itertools
import os
import sys
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from . import __version__
from .analyzer import Analyzer
from .detectors import SEVERITY_ORDER, Detector, DetectorConfig
from .filters import EntryFilter, last_period, parse_datetime
from .generator import GeneratorConfig, write_log
from .html_report import to_html
from .parser import LogFormatError, LogParser, read_entries
from .report import Report, to_json, to_text

EPILOG = """примеры:
  log-lens analyze access.log
  log-lens analyze /var/log/nginx/access.log* -o report.html
  log-lens analyze access.log --status 5xx --since 2026-11-01 --until 2026-11-03
  log-lens analyze access.log --last 24h --exclude-bots --top 20 --output json
  log-lens analyze app.log --format '$remote_addr [$time_local] "$request" $status $body_bytes_sent'
  log-lens generate -n 20000 -o demo.log
"""


def _positive_int(value: str) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("нужно положительное число")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-lens",
        description="Анализатор access-логов nginx/Apache: статистика, подозрительная активность, HTML-отчёт.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"log-lens {__version__}")
    sub = p.add_subparsers(dest="command", metavar="КОМАНДА")

    a = sub.add_parser("analyze", aliases=["a"], help="проанализировать логи",
                       epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("files", nargs="+", metavar="ФАЙЛ", help="файлы логов (.log, .gz) или - для stdin")
    a.add_argument("-f", "--format", default="auto",
                   help="auto | combined | common | timed | строка log_format nginx (по умолчанию auto)")
    a.add_argument("-o", "--out", help="куда сохранить отчёт (формат по расширению: .html, .json, .txt)")
    a.add_argument("--output", choices=["text", "json", "html"], help="формат вывода (по умолчанию text)")
    a.add_argument("-n", "--top", type=_positive_int, default=10, help="сколько строк в топах (по умолчанию 10)")
    a.add_argument("--title", default="Отчёт log-lens", help="заголовок HTML-отчёта")
    a.add_argument("--keep-query", action="store_true", help="не отбрасывать ?query у путей при группировке")
    a.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="цвет в терминале")

    g = a.add_argument_group("фильтры")
    g.add_argument("--since", help="с даты/времени: 2026-11-01 или '2026-11-01 14:00'")
    g.add_argument("--until", help="по дату/время включительно")
    g.add_argument("--last", help="последний период относительно последней записи: 30m, 24h, 7d")
    g.add_argument("--status", help="коды: 404 | 4xx | 500-599 | 4xx,301 | !2xx")
    g.add_argument("--path", help="регулярное выражение для пути, например '^/api/'")
    g.add_argument("--ip", help="IP или подсеть, через запятую: 203.0.113.0/24,192.0.2.7")
    g.add_argument("--method", help="методы через запятую: GET,POST")
    bots = g.add_mutually_exclusive_group()
    bots.add_argument("--exclude-bots", action="store_true", help="исключить ботов и скрипты")
    bots.add_argument("--only-bots", action="store_true", help="только боты и скрипты")

    d = a.add_argument_group("детекторы")
    d.add_argument("--no-detect", action="store_true", help="не искать подозрительную активность")
    d.add_argument("--burst-404", type=_positive_int, default=20, metavar="N", help="порог 404 за 5 минут (20)")
    d.add_argument("--brute", type=_positive_int, default=10, metavar="N", help="порог POST на вход за 10 минут (10)")
    d.add_argument("--rate", type=_positive_int, default=120, metavar="N", help="порог запросов в минуту с IP (120)")
    d.add_argument("--fail-on", choices=["low", "medium", "high"],
                   help="код выхода 3, если найдено событие этого уровня или выше (для cron/CI)")

    gen = sub.add_parser("generate", aliases=["gen"], help="сгенерировать тестовый лог")
    gen.add_argument("-n", "--lines", type=_positive_int, default=5000, help="примерное число строк (5000)")
    gen.add_argument("-o", "--out", help="файл (по умолчанию stdout)")
    gen.add_argument("--days", type=float, default=7.0, help="длительность лога в днях (7)")
    gen.add_argument("--start", default="2026-11-01T00:00:00+05:00", help="начало лога (ISO 8601)")
    gen.add_argument("--seed", type=int, default=42, help="seed генератора (42)")
    gen.add_argument("--no-attacks", action="store_true", help="без сценариев атак")
    gen.add_argument("--no-time", action="store_true", help="без $request_time (чистый combined)")
    return p


def _resolve_output(args) -> str:
    if args.output:
        return args.output
    if args.out:
        ext = os.path.splitext(args.out)[1].lower()
        return {".html": "html", ".htm": "html", ".json": "json"}.get(ext, "text")
    return "text"


def _use_color(mode: str, to_file: bool) -> bool:
    if mode == "always":
        return True
    if mode == "never" or to_file:
        return False
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def run_analyze(args) -> int:
    parser = LogParser(args.format)
    entries = read_entries(args.files, parser)

    # смотрим на первую запись, чтобы даты фильтров без часового пояса трактовать в поясе лога
    first = next(entries, None)
    tz = first.time.tzinfo if first else timezone.utc
    stream = itertools.chain([first], entries) if first else iter(())

    since = parse_datetime(args.since, tz=tz) if args.since else None
    until = parse_datetime(args.until, end=True, tz=tz) if args.until else None
    if args.last:
        data = list(stream)
        if data:
            newest = max(e.time for e in data)
            start = last_period(args.last, newest)
            since = max(since, start) if since else start
        stream = iter(data)

    flt = EntryFilter(since=since, until=until, status=args.status, path=args.path, ip=args.ip,
                      method=args.method, exclude_bots=args.exclude_bots, only_bots=args.only_bots)
    analyzer = Analyzer(strip_query=not args.keep_query)
    detector = None if args.no_detect else Detector(DetectorConfig(
        burst_404_count=args.burst_404, brute_count=args.brute, rate_per_minute=args.rate))

    for e in flt.apply(stream):
        analyzer.feed(e)
        if detector:
            detector.feed(e)

    report = Report(
        stats=analyzer.result(),
        findings=detector.findings() if detector else [],
        files=list(args.files), lines_total=parser.total_lines, malformed=parser.malformed,
        bad_samples=parser.bad_samples, filters=flt.describe(), top=args.top,
    )
    if parser.total_lines and parser.malformed == parser.total_lines:
        print(f"log-lens: ни одна строка не разобрана (формат {args.format!r}). Пример строки:\n  "
              + (parser.bad_samples[0] if parser.bad_samples else ""), file=sys.stderr)

    kind = _resolve_output(args)
    if kind == "html":
        text = to_html(report, title=args.title)
    elif kind == "json":
        text = to_json(report) + "\n"
    else:
        text = to_text(report, color=_use_color(args.color, bool(args.out)))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"log-lens: отчёт сохранён в {args.out} "
              f"({report.stats.total} запросов, {len(report.findings)} подозрительных событий)", file=sys.stderr)
    else:
        sys.stdout.write(text)

    if args.fail_on and report.findings:
        limit = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= limit for f in report.findings):
            return 3
    return 0


def run_generate(args) -> int:
    try:
        start = datetime.fromisoformat(args.start)
    except ValueError:
        raise ValueError(f"неверная дата --start: {args.start!r}") from None
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone(timedelta(hours=5)))
    if args.days <= 0:
        raise ValueError("--days должно быть больше нуля")
    cfg = GeneratorConfig(lines=args.lines, start=start, days=args.days, seed=args.seed,
                          with_time=not args.no_time, attacks=not args.no_attacks)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            n = write_log(cfg, fh)
        print(f"log-lens: записано {n} строк в {args.out}", file=sys.stderr)
    else:
        write_log(cfg, sys.stdout)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    try:
        if args.command in ("analyze", "a"):
            return run_analyze(args)
        return run_generate(args)
    except (ValueError, LogFormatError) as exc:
        print(f"log-lens: ошибка: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"log-lens: файл не найден: {exc.filename}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
