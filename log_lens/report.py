"""Сборка отчёта и вывод в текст и JSON."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime

from .analyzer import Stats
from .detectors import Finding

SEVERITY_LABEL = {"high": "ВЫСОКИЙ", "medium": "СРЕДНИЙ", "low": "НИЗКИЙ"}
KIND_LABEL = {
    "scanner": "Сканер", "404-burst": "Всплеск 404", "bruteforce": "Подбор пароля",
    "rate": "Частота", "spike": "Всплеск трафика",
}
WEEKDAYS = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]


@dataclass
class Report:
    stats: Stats
    findings: list[Finding]
    files: list[str]
    lines_total: int = 0
    malformed: int = 0
    bad_samples: list = field(default_factory=list)
    filters: list = field(default_factory=list)
    top: int = 10
    generated_at: datetime = field(default_factory=lambda: datetime.now().astimezone())


def human_bytes(n: float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(n) < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d} д")
    if h:
        parts.append(f"{h} ч")
    if m or not parts:
        parts.append(f"{m} мин")
    return " ".join(parts)


def fmt_ms(sec: float | None) -> str:
    return "—" if sec is None else f"{sec * 1000:.0f} мс"


def summary(report: Report) -> dict:
    s = report.stats
    return {
        "requests": s.total,
        "unique_ips": s.unique_ips,
        "bytes": s.bytes_total,
        "error_rate": round(s.error_rate, 4),
        "bot_share": round(s.bot_share, 4),
        "first": s.first.isoformat() if s.first else None,
        "last": s.last.isoformat() if s.last else None,
    }


# ------------------------------- JSON -------------------------------

def to_json(report: Report) -> str:
    s, n = report.stats, report.top
    data = {
        "generated_at": report.generated_at.isoformat(),
        "files": report.files,
        "lines": report.lines_total,
        "malformed": report.malformed,
        "filters": report.filters,
        "summary": summary(report),
        "status_classes": dict(sorted(s.status_classes.items())),
        "statuses": {str(k): v for k, v in sorted(s.statuses.items())},
        "methods": dict(s.methods.most_common()),
        "top_paths": s.paths.most_common(n),
        "top_ips": s.ips.most_common(n),
        "top_user_agents": s.user_agents.most_common(n),
        "top_referers": s.referers.most_common(n),
        "top_4xx_paths": s.error_paths.most_common(n),
        "top_5xx_paths": s.server_error_paths.most_common(n),
        "hours": [s.hours.get(h, 0) for h in range(24)],
        "weekdays": [s.weekdays.get(d, 0) for d in range(7)],
        "timeline_step_seconds": int(s.timeline_step.total_seconds()),
        "timeline": [[t.isoformat(), c, e] for t, c, e in s.timeline_series()],
        "response_time": s.response_time_summary(),
        "slowest_paths": [[p, round(a, 4), c] for p, a, c in s.slowest_paths(n)],
        "findings": [f.to_dict() for f in report.findings],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


# ------------------------------- Текст -------------------------------

class _Style:
    def __init__(self, color: bool):
        self.color = color

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def bold(self, t): return self._wrap("1", t)
    def dim(self, t): return self._wrap("2", t)
    def red(self, t): return self._wrap("31", t)
    def yellow(self, t): return self._wrap("33", t)
    def green(self, t): return self._wrap("32", t)
    def cyan(self, t): return self._wrap("36", t)


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(1, width - 1)] + "…"


def _bar(value: int, maximum: int, width: int) -> str:
    if maximum <= 0 or width <= 0:
        return ""
    full = value / maximum * width
    n = int(full)
    rest = "▏▎▍▌▋▊▉"[int((full - n) * 7)] if full - n > 1 / 7 and n < width else ""
    return "█" * n + rest


def _table(rows, total: int, st: _Style, width: int, label_width: int = 48) -> list[str]:
    if not rows:
        return [st.dim("  (нет данных)")]
    maximum = max(c for _, c in rows)
    num_w = max(len(f"{c:,}".replace(",", " ")) for _, c in rows)
    bar_w = max(0, width - label_width - num_w - 16)
    out = []
    for label, count in rows:
        pct = count / total * 100 if total else 0
        num = f"{count:,}".replace(",", " ")
        out.append(f"  {_truncate(str(label), label_width):<{label_width}} {num:>{num_w}} {pct:5.1f}%  "
                   + st.cyan(_bar(count, maximum, bar_w)))
    return out


def to_text(report: Report, color: bool = False, width: int | None = None) -> str:
    st = _Style(color)
    width = width or min(shutil.get_terminal_size((100, 20)).columns, 120)
    s, n = report.stats, report.top
    lines: list[str] = []

    def section(title: str):
        lines.append("")
        lines.append(st.bold(title))
        lines.append(st.dim("─" * min(width, 80)))

    lines.append(st.bold("log-lens — отчёт по access-логам"))
    lines.append(st.dim("Файлы: " + ", ".join(report.files)))
    if report.filters:
        lines.append(st.dim("Фильтры: " + "; ".join(report.filters)))
    if s.total == 0:
        lines.append("")
        lines.append(st.yellow("Нет записей, подходящих под условия."))
        if report.malformed:
            lines.append(st.yellow(f"Не разобрано строк: {report.malformed}. Проверьте --format."))
        return "\n".join(lines) + "\n"

    section("Сводка")
    dur = s.duration.total_seconds() if s.duration else 0
    err = s.error_rate * 100
    err_txt = f"{err:.1f}%"
    err_txt = st.red(err_txt) if err >= 10 else st.yellow(err_txt) if err >= 3 else st.green(err_txt)
    lines += [
        f"  Запросов:        {s.total:,}".replace(",", " "),
        f"  Уникальных IP:   {s.unique_ips:,}".replace(",", " "),
        f"  Передано:        {human_bytes(s.bytes_total)}",
        f"  Период:          {s.first:%Y-%m-%d %H:%M} — {s.last:%Y-%m-%d %H:%M} ({human_duration(dur)})",
        f"  Доля ошибок:     {err_txt} (4xx: {s.status_classes['4xx']}, 5xx: {s.status_classes['5xx']})",
        f"  Доля ботов:      {s.bot_share * 100:.1f}%",
    ]
    if report.malformed:
        lines.append(st.yellow(f"  Не разобрано:    {report.malformed} строк из {report.lines_total}"))
    rt = s.response_time_summary()
    if rt:
        lines.append(f"  Время ответа:    сред. {fmt_ms(rt['avg'])}, p50 {fmt_ms(rt['p50'])}, "
                     f"p95 {fmt_ms(rt['p95'])}, макс. {fmt_ms(rt['max'])}")

    section("Подозрительная активность")
    if not report.findings:
        lines.append(st.green("  Ничего подозрительного не найдено."))
    for f in report.findings:
        sev = SEVERITY_LABEL[f.severity]
        sev = st.red(sev) if f.severity == "high" else st.yellow(sev) if f.severity == "medium" else st.dim(sev)
        who = f.ip or "все IP"
        lines.append(f"  [{sev}] {st.bold(KIND_LABEL.get(f.kind, f.kind))} · {who} · "
                     f"{f.first:%Y-%m-%d %H:%M}–{f.last:%H:%M}")
        lines.append(f"      {f.title}")
        if f.samples:
            lines.append(st.dim("      примеры: " + ", ".join(_truncate(x, 60) for x in f.samples[:3])))

    section("Коды ответа")
    lines += _table(sorted(s.status_classes.items()), s.total, st, width, 12)
    section(f"Топ-{n} путей")
    lines += _table(s.paths.most_common(n), s.total, st, width)
    section(f"Топ-{n} IP")
    lines += _table(s.ips.most_common(n), s.total, st, width, 20)
    if s.error_paths:
        section(f"Топ-{n} путей с 4xx")
        lines += _table(s.error_paths.most_common(n), s.total, st, width)
    if s.server_error_paths:
        section(f"Топ-{n} путей с 5xx")
        lines += _table(s.server_error_paths.most_common(n), s.total, st, width)
    section(f"Топ-{n} User-Agent")
    lines += _table(s.user_agents.most_common(n), s.total, st, width, 60)
    if s.referers:
        section(f"Топ-{n} рефереров")
        lines += _table(s.referers.most_common(n), s.total, st, width)
    if rt:
        section("Самые медленные пути (среднее время ответа)")
        for p, avg, c in s.slowest_paths(n):
            lines.append(f"  {_truncate(p, 48):<48} {fmt_ms(avg):>9}  ({c} запр.)")

    section("Нагрузка по часам суток")
    lines += _table([(f"{h:02d}:00", s.hours.get(h, 0)) for h in range(24)], s.total, st, width, 6) \
        if s.hours else []
    return "\n".join(lines) + "\n"
