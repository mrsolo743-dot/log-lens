"""Агрегация статистики по записям лога (за один проход, без хранения всех записей)."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .filters import is_bot
from .parser import LogEntry

RESPONSE_TIME_SAMPLE = 100_000  # сколько значений request_time держать для перцентилей


def percentile(values: list[float], q: float) -> float | None:
    """Перцентиль с линейной интерполяцией (``q`` от 0 до 100)."""
    if not values:
        return None
    data = sorted(values)
    if len(data) == 1:
        return data[0]
    k = (len(data) - 1) * q / 100
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return data[int(k)]
    return data[lo] + (data[hi] - data[lo]) * (k - lo)


def normalize_path(path: str, strip_query: bool = True) -> str:
    """Убирает query-строку (``/a?b=1`` → ``/a``), чтобы группировать одинаковые страницы."""
    if strip_query:
        path = path.split("?", 1)[0]
    return path or "/"


@dataclass
class Stats:
    """Итоговая статистика по логу."""

    total: int = 0
    bytes_total: int = 0
    first: datetime | None = None
    last: datetime | None = None
    statuses: Counter = field(default_factory=Counter)
    status_classes: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    ips: Counter = field(default_factory=Counter)
    user_agents: Counter = field(default_factory=Counter)
    referers: Counter = field(default_factory=Counter)
    error_paths: Counter = field(default_factory=Counter)      # 4xx
    server_error_paths: Counter = field(default_factory=Counter)  # 5xx
    hours: Counter = field(default_factory=Counter)            # час суток 0..23
    weekdays: Counter = field(default_factory=Counter)         # 0 = понедельник
    timeline: Counter = field(default_factory=Counter)         # начало интервала -> запросов
    timeline_errors: Counter = field(default_factory=Counter)
    bytes_by_path: Counter = field(default_factory=Counter)
    bot_requests: int = 0
    response_times: list = field(default_factory=list)
    slow_paths: dict = field(default_factory=lambda: defaultdict(list))
    timeline_step: timedelta = timedelta(hours=1)

    # ---- производные показатели ----
    @property
    def unique_ips(self) -> int:
        return len(self.ips)

    @property
    def error_rate(self) -> float:
        if not self.total:
            return 0.0
        return (self.status_classes["4xx"] + self.status_classes["5xx"]) / self.total

    @property
    def bot_share(self) -> float:
        return self.bot_requests / self.total if self.total else 0.0

    @property
    def duration(self) -> timedelta | None:
        if self.first and self.last:
            return self.last - self.first
        return None

    def response_time_summary(self) -> dict | None:
        if not self.response_times:
            return None
        rt = self.response_times
        return {
            "count": len(rt),
            "avg": sum(rt) / len(rt),
            "p50": percentile(rt, 50),
            "p95": percentile(rt, 95),
            "p99": percentile(rt, 99),
            "max": max(rt),
        }

    def slowest_paths(self, n: int = 10) -> list[tuple[str, float, int]]:
        """Пути с наибольшим средним временем ответа: (путь, среднее, кол-во)."""
        rows = [
            (p, sum(v) / len(v), len(v)) for p, v in self.slow_paths.items() if v
        ]
        rows.sort(key=lambda r: r[1], reverse=True)
        return rows[:n]

    def timeline_series(self) -> list[tuple[datetime, int, int]]:
        """Непрерывный ряд (начало интервала, запросы, ошибки) без пропусков."""
        if not self.timeline:
            return []
        start, end = min(self.timeline), max(self.timeline)
        out = []
        t = start
        guard = 0
        while t <= end and guard < 10_000:
            out.append((t, self.timeline[t], self.timeline_errors[t]))
            t += self.timeline_step
            guard += 1
        return out


def choose_step(first: datetime | None, last: datetime | None) -> timedelta:
    """Подбирает шаг временной шкалы так, чтобы точек было не больше ~200."""
    if not first or not last:
        return timedelta(hours=1)
    span = (last - first).total_seconds()
    for step in (60, 300, 900, 3600, 3 * 3600, 6 * 3600, 86400, 7 * 86400):
        if span / step <= 200:
            return timedelta(seconds=step)
    return timedelta(days=30)


def bucket(t: datetime, step: timedelta) -> datetime:
    """Округляет время вниз до шага по *локальному* времени записи
    (чтобы суточные интервалы начинались в полночь часового пояса лога)."""
    seconds = int(step.total_seconds())
    if step >= timedelta(days=7):
        day = t.replace(hour=0, minute=0, second=0, microsecond=0)
        return day - timedelta(days=day.weekday())  # понедельник
    epoch = datetime(1970, 1, 1)
    local = int((t.replace(tzinfo=None) - epoch).total_seconds())
    return (epoch + timedelta(seconds=local - local % seconds)).replace(tzinfo=t.tzinfo)


class Analyzer:
    """Накапливает статистику. Использование: ``feed(entry)`` ... ``stats``.

    Если шаг временной шкалы не задан, сначала все интервалы считаются по минутам,
    а при выдаче результата укрупняются.
    """

    def __init__(self, strip_query: bool = True, timeline_step: timedelta | None = None):
        self.strip_query = strip_query
        self.fixed_step = timeline_step
        self.stats = Stats()
        self._minute = Counter()
        self._minute_err = Counter()

    def feed(self, e: LogEntry) -> None:
        s = self.stats
        s.total += 1
        s.bytes_total += e.size
        if s.first is None or e.time < s.first:
            s.first = e.time
        if s.last is None or e.time > s.last:
            s.last = e.time
        path = normalize_path(e.path, self.strip_query)
        s.statuses[e.status] += 1
        s.status_classes[e.status_class] += 1
        s.methods[e.method] += 1
        s.paths[path] += 1
        s.ips[e.ip] += 1
        s.user_agents[e.user_agent] += 1
        if e.referer not in ("-", ""):
            s.referers[e.referer] += 1
        if 400 <= e.status < 500:
            s.error_paths[path] += 1
        elif e.status >= 500:
            s.server_error_paths[path] += 1
        s.hours[e.time.hour] += 1
        s.weekdays[e.time.weekday()] += 1
        s.bytes_by_path[path] += e.size
        if is_bot(e.user_agent):
            s.bot_requests += 1
        if e.request_time is not None:
            if len(s.response_times) < RESPONSE_TIME_SAMPLE:
                s.response_times.append(e.request_time)
            lst = s.slow_paths[path]
            if len(lst) < 1000:
                lst.append(e.request_time)
        minute = e.time.replace(second=0, microsecond=0)
        self._minute[minute] += 1
        if e.is_error:
            self._minute_err[minute] += 1

    def feed_all(self, entries: Iterable[LogEntry]) -> Stats:
        for e in entries:
            self.feed(e)
        return self.result()

    def result(self) -> Stats:
        s = self.stats
        step = self.fixed_step or choose_step(s.first, s.last)
        s.timeline_step = step
        s.timeline = Counter()
        s.timeline_errors = Counter()
        for minute, n in self._minute.items():
            s.timeline[bucket(minute, step)] += n
        for minute, n in self._minute_err.items():
            s.timeline_errors[bucket(minute, step)] += n
        return s

    @property
    def per_minute(self) -> Counter:
        """Число запросов по минутам (используется детектором всплесков)."""
        return self._minute
