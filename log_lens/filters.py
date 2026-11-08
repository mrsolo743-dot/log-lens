"""Фильтры записей лога: по времени, статусу, пути, IP, методу и ботам."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone

from .parser import LogEntry

BOT_RE = re.compile(
    r"bot|crawl|spider|slurp|curl|wget|python-requests|httpclient|go-http-client|"
    r"scanner|nikto|sqlmap|masscan|zgrab|nmap|headless",
    re.IGNORECASE,
)


def is_bot(user_agent: str) -> bool:
    """Грубая эвристика: похож ли User-Agent на бота или скрипт."""
    return user_agent in ("", "-") or bool(BOT_RE.search(user_agent))


def parse_datetime(value: str, end: bool = False, tz: timezone | None = None) -> datetime:
    """Разбирает дату для ``--since``/``--until``.

    Форматы: ``2026-11-08``, ``2026-11-08 14:30``, ``2026-11-08T14:30:00``,
    ``2026-11-08T14:30:00+05:00``. Для даты без времени и ``end=True``
    возвращается конец дня. Без указания зоны используется ``tz`` (по умолчанию UTC).
    """
    value = value.strip()
    tz = tz or timezone.utc
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"не удалось разобрать дату {value!r}: ожидается ГГГГ-ММ-ДД[ ЧЧ:ММ[:СС]]") from exc
    date_only = len(value) == 10
    if date_only and end:
        dt = datetime.combine(dt.date(), time.max)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt


def parse_status_spec(spec: str) -> Callable[[int], bool]:
    """Разбирает фильтр статусов: ``404``, ``4xx``, ``500-599``, ``4xx,301``, ``!2xx``."""
    spec = spec.strip()
    negate = spec.startswith("!")
    if negate:
        spec = spec[1:]
    checks: list[Callable[[int], bool]] = []
    for part in filter(None, (p.strip().lower() for p in spec.split(","))):
        if re.fullmatch(r"[1-5]xx", part):
            cls = int(part[0])
            checks.append(lambda s, c=cls: s // 100 == c)
        elif re.fullmatch(r"\d{3}-\d{3}", part):
            lo, hi = map(int, part.split("-"))
            if lo > hi:
                raise ValueError(f"неверный диапазон статусов: {part}")
            checks.append(lambda s, lo=lo, hi=hi: lo <= s <= hi)
        elif re.fullmatch(r"\d{3}", part):
            code = int(part)
            checks.append(lambda s, code=code: s == code)
        else:
            raise ValueError(f"неверный фильтр статуса: {part!r} (примеры: 404, 4xx, 500-599)")
    if not checks:
        raise ValueError("пустой фильтр статуса")

    def match(status: int) -> bool:
        result = any(c(status) for c in checks)
        return not result if negate else result

    return match


def _ip_matcher(spec: str) -> Callable[[str], bool]:
    nets = []
    for part in filter(None, (p.strip() for p in spec.split(","))):
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError as exc:
            raise ValueError(f"неверный IP или подсеть: {part!r}") from exc

    def match(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in nets)

    return match


@dataclass
class EntryFilter:
    """Набор условий. Запись проходит, если удовлетворяет всем заданным условиям."""

    since: datetime | None = None
    until: datetime | None = None
    status: str | None = None
    path: str | None = None          # регулярное выражение
    ip: str | None = None            # IP или подсеть, через запятую
    method: str | None = None        # GET,POST
    exclude_bots: bool = False
    only_bots: bool = False
    _checks: list = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.exclude_bots and self.only_bots:
            raise ValueError("нельзя одновременно исключать и оставлять только ботов")
        if self.since and self.until and self.since > self.until:
            raise ValueError("--since позже --until")
        if self.since:
            self._checks.append(lambda e: e.time >= self.since)
        if self.until:
            self._checks.append(lambda e: e.time <= self.until)
        if self.status:
            st = parse_status_spec(self.status)
            self._checks.append(lambda e: st(e.status))
        if self.path:
            try:
                rx = re.compile(self.path)
            except re.error as exc:
                raise ValueError(f"неверное регулярное выражение пути: {exc}") from exc
            self._checks.append(lambda e: rx.search(e.path) is not None)
        if self.ip:
            ipm = _ip_matcher(self.ip)
            self._checks.append(lambda e: ipm(e.ip))
        if self.method:
            methods = {m.strip().upper() for m in self.method.split(",") if m.strip()}
            self._checks.append(lambda e: e.method in methods)
        if self.exclude_bots:
            self._checks.append(lambda e: not is_bot(e.user_agent))
        if self.only_bots:
            self._checks.append(lambda e: is_bot(e.user_agent))

    @property
    def active(self) -> bool:
        return bool(self._checks)

    def describe(self) -> list[str]:
        """Человекочитаемый список активных фильтров (для отчёта)."""
        out = []
        if self.since:
            out.append(f"с {self.since:%Y-%m-%d %H:%M}")
        if self.until:
            out.append(f"по {self.until:%Y-%m-%d %H:%M}")
        if self.status:
            out.append(f"статус {self.status}")
        if self.path:
            out.append(f"путь ~ {self.path}")
        if self.ip:
            out.append(f"IP {self.ip}")
        if self.method:
            out.append(f"метод {self.method.upper()}")
        if self.exclude_bots:
            out.append("без ботов")
        if self.only_bots:
            out.append("только боты")
        return out

    def __call__(self, entry: LogEntry) -> bool:
        return all(check(entry) for check in self._checks)

    def apply(self, entries: Iterable[LogEntry]) -> Iterator[LogEntry]:
        if not self._checks:
            yield from entries
            return
        for e in entries:
            if self(e):
                yield e


def last_period(spec: str, now: datetime) -> datetime:
    """``--last 24h`` / ``30m`` / ``7d`` → момент начала периода относительно ``now``."""
    m = re.fullmatch(r"\s*(\d+)\s*([smhdw])\s*", spec.lower())
    if not m:
        raise ValueError(f"неверный период {spec!r} (примеры: 30m, 24h, 7d)")
    n, unit = int(m.group(1)), m.group(2)
    seconds = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
    return now - timedelta(seconds=n * seconds)
