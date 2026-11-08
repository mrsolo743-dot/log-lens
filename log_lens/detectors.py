"""Поиск подозрительной активности в логах.

Детекторы:
* ``scanner``     — IP перебирает известные «чувствительные» пути (/.env, /wp-login.php, /.git ...);
* ``404-burst``   — IP получает много 404 за короткое окно (перебор URL);
* ``bruteforce``  — много POST-запросов к страницам входа за короткое окно;
* ``rate``        — один IP шлёт слишком много запросов в минуту (флуд, агрессивный парсер);
* ``spike``       — общий всплеск трафика: минута, сильно выбивающаяся из среднего.
"""

from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from .parser import LogEntry

SENSITIVE_RE = re.compile(
    r"(/\.env|/\.git/|/\.svn|/\.aws|/\.ds_store|/wp-login\.php|/wp-admin|/xmlrpc\.php|"
    r"/phpmyadmin|/pma/|/adminer|/server-status|/config\.(php|json|yml)|/backup|\.sql(\.gz)?$|"
    r"/etc/passwd|/cgi-bin/|/vendor/phpunit|/shell|/boaform|/actuator|/console|"
    r"\.\./|%2e%2e|/id_rsa|/\.htaccess|/\.htpasswd)",
    re.IGNORECASE,
)
LOGIN_RE = re.compile(r"(login|signin|sign-in|auth|wp-login\.php|xmlrpc\.php|/session|/token)", re.IGNORECASE)

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class DetectorConfig:
    scanner_min_hits: int = 5
    burst_404_count: int = 20
    burst_404_window: timedelta = timedelta(minutes=5)
    brute_count: int = 10
    brute_window: timedelta = timedelta(minutes=10)
    rate_per_minute: int = 120
    spike_sigma: float = 4.0
    spike_min_requests: int = 50


@dataclass
class Finding:
    kind: str
    severity: str
    title: str
    ip: str | None
    count: int
    first: datetime
    last: datetime
    samples: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["first"] = self.first.isoformat()
        d["last"] = self.last.isoformat()
        return d


def _max_window(times: list[datetime], window: timedelta) -> tuple[int, datetime, datetime]:
    """Максимальное число событий в скользящем окне и границы этого окна."""
    times = sorted(times)
    best, best_lo, best_hi = 0, times[0], times[0]
    q: deque = deque()
    for t in times:
        q.append(t)
        while t - q[0] > window:
            q.popleft()
        if len(q) > best:
            best, best_lo, best_hi = len(q), q[0], t
    return best, best_lo, best_hi


def _severity(count: int, threshold: int) -> str:
    if count >= threshold * 5:
        return "high"
    if count >= threshold * 2:
        return "medium"
    return "low"


class Detector:
    """Накопитель для детекторов. ``feed(entry)`` для каждой записи, затем ``findings()``."""

    def __init__(self, config: DetectorConfig | None = None):
        self.cfg = config or DetectorConfig()
        self._sensitive: dict[str, list] = defaultdict(list)
        self._404: dict[str, list] = defaultdict(list)
        self._404_paths: dict[str, Counter] = defaultdict(Counter)
        self._login: dict[str, list] = defaultdict(list)
        self._login_ok: dict[str, int] = Counter()
        self._login_paths: dict[str, Counter] = defaultdict(Counter)
        self._ip_minute: Counter = Counter()
        self._minute: Counter = Counter()

    def feed(self, e: LogEntry) -> None:
        if SENSITIVE_RE.search(e.path):
            self._sensitive[e.ip].append((e.time, e.path, e.status))
        if e.status == 404:
            self._404[e.ip].append(e.time)
            self._404_paths[e.ip][e.path] += 1
        if e.method == "POST" and LOGIN_RE.search(e.path):
            self._login[e.ip].append(e.time)
            self._login_paths[e.ip][f"{e.path} → {e.status}"] += 1
            if e.status < 400:
                self._login_ok[e.ip] += 1
        minute = e.time.replace(second=0, microsecond=0)
        self._ip_minute[(e.ip, minute)] += 1
        self._minute[minute] += 1

    def feed_all(self, entries: Iterable[LogEntry]) -> list[Finding]:
        for e in entries:
            self.feed(e)
        return self.findings()

    # ---- отдельные детекторы ----
    def _scanners(self) -> list[Finding]:
        out = []
        for ip, hits in self._sensitive.items():
            if len(hits) < self.cfg.scanner_min_hits:
                continue
            hits.sort()
            paths = Counter(p for _, p, _ in hits)
            ok = sum(1 for _, _, s in hits if s < 400)
            title = f"Сканирование уязвимостей: {len(paths)} уникальных чувствительных путей"
            if ok:
                title += f", {ok} с успешным ответом!"
            out.append(Finding(
                kind="scanner",
                severity="high" if ok else _severity(len(hits), self.cfg.scanner_min_hits),
                title=title,
                ip=ip, count=len(hits), first=hits[0][0], last=hits[-1][0],
                samples=[p for p, _ in paths.most_common(5)],
            ))
        return out

    def _bursts_404(self, skip: frozenset = frozenset()) -> list[Finding]:
        out = []
        for ip, times in self._404.items():
            if ip in skip or len(times) < self.cfg.burst_404_count:
                continue
            n, lo, hi = _max_window(times, self.cfg.burst_404_window)
            if n >= self.cfg.burst_404_count:
                minutes = int(self.cfg.burst_404_window.total_seconds() // 60)
                out.append(Finding(
                    kind="404-burst", severity=_severity(n, self.cfg.burst_404_count),
                    title=f"Всплеск 404: {n} за {minutes} мин (всего 404 от IP: {len(times)})",
                    ip=ip, count=n, first=lo, last=hi,
                    samples=[p for p, _ in self._404_paths[ip].most_common(5)],
                ))
        return out

    def _bruteforce(self) -> list[Finding]:
        out = []
        for ip, times in self._login.items():
            if len(times) < self.cfg.brute_count:
                continue
            n, lo, hi = _max_window(times, self.cfg.brute_window)
            if n >= self.cfg.brute_count:
                minutes = int(self.cfg.brute_window.total_seconds() // 60)
                ok = self._login_ok.get(ip, 0)
                title = f"Подбор пароля: {n} POST-запросов на вход за {minutes} мин"
                if ok:
                    title += f"; успешных ответов: {ok} — возможно, пароль подобран!"
                out.append(Finding(
                    kind="bruteforce", severity="high" if ok else _severity(n, self.cfg.brute_count),
                    title=title,
                    ip=ip, count=n, first=lo, last=hi,
                    samples=[p for p, _ in self._login_paths[ip].most_common(5)],
                ))
        return out

    def _rate(self) -> list[Finding]:
        per_ip: dict[str, list] = defaultdict(list)
        for (ip, minute), n in self._ip_minute.items():
            if n >= self.cfg.rate_per_minute:
                per_ip[ip].append((minute, n))
        out = []
        for ip, rows in per_ip.items():
            rows.sort()
            peak = max(n for _, n in rows)
            out.append(Finding(
                kind="rate", severity=_severity(peak, self.cfg.rate_per_minute),
                title=f"Высокая частота: до {peak} запросов/мин ({len(rows)} мин выше порога)",
                ip=ip, count=peak, first=rows[0][0], last=rows[-1][0] + timedelta(minutes=1),
                samples=[f"{m:%H:%M} — {n}" for m, n in sorted(rows, key=lambda r: -r[1])[:5]],
            ))
        return out

    def _spikes(self) -> list[Finding]:
        if len(self._minute) < 10:
            return []
        # заполняем пустые минуты нулями, иначе среднее получится завышенным
        lo, hi = min(self._minute), max(self._minute)
        span = int((hi - lo).total_seconds() // 60) + 1
        if span > 500_000:
            values = list(self._minute.values())
        else:
            values = [self._minute.get(lo + timedelta(minutes=i), 0) for i in range(span)]
        mean = statistics.fmean(values)
        sd = statistics.pstdev(values)
        limit = max(mean + self.cfg.spike_sigma * sd, self.cfg.spike_min_requests)
        hot = sorted((m, n) for m, n in self._minute.items() if n >= limit)
        if not hot:
            return []
        # склеиваем соседние минуты в эпизоды
        episodes, cur = [], [hot[0]]
        for m, n in hot[1:]:
            if m - cur[-1][0] <= timedelta(minutes=2):
                cur.append((m, n))
            else:
                episodes.append(cur)
                cur = [(m, n)]
        episodes.append(cur)
        out = []
        for ep in episodes:
            peak = max(n for _, n in ep)
            out.append(Finding(
                kind="spike", severity="medium" if peak >= limit * 2 else "low",
                title=f"Всплеск трафика: пик {peak} запросов/мин при среднем {mean:.1f}",
                ip=None, count=peak, first=ep[0][0], last=ep[-1][0] + timedelta(minutes=1),
                samples=[f"{m:%Y-%m-%d %H:%M} — {n}" for m, n in ep[:5]],
            ))
        return out

    def findings(self) -> list[Finding]:
        scanners = self._scanners()
        # 404 от сканера — следствие сканирования, отдельное событие не дублируем
        skip = frozenset(f.ip for f in scanners)
        result = scanners + self._bruteforce() + self._bursts_404(skip) + self._rate() + self._spikes()
        result.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.count))
        return result
