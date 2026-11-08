"""Разбор строк access-логов nginx/Apache.

Поддерживаются форматы:
* ``combined`` — стандартный формат nginx и Apache (с Referer и User-Agent);
* ``common`` — Common Log Format (без Referer и User-Agent);
* ``timed`` — combined + ``$request_time`` в конце строки (время ответа в секундах);
* пользовательский формат в синтаксисе директивы ``log_format`` nginx
  (``$remote_addr - $remote_user [$time_local] "$request" ...``).
"""

from __future__ import annotations

import gzip
import io
import re
import sys
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import TextIO

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

_COMMON_RE = (
    r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\d+|-)'
)
_COMBINED_RE = _COMMON_RE + r' "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<user_agent>(?:[^"\\]|\\.)*)"'

TIMED = re.compile(_COMBINED_RE + r" (?P<request_time>\d+(?:\.\d+)?|-)\s*$")
COMBINED = re.compile(_COMBINED_RE + r"(?:\s.*)?$")
COMMON = re.compile(_COMMON_RE + r"\s*$")

# Переменные nginx -> (имя группы, регулярное выражение)
NGINX_VARIABLES = {
    "remote_addr": ("ip", r"\S+"),
    "remote_user": ("user", r"\S+"),
    "time_local": ("time", r"[^\]]+"),
    "request": ("request", r'(?:[^"\\]|\\.)*'),
    "status": ("status", r"\d{3}"),
    "body_bytes_sent": ("size", r"\d+|-"),
    "bytes_sent": ("size", r"\d+|-"),
    "http_referer": ("referer", r'(?:[^"\\]|\\.)*'),
    "http_user_agent": ("user_agent", r'(?:[^"\\]|\\.)*'),
    "request_time": ("request_time", r"[\d.]+|-"),
    "upstream_response_time": ("upstream_time", r"[\d.,: ]+|-"),
    "host": ("host", r"\S+"),
    "http_x_forwarded_for": ("forwarded_for", r'(?:[^"\\]|\\.)*'),
}


class LogFormatError(ValueError):
    """Ошибка в описании пользовательского формата лога."""


@dataclass
class LogEntry:
    """Одна разобранная строка лога."""

    ip: str
    time: datetime
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referer: str = "-"
    user_agent: str = "-"
    user: str = "-"
    request_time: float | None = None
    host: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def status_class(self) -> str:
        """Класс ответа: ``2xx``, ``3xx``, ``4xx`` или ``5xx``."""
        return f"{self.status // 100}xx"

    @property
    def is_error(self) -> bool:
        return self.status >= 400


def compile_nginx_format(fmt: str) -> re.Pattern:
    """Превращает строку ``log_format`` nginx в регулярное выражение.

    Неизвестные переменные допускаются: они сохраняются в ``LogEntry.extra``.
    Обязательные поля: ``$remote_addr``, ``$time_local``, ``$request``, ``$status``.
    """
    parts = []
    used = set()
    pos = 0
    for m in re.finditer(r"\$\{?([a-z_][a-z0-9_]*)\}?", fmt):
        parts.append(re.escape(fmt[pos:m.start()]))
        name = m.group(1)
        group, pattern = NGINX_VARIABLES.get(name, (f"x_{name}", r"\S+"))
        # если после переменной идёт кавычка — разрешаем любой текст до кавычки
        if group.startswith("x_") and fmt[m.end():m.end() + 1] == '"':
            pattern = r'(?:[^"\\]|\\.)*'
        if group in used:
            parts.append(f"(?:{pattern})")
        else:
            parts.append(f"(?P<{group}>{pattern})")
            used.add(group)
        pos = m.end()
    parts.append(re.escape(fmt[pos:]))
    missing = {"ip", "time", "request", "status"} - used
    if missing:
        names = {"ip": "$remote_addr", "time": "$time_local", "request": "$request", "status": "$status"}
        raise LogFormatError(
            "в формате не хватает обязательных переменных: "
            + ", ".join(sorted(names[g] for g in missing))
        )
    # пробелы в формате могут быть растянуты табуляцией или несколькими пробелами
    regex = "".join(parts).replace(r"\ ", r"\s+")
    return re.compile("^" + regex + r"\s*$")


def _unescape(value: str) -> str:
    if "\\" not in value:
        return value
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _split_request(request: str) -> tuple[str, str, str]:
    parts = request.split(" ")
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], "-"
    # пустой запрос ("-") или мусор от сканеров
    return "-", request or "-", "-"


def _to_float(value: str | None) -> float | None:
    if value in (None, "", "-"):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def entry_from_match(m: re.Match) -> LogEntry:
    """Строит ``LogEntry`` из совпадения любого из регулярных выражений."""
    d = m.groupdict()
    method, path, protocol = _split_request(_unescape(d["request"]))
    size = d.get("size")
    extra = {k[2:]: v for k, v in d.items() if k.startswith("x_")}
    for key in ("upstream_time", "forwarded_for"):
        if d.get(key) is not None:
            extra[key] = d[key]
    return LogEntry(
        ip=d["ip"],
        time=datetime.strptime(d["time"], TIME_FORMAT),
        method=method.upper() if method != "-" else method,
        path=path,
        protocol=protocol,
        status=int(d["status"]),
        size=int(size) if size and size != "-" else 0,
        referer=_unescape(d.get("referer") or "-"),
        user_agent=_unescape(d.get("user_agent") or "-"),
        user=d.get("user") or "-",
        request_time=_to_float(d.get("request_time")),
        host=d.get("host"),
        extra=extra,
    )


class LogParser:
    """Парсер строк лога с автоопределением формата.

    ``fmt``: ``"auto"``, ``"timed"``, ``"combined"``, ``"common"`` или строка в синтаксисе
    ``log_format`` nginx (содержит ``$``).
    """

    def __init__(self, fmt: str = "auto"):
        self.fmt = fmt
        self.malformed = 0
        self.total_lines = 0
        self.bad_samples: list[str] = []
        if fmt == "auto":
            self._patterns = [TIMED, COMBINED, COMMON]
        elif fmt == "timed":
            self._patterns = [TIMED]
        elif fmt == "combined":
            self._patterns = [COMBINED]
        elif fmt == "common":
            self._patterns = [COMMON]
        elif "$" in fmt:
            self._patterns = [compile_nginx_format(fmt)]
        else:
            raise LogFormatError(f"неизвестный формат: {fmt!r}")

    def parse_line(self, line: str) -> LogEntry | None:
        """Разбирает строку. Возвращает ``None`` для пустых и битых строк."""
        line = line.rstrip("\r\n")
        if not line.strip():
            return None
        self.total_lines += 1
        for i, pattern in enumerate(self._patterns):
            m = pattern.match(line)
            if m:
                try:
                    entry = entry_from_match(m)
                except ValueError:
                    break
                if i and self.fmt == "auto":
                    # формат нашёлся не с первой попытки — пробуем его первым
                    self._patterns.insert(0, self._patterns.pop(i))
                return entry
        self.malformed += 1
        if len(self.bad_samples) < 5:
            self.bad_samples.append(line[:200])
        return None

    def parse(self, lines: Iterable[str]) -> Iterator[LogEntry]:
        for line in lines:
            entry = self.parse_line(line)
            if entry is not None:
                yield entry


def open_log(path: str) -> TextIO:
    """Открывает лог: обычный файл, ``.gz`` или ``-`` (stdin)."""
    if path == "-":
        return io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
    with open(path, "rb") as fh:
        magic = fh.read(2)
    if magic == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def read_entries(paths: Iterable[str], parser: LogParser,
                 on_file: Callable[[str], None] | None = None) -> Iterator[LogEntry]:
    """Последовательно читает записи из нескольких файлов."""
    for path in paths:
        if on_file:
            on_file(path)
        with open_log(path) as fh:
            yield from parser.parse(fh)
