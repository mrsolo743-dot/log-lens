"""Генератор правдоподобных тестовых access-логов (для демо и тестов).

Все IP-адреса берутся из диапазонов, зарезервированных для документации
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), поэтому
логи не содержат адресов реальных людей.
"""

from __future__ import annotations

import math
import random
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TextIO

from .parser import TIME_FORMAT

NETS = ("192.0.2", "198.51.100", "203.0.113")

PAGES = [
    ("/", 30), ("/blog", 10), ("/blog/python-tips", 6), ("/blog/css-grid", 5),
    ("/blog/regex-cheatsheet", 4), ("/about", 4), ("/contact", 3), ("/projects", 6),
    ("/projects/habit-heatmap", 3), ("/projects/md-slides", 3), ("/search?q=python", 3),
    ("/search?q=nginx", 2), ("/api/v1/posts", 8), ("/api/v1/posts?page=2", 3),
    ("/api/v1/stats", 4), ("/rss.xml", 5), ("/sitemap.xml", 2), ("/robots.txt", 2),
]
ASSETS = [
    ("/static/css/main.css", 18000), ("/static/js/app.js", 54000),
    ("/static/img/logo.svg", 3200), ("/static/img/hero.webp", 120000),
    ("/favicon.ico", 4286),
]
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36",
]
BOTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl/8.5.0",
]
REFERERS = ["-", "-", "-", "https://www.google.com/", "https://yandex.ru/", "https://github.com/", "https://t.me/"]
SCAN_PATHS = [
    "/.env", "/.git/config", "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/phpmyadmin/",
    "/admin/config.php", "/backup.sql", "/server-status", "/.aws/credentials",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/luci", "/.DS_Store",
    "/config.json", "/actuator/env", "/.htpasswd", "/db.sql.gz", "/shell.php",
]


@dataclass
class GeneratorConfig:
    lines: int = 5000
    start: datetime = datetime(2026, 11, 1, tzinfo=timezone(timedelta(hours=5)))
    days: float = 7.0
    seed: int | None = 42
    with_time: bool = True     # добавлять $request_time в конец строки
    attacks: bool = True       # добавлять сценарии атак


def _ip(rng: random.Random) -> str:
    return f"{rng.choice(NETS)}.{rng.randint(1, 254)}"


def _line(ip, t, method, path, status, size, ref, ua, rt, with_time) -> str:
    s = (f'{ip} - - [{t.strftime(TIME_FORMAT)}] "{method} {path} HTTP/1.1" '
         f'{status} {size} "{ref}" "{ua}"')
    if with_time:
        s += f" {rt:.3f}"
    return s


def _daily_weight(t: datetime) -> float:
    """Суточный профиль: ночью мало трафика, пик около 15:00."""
    h = t.hour + t.minute / 60
    return 0.15 + math.exp(-((h - 15) ** 2) / 18)


def generate(cfg: GeneratorConfig) -> list[tuple[datetime, str]]:
    rng = random.Random(cfg.seed)
    span = timedelta(days=cfg.days).total_seconds()
    visitors = [(_ip(rng), rng.choice(BROWSERS)) for _ in range(250)]
    bots = [(_ip(rng), ua) for ua in BOTS]
    pages, weights = zip(*PAGES)
    rows: list[tuple[datetime, str]] = []

    def add(ip, t, method, path, status, size, ref, ua, rt):
        rows.append((t, _line(ip, t, method, path, status, size, ref, ua, rt, cfg.with_time)))

    while len(rows) < cfg.lines:
        t = cfg.start + timedelta(seconds=rng.random() * span)
        if rng.random() > _daily_weight(t) / 1.15:
            continue  # отбраковка по суточному профилю
        if rng.random() < 0.12:
            ip, ua = rng.choice(bots)
        else:
            ip, ua = rng.choice(visitors)
        path = rng.choices(pages, weights)[0]
        roll = rng.random()
        if roll < 0.80:
            status, size = 200, rng.randint(2_000, 40_000)
        elif roll < 0.88:
            status, size = 304, 0
        elif roll < 0.92:
            status, size = 301, 178
        elif roll < 0.985:
            status, size = 404, 153
            path = rng.choice(["/old-page", "/blog/deleted-post", "/img/missing.png", "/apple-touch-icon.png"])
        else:
            status, size = rng.choice([500, 502, 503]), 0
            path = rng.choice(["/api/v1/stats", "/api/v1/posts", "/search?q=nginx"])
        method = "GET"
        if path.startswith("/api/") and rng.random() < 0.15:
            method = "POST"
        rt = rng.lognormvariate(-3.2, 0.7) * (8 if status >= 500 else 1)
        if "/search" in path:
            rt *= 4
        add(ip, t, method, path, status, size, rng.choice(REFERERS), ua, rt)
        # браузер подгружает статику
        if ua in BROWSERS and status == 200 and not path.startswith("/api") and rng.random() < 0.3:
            for asset, asize in rng.sample(ASSETS, 2):
                at = t + timedelta(milliseconds=rng.randint(50, 900))
                add(ip, at, "GET", asset, 200, asize, f"https://example.com{path}", ua, rng.random() * 0.01)

    if cfg.attacks:
        _attacks(rng, cfg, add)
    rows.sort(key=lambda r: r[0])
    return rows


def _attacks(rng: random.Random, cfg: GeneratorConfig, add) -> None:
    span = cfg.days * 86400

    def at(frac: float) -> datetime:
        return cfg.start + timedelta(seconds=span * frac)

    # 1. сканер уязвимостей
    ip, t = "198.51.100.66", at(0.2)
    for path in SCAN_PATHS * 2:
        t += timedelta(seconds=rng.uniform(0.5, 3))
        status = 200 if path == "/server-status" else 404
        add(ip, t, "GET", path, status, 162, "-", "Mozilla/5.0 zgrab/0.x", 0.002)

    # 2. подбор пароля
    ip, t = "203.0.113.13", at(0.45)
    for _ in range(80):
        t += timedelta(seconds=rng.uniform(1, 6))
        add(ip, t, "POST", "/login", 401, 41, "https://example.com/login", "python-requests/2.32", 0.09)
    add(ip, t + timedelta(seconds=3), "POST", "/login", 302, 0, "https://example.com/login", "python-requests/2.32", 0.08)

    # 3. перебор URL (404)
    ip, t = "192.0.2.200", at(0.6)
    for i in range(60):
        t += timedelta(seconds=rng.uniform(0.5, 4))
        add(ip, t, "GET", f"/files/archive_{i:03d}.zip", 404, 153, "-", "Wget/1.21", 0.003)

    # 4. флуд с одного IP — всплеск трафика
    ip, t = "203.0.113.250", at(0.75).replace(second=0, microsecond=0)
    for _ in range(600):
        t2 = t + timedelta(seconds=rng.uniform(0, 180))
        add(ip, t2, "GET", "/api/v1/posts", 200, 2048, "-", "Go-http-client/1.1", 0.05)


def iter_lines(cfg: GeneratorConfig) -> Iterator[str]:
    for _, line in generate(cfg):
        yield line


def write_log(cfg: GeneratorConfig, out: TextIO) -> int:
    n = 0
    for line in iter_lines(cfg):
        out.write(line + "\n")
        n += 1
    return n
