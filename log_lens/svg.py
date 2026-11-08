"""Простые SVG-графики без внешних библиотек.

Цвета не зашиты в SVG: элементы получают CSS-классы (``s-main``, ``s-err``,
``c-2xx`` ...), а палитра задаётся стилями HTML-отчёта (светлая и тёмная тема).
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import datetime, timedelta
from html import escape


def _nice_max(value: float) -> float:
    """Округляет максимум шкалы вверх до «красивого» числа (1, 2, 5 × 10^n)."""
    if value <= 0:
        return 1
    exp = 10 ** math.floor(math.log10(value))
    for m in (1, 2, 2.5, 5, 10):
        if value <= m * exp:
            return m * exp
    return 10 * exp


def _fmt_num(v: float) -> str:
    if v >= 1_000_000:
        return f"{round(v / 1_000_000, 1):g}M"
    if v >= 1000:
        return f"{round(v / 1000, 1):g}k"
    return f"{v:g}"


def _grid(w, h, pad_l, pad_t, plot_w, plot_h, ymax, ticks=4) -> list[str]:
    out = []
    for i in range(ticks + 1):
        v = ymax * i / ticks
        y = pad_t + plot_h - plot_h * i / ticks
        out.append(f'<line class="grid" x1="{pad_l}" x2="{pad_l + plot_w}" y1="{y:.1f}" y2="{y:.1f}"/>')
        out.append(f'<text class="axis" x="{pad_l - 6}" y="{y + 4:.1f}" text-anchor="end">{_fmt_num(v)}</text>')
    return out


def column_chart(labels: Sequence[str], values: Sequence[int], *, title: str,
                 width: int = 640, height: int = 220, highlight_max: bool = True,
                 label_every: int = 1) -> str:
    """Столбчатая диаграмма (по часам, по дням недели)."""
    pad_l, pad_r, pad_t, pad_b = 44, 8, 10, 26
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b
    ymax = _nice_max(max(values, default=0))
    n = max(len(values), 1)
    slot = plot_w / n
    bw = max(slot * 0.72, 1)
    peak = max(values, default=0)
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}">']
    parts += _grid(width, height, pad_l, pad_t, plot_w, plot_h, ymax)
    for i, (lab, v) in enumerate(zip(labels, values)):
        x = pad_l + i * slot + (slot - bw) / 2
        bh = plot_h * v / ymax if ymax else 0
        y = pad_t + plot_h - bh
        cls = "bar peak" if highlight_max and v == peak and v > 0 else "bar"
        parts.append(f'<rect class="{cls}" x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{max(bh, 0):.1f}" rx="2">'
                     f'<title>{escape(lab)}: {v}</title></rect>')
        if i % label_every == 0:
            parts.append(f'<text class="axis" x="{x + bw / 2:.1f}" y="{height - 8}" text-anchor="middle">{escape(lab)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _time_label(t: datetime, step: timedelta, span: timedelta) -> str:
    if step >= timedelta(days=1) or span > timedelta(days=3):
        return t.strftime("%d.%m")
    if span > timedelta(hours=20):
        return t.strftime("%d.%m %H:%M")
    return t.strftime("%H:%M")


def timeline_chart(series: Sequence[tuple[datetime, int, int]], step: timedelta, *,
                   title: str, width: int = 960, height: int = 260) -> str:
    """Линейный график запросов и ошибок во времени (площадь + линия ошибок)."""
    if not series:
        return '<p class="muted">Нет данных для графика.</p>'
    pad_l, pad_r, pad_t, pad_b = 48, 12, 12, 28
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b
    ymax = _nice_max(max(c for _, c, _ in series))
    n = len(series)
    dx = plot_w / max(n - 1, 1)

    def pt(i, v):
        return pad_l + i * dx, pad_t + plot_h - plot_h * v / ymax

    main = [pt(i, c) for i, (_, c, _) in enumerate(series)]
    errs = [pt(i, e) for i, (_, _, e) in enumerate(series)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in main)
    area = f"{pad_l:.1f},{pad_t + plot_h:.1f} {line} {main[-1][0]:.1f},{pad_t + plot_h:.1f}"
    err_line = " ".join(f"{x:.1f},{y:.1f}" for x, y in errs)
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}">']
    parts += _grid(width, height, pad_l, pad_t, plot_w, plot_h, ymax)
    parts.append(f'<polygon class="s-area" points="{area}"/>')
    parts.append(f'<polyline class="s-main" points="{line}"/>')
    parts.append(f'<polyline class="s-err" points="{err_line}"/>')
    span = series[-1][0] - series[0][0]
    ticks = min(6, n)
    for k in range(ticks):
        i = round(k * (n - 1) / max(ticks - 1, 1))
        x = pad_l + i * dx
        anchor = "start" if k == 0 else "end" if k == ticks - 1 else "middle"
        parts.append(f'<text class="axis" x="{x:.1f}" y="{height - 8}" text-anchor="{anchor}">'
                     f'{escape(_time_label(series[i][0], step, span))}</text>')
    # невидимые полосы для подсказок при наведении
    for i, (t, c, e) in enumerate(series):
        x = pad_l + i * dx - dx / 2
        parts.append(f'<rect class="hover" x="{max(x, pad_l):.1f}" y="{pad_t}" width="{max(dx, 1):.1f}" '
                     f'height="{plot_h}"><title>{t:%Y-%m-%d %H:%M} — запросов: {c}, ошибок: {e}</title></rect>')
    parts.append("</svg>")
    return "".join(parts)


def donut_chart(items: Sequence[tuple[str, int]], *, title: str, size: int = 200) -> str:
    """Кольцевая диаграмма. ``items`` — (класс, значение), класс становится CSS-классом ``c-<класс>``."""
    total = sum(v for _, v in items)
    r, stroke = size / 2 - 16, 26
    c = 2 * math.pi * r
    cx = cy = size / 2
    parts = [f'<svg class="donut" viewBox="0 0 {size} {size}" role="img" aria-label="{escape(title)}">',
             f'<circle class="donut-bg" cx="{cx}" cy="{cy}" r="{r}" stroke-width="{stroke}"/>']
    offset = 0.0
    for key, v in items:
        if not total or not v:
            continue
        length = c * v / total
        gap = 2 if len([1 for _, x in items if x]) > 1 else 0
        parts.append(
            f'<circle class="seg c-{escape(key)}" cx="{cx}" cy="{cy}" r="{r}" stroke-width="{stroke}" '
            f'stroke-dasharray="{max(length - gap, 0.5):.2f} {c:.2f}" stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"><title>{escape(key)}: {v} ({v / total * 100:.1f}%)</title></circle>')
        offset += length
    parts.append(f'<text class="donut-num" x="{cx}" y="{cy + 2}" text-anchor="middle">{_fmt_num(total)}</text>')
    parts.append(f'<text class="donut-cap" x="{cx}" y="{cy + 20}" text-anchor="middle">запросов</text>')
    parts.append("</svg>")
    return "".join(parts)
