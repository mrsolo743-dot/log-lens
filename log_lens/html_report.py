"""Автономный HTML-отчёт: один файл без внешних зависимостей (CSS, SVG и JS встроены)."""

from __future__ import annotations

from collections.abc import Iterable
from html import escape

from . import __version__
from .report import (
    KIND_LABEL,
    SEVERITY_LABEL,
    WEEKDAYS,
    Report,
    fmt_ms,
    human_bytes,
    human_duration,
)
from .svg import column_chart, donut_chart, timeline_chart

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#677084;--line:#e3e6ec;--accent:#2f6fde;
--accent-soft:rgba(47,111,222,.14);--err:#d64545;--warn:#c98a12;--ok:#2e9f62;--c3:#4f7fd9;
--bar:#2f6fde;--peak:#1b4fb0;--chip:#eef1f6;--shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08)}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f1218;--card:#171b23;--text:#e6e9ef;
--muted:#9099ab;--line:#2a303c;--accent:#6e9bff;--accent-soft:rgba(110,155,255,.18);--err:#ff6b6b;--warn:#f0b33a;
--ok:#4cc38a;--c3:#7ea3f0;--bar:#6e9bff;--peak:#a9c2ff;--chip:#222836;--shadow:none}}
:root[data-theme=dark]{--bg:#0f1218;--card:#171b23;--text:#e6e9ef;--muted:#9099ab;--line:#2a303c;--accent:#6e9bff;
--accent-soft:rgba(110,155,255,.18);--err:#ff6b6b;--warn:#f0b33a;--ok:#4cc38a;--c3:#7ea3f0;--bar:#6e9bff;
--peak:#a9c2ff;--chip:#222836;--shadow:none}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-start;justify-content:space-between;margin-bottom:20px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:0 0 12px}
.muted{color:var(--muted)}.small{font-size:13px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.chip{background:var(--chip);border-radius:999px;padding:2px 10px;font-size:12.5px;color:var(--muted);word-break:break-all}
button.theme{border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:8px;padding:6px 12px;cursor:pointer;font:inherit}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}
.kpi,.card{background:var(--card);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}
.kpi{padding:14px 16px}.kpi .v{font-size:24px;font-weight:650;letter-spacing:-.01em}.kpi .l{color:var(--muted);font-size:13px}
.kpi.bad .v{color:var(--err)}.kpi.warn .v{color:var(--warn)}.kpi.good .v{color:var(--ok)}
.card{padding:16px;margin-bottom:16px;min-width:0}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,460px),1fr));gap:16px}
.grid2>.card{margin-bottom:0}.row{margin-bottom:16px}
svg.chart{width:100%;height:auto;display:block}
svg .grid{stroke:var(--line);stroke-width:1}
svg .axis{fill:var(--muted);font-size:11px}
svg .bar{fill:var(--bar);opacity:.75}svg .bar.peak{fill:var(--peak);opacity:1}svg .bar:hover{opacity:1}
svg .s-area{fill:var(--accent-soft)}svg .s-main{fill:none;stroke:var(--accent);stroke-width:2;stroke-linejoin:round}
svg .s-err{fill:none;stroke:var(--err);stroke-width:1.6;stroke-linejoin:round}
svg .hover{fill:transparent}svg .hover:hover{fill:var(--accent-soft)}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:13px;color:var(--muted);margin-top:6px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px}
.donut-wrap{display:flex;gap:20px;align-items:center;flex-wrap:wrap}
svg.donut{width:180px;height:180px;flex:none}
.donut-bg{fill:none;stroke:var(--chip)}.seg{fill:none}
.c-2xx{stroke:var(--ok)}.c-3xx{stroke:var(--c3)}.c-4xx{stroke:var(--warn)}.c-5xx{stroke:var(--err)}.c-1xx{stroke:var(--muted)}
.bg-2xx{background:var(--ok)}.bg-3xx{background:var(--c3)}.bg-4xx{background:var(--warn)}.bg-5xx{background:var(--err)}.bg-1xx{background:var(--muted)}
.donut-num{fill:var(--text);font-size:26px;font-weight:650}.donut-cap{fill:var(--muted);font-size:12px}
.status-list{list-style:none;padding:0;margin:0;font-size:14px}.status-list li{margin:4px 0}
.finding{border-left:4px solid var(--muted);padding:10px 12px;margin:10px 0;background:var(--chip);border-radius:0 8px 8px 0}
.finding.high{border-color:var(--err)}.finding.medium{border-color:var(--warn)}.finding.low{border-color:var(--c3)}
.badge{font-size:11px;font-weight:700;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:var(--muted);margin-right:6px}
.badge.high{background:var(--err)}.badge.medium{background:var(--warn)}.badge.low{background:var(--c3)}
.finding code{font-size:12.5px}
.ok-box{color:var(--ok);font-weight:600}
.tbl-tools{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap}
.tbl-tools h2{margin:0}
input.search{border:1px solid var(--line);background:var(--bg);color:var(--text);border-radius:8px;padding:5px 10px;font:inherit;font-size:13px;width:180px;max-width:100%}
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;cursor:pointer;user-select:none;white-space:nowrap}
th[data-sort]::after{content:" ↕";opacity:.4}th.asc::after{content:" ↑";opacity:1}th.desc::after{content:" ↓";opacity:1}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}th.num{text-align:right}
td.key{word-break:break-all;max-width:520px}
.meter{height:6px;background:var(--chip);border-radius:3px;min-width:60px}.meter span{display:block;height:100%;background:var(--bar);border-radius:3px}
code{background:var(--chip);border-radius:4px;padding:1px 5px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
footer{margin-top:24px;font-size:12.5px;color:var(--muted);text-align:center}
@media (max-width:600px){.kpi .v{font-size:20px}h1{font-size:20px}}
"""

JS = """
(function(){
  var root=document.documentElement, btn=document.getElementById('theme');
  var order=['auto','light','dark'], names={auto:'Тема: авто',light:'Тема: светлая',dark:'Тема: тёмная'};
  function apply(m){ if(m==='auto') root.removeAttribute('data-theme'); else root.setAttribute('data-theme',m); btn.textContent=names[m]; }
  var mode='auto'; try{ mode=localStorage.getItem('log-lens-theme')||'auto'; }catch(e){}
  apply(mode);
  btn.addEventListener('click',function(){ mode=order[(order.indexOf(mode)+1)%3]; apply(mode); try{localStorage.setItem('log-lens-theme',mode);}catch(e){} });

  document.querySelectorAll('table.sortable').forEach(function(tbl){
    var tbody=tbl.tBodies[0];
    tbl.querySelectorAll('th[data-sort]').forEach(function(th,idx){
      th.addEventListener('click',function(){
        var col=th.cellIndex, num=th.dataset.sort==='num', asc=!th.classList.contains('asc');
        tbl.querySelectorAll('th').forEach(function(x){x.classList.remove('asc','desc');});
        th.classList.add(asc?'asc':'desc');
        var rows=Array.prototype.slice.call(tbody.rows);
        rows.sort(function(a,b){
          var x=a.cells[col].dataset.v||a.cells[col].textContent, y=b.cells[col].dataset.v||b.cells[col].textContent;
          if(num){ x=parseFloat(x); y=parseFloat(y); return asc?x-y:y-x; }
          return asc?x.localeCompare(y):y.localeCompare(x);
        });
        rows.forEach(function(r){tbody.appendChild(r);});
      });
    });
  });
  document.querySelectorAll('input.search').forEach(function(inp){
    var tbl=document.getElementById(inp.dataset.table);
    inp.addEventListener('input',function(){
      var q=inp.value.trim().toLowerCase(), shown=0;
      Array.prototype.forEach.call(tbl.tBodies[0].rows,function(r){
        var ok=!q||r.cells[0].textContent.toLowerCase().indexOf(q)>=0; r.hidden=!ok; if(ok) shown++;
      });
      var cnt=document.getElementById(inp.dataset.table+'-count'); if(cnt) cnt.textContent=shown;
    });
  });
})();
"""


def _num(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def _table(table_id: str, title: str, rows: Iterable[tuple[str, int]], total: int,
           key_title: str, extra: dict | None = None) -> str:
    rows = list(rows)
    if not rows:
        return ""
    maximum = max(c for _, c in rows) or 1
    extra = extra or {}
    extra_head = "".join(f'<th class="num" data-sort="num">{escape(h)}</th>' for h in extra)
    body = []
    for key, count in rows:
        extra_cells = "".join(
            f'<td class="num" data-v="{fn(key)[0]}">{escape(fn(key)[1])}</td>' for fn in extra.values()
        )
        body.append(
            f'<tr><td class="key">{escape(str(key))}</td>'
            f'<td class="num" data-v="{count}">{_num(count)}</td>'
            f'<td class="num" data-v="{count}">{count / total * 100 if total else 0:.1f}%</td>'
            f'{extra_cells}'
            f'<td style="width:22%"><div class="meter"><span style="width:{count / maximum * 100:.1f}%"></span></div></td></tr>'
        )
    return f"""
<section class="card">
  <div class="tbl-tools"><h2>{escape(title)} <span class="muted small">(<span id="{table_id}-count">{len(rows)}</span>)</span></h2>
  <input class="search" type="search" placeholder="Фильтр…" data-table="{table_id}" aria-label="Фильтр таблицы"></div>
  <div class="tbl-wrap"><table class="sortable" id="{table_id}">
  <thead><tr><th data-sort="str">{escape(key_title)}</th><th class="num" data-sort="num">Запросов</th>
  <th class="num" data-sort="num">Доля</th>{extra_head}<th></th></tr></thead>
  <tbody>{''.join(body)}</tbody></table></div>
</section>"""


def _findings(report: Report) -> str:
    if not report.findings:
        return '<section class="card"><h2>Подозрительная активность</h2><p class="ok-box">Ничего подозрительного не найдено.</p></section>'
    items = []
    for f in report.findings:
        samples = "".join(f"<code>{escape(x)}</code> " for x in f.samples[:5])
        who = f"<code>{escape(f.ip)}</code>" if f.ip else "все IP"
        items.append(
            f'<div class="finding {f.severity}"><span class="badge {f.severity}">{SEVERITY_LABEL[f.severity]}</span>'
            f'<b>{escape(KIND_LABEL.get(f.kind, f.kind))}</b> · {who} · '
            f'<span class="muted small">{f.first:%Y-%m-%d %H:%M} – {f.last:%Y-%m-%d %H:%M}</span>'
            f'<div>{escape(f.title)}</div>'
            + (f'<div class="small muted">Примеры: {samples}</div>' if samples else "")
            + "</div>"
        )
    return (f'<section class="card"><h2>Подозрительная активность '
            f'<span class="muted small">({len(report.findings)})</span></h2>{"".join(items)}</section>')


def to_html(report: Report, title: str = "Отчёт log-lens") -> str:
    s, n = report.stats, report.top
    head = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>{CSS}</style></head><body><main>"""
    files = "".join(f'<span class="chip">{escape(f)}</span>' for f in report.files)
    filters = "".join(f'<span class="chip">{escape(f)}</span>' for f in report.filters)
    header = f"""
<header><div><h1>{escape(title)}</h1>
<div class="muted small">Создан {report.generated_at:%Y-%m-%d %H:%M} · log-lens {__version__}</div>
<div class="chips">{files}{filters}</div></div>
<button class="theme" id="theme" type="button">Тема: авто</button></header>"""

    if s.total == 0:
        msg = "Нет записей, подходящих под условия."
        if report.malformed:
            msg += f" Не разобрано строк: {report.malformed} — проверьте параметр --format."
        return head + header + f'<section class="card"><p>{escape(msg)}</p></section></main><script>{JS}</script></body></html>'

    err = s.error_rate * 100
    err_cls = "bad" if err >= 10 else "warn" if err >= 3 else "good"
    dur = s.duration.total_seconds() if s.duration else 0
    rt = s.response_time_summary()
    kpis = [
        ("", _num(s.total), "запросов"),
        ("", _num(s.unique_ips), "уникальных IP"),
        ("", human_bytes(s.bytes_total), "передано"),
        (err_cls, f"{err:.1f}%", "доля ошибок 4xx/5xx"),
        ("", f"{s.bot_share * 100:.1f}%", "запросов от ботов"),
        ("bad" if report.findings else "good", str(len(report.findings)), "подозрительных событий"),
    ]
    if rt:
        kpis.append(("", fmt_ms(rt["p95"]), "время ответа p95"))
    kpi_html = '<section class="kpis">' + "".join(
        f'<div class="kpi {c}"><div class="v">{escape(v)}</div><div class="l">{escape(lab)}</div></div>' for c, v, lab in kpis
    ) + "</section>"
    period = (f'<p class="muted small">Период: {s.first:%Y-%m-%d %H:%M} — {s.last:%Y-%m-%d %H:%M} '
              f'({human_duration(dur)})'
              + (f' · не разобрано строк: {report.malformed} из {report.lines_total}' if report.malformed else "")
              + "</p>")

    step_min = int(s.timeline_step.total_seconds() // 60)
    step_txt = f"{step_min} мин" if step_min < 60 else f"{step_min // 60} ч" if step_min < 1440 else f"{step_min // 1440} д"
    timeline = f"""
<section class="card"><h2>Запросы во времени <span class="muted small">(шаг {step_txt})</span></h2>
{timeline_chart(s.timeline_series(), s.timeline_step, title="Запросы во времени")}
<div class="legend"><span><i style="background:var(--accent)"></i>все запросы</span><span><i style="background:var(--err)"></i>ошибки 4xx/5xx</span></div>
</section>"""

    classes = sorted(s.status_classes.items())
    status_items = "".join(
        f'<li><i class="legend-dot bg-{k}" style="display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px"></i>'
        f'<b>{k}</b> — {_num(v)} ({v / s.total * 100:.1f}%)</li>' for k, v in classes)
    top_codes = ", ".join(f"<code>{code}</code>&nbsp;{_num(c)}" for code, c in s.statuses.most_common(8))
    status_card = f"""
<section class="card"><h2>Коды ответа</h2><div class="donut-wrap">{donut_chart(classes, title="Коды ответа")}
<div><ul class="status-list">{status_items}</ul><p class="small muted">Частые коды: {top_codes}</p>
<p class="small muted">Методы: {", ".join(f"{escape(m)}&nbsp;{_num(c)}" for m, c in s.methods.most_common(6))}</p></div></div></section>"""

    hours = column_chart([f"{h:02d}" for h in range(24)], [s.hours.get(h, 0) for h in range(24)],
                         title="Нагрузка по часам", width=960, height=220)
    days = column_chart(WEEKDAYS, [s.weekdays.get(d, 0) for d in range(7)], title="Нагрузка по дням недели",
                        width=420)
    load = f"""
<div class="grid2 row">{status_card}<section class="card"><h2>По дням недели</h2>{days}</section></div>
<section class="card"><h2>Нагрузка по часам суток</h2>{hours}</section>"""

    bytes_col = {"Трафик": lambda p: (s.bytes_by_path.get(p, 0), human_bytes(s.bytes_by_path.get(p, 0)))}
    tables = [
        _table("t-paths", f"Топ-{n} путей", s.paths.most_common(n), s.total, "Путь", bytes_col),
        _table("t-ips", f"Топ-{n} IP", s.ips.most_common(n), s.total, "IP"),
        _table("t-4xx", f"Топ-{n} путей с 4xx", s.error_paths.most_common(n), s.total, "Путь"),
        _table("t-5xx", f"Топ-{n} путей с 5xx", s.server_error_paths.most_common(n), s.total, "Путь"),
        _table("t-ua", f"Топ-{n} User-Agent", s.user_agents.most_common(n), s.total, "User-Agent"),
        _table("t-ref", f"Топ-{n} рефереров", s.referers.most_common(n), s.total, "Реферер"),
    ]
    slow = ""
    if rt:
        rows = "".join(
            f'<tr><td class="key">{escape(p)}</td><td class="num" data-v="{a}">{fmt_ms(a)}</td>'
            f'<td class="num" data-v="{c}">{_num(c)}</td></tr>' for p, a, c in s.slowest_paths(n))
        slow = f"""
<section class="card"><h2>Время ответа</h2>
<p class="small muted">Среднее {fmt_ms(rt['avg'])} · медиана {fmt_ms(rt['p50'])} · p95 {fmt_ms(rt['p95'])} · p99 {fmt_ms(rt['p99'])} · максимум {fmt_ms(rt['max'])}</p>
<div class="tbl-wrap"><table class="sortable"><thead><tr><th data-sort="str">Самые медленные пути</th>
<th class="num" data-sort="num">Среднее</th><th class="num" data-sort="num">Запросов</th></tr></thead><tbody>{rows}</tbody></table></div></section>"""

    tables_html = '<div class="grid2 row">' + "".join(t for t in tables if t) + "</div>"
    body = (header + kpi_html + period + _findings(report) + timeline
            + load + tables_html + slow
            + '<footer>Сгенерировано log-lens · все данные внутри этого файла, внешние запросы не выполняются</footer>')
    return head + body + f"</main><script>{JS}</script></body></html>"
