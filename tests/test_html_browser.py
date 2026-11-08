"""Проверка HTML-отчёта в настоящем браузере (Playwright). Пропускается, если Playwright не установлен."""

import pytest

from log_lens.cli import main

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    d = tmp_path_factory.mktemp("html")
    log, out = d / "a.log", d / "r.html"
    main(["generate", "-n", "1500", "--days", "2", "-o", str(log)])
    main(["analyze", str(log), "-o", str(out), "--top", "15"])
    return out


@pytest.fixture(scope="module")
def browser():
    with playwright.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # браузер не установлен
            pytest.skip(f"Chromium недоступен: {exc}")
        yield b
        b.close()


def test_report_in_browser(browser, report):
    page = browser.new_page(viewport={"width": 1280, "height": 900})
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: m.type == "error" and errors.append(m.text))
    page.goto(report.as_uri())

    assert page.locator(".kpi").count() >= 6
    assert page.locator(".finding").count() >= 4

    # сортировка по числу запросов по возрастанию
    page.locator("#t-paths th", has_text="Запросов").click()
    nums = [int(v) for v in page.locator("#t-paths tbody td:nth-child(2)").evaluate_all(
        "els => els.map(e => e.dataset.v)")]
    assert nums == sorted(nums)

    # фильтр таблицы
    page.fill('input[data-table="t-paths"]', "static")
    visible = page.locator("#t-paths tbody tr:visible")
    assert visible.count() >= 1
    assert all("static" in t for t in visible.all_inner_texts())
    assert page.locator("#t-paths-count").inner_text() == str(visible.count())

    # переключение темы
    btn = page.locator("#theme")
    btn.click()
    assert page.evaluate("document.documentElement.dataset.theme") == "light"
    btn.click()
    assert page.evaluate("document.documentElement.dataset.theme") == "dark"
    assert errors == []


def test_report_mobile_no_horizontal_scroll(browser, report):
    page = browser.new_page(viewport={"width": 375, "height": 800})
    page.goto(report.as_uri())
    assert page.evaluate("document.documentElement.scrollWidth") <= 375
