from datetime import datetime, timedelta

from conftest import TZ

from log_lens.detectors import Detector, DetectorConfig, _max_window

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=TZ)


def kinds(findings):
    return sorted(f.kind for f in findings)


def test_max_window():
    times = [T0 + timedelta(seconds=s) for s in (0, 10, 20, 400, 410)]
    n, lo, hi = _max_window(times, timedelta(minutes=1))
    assert n == 3 and lo == T0 and hi == T0 + timedelta(seconds=20)


def test_clean_traffic_has_no_findings(entry):
    d = Detector()
    for i in range(300):
        d.feed(entry(ip=f"192.0.2.{i % 50}", t=T0 + timedelta(seconds=i * 30), path="/"))
    assert d.findings() == []


def test_scanner(entry):
    d = Detector()
    for i, p in enumerate(["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.sql", "/server-status"]):
        d.feed(entry(ip="198.51.100.66", t=T0 + timedelta(seconds=i), path=p, status=200 if p == "/server-status" else 404))
    f = d.findings()
    assert kinds(f) == ["scanner"]
    assert f[0].severity == "high"  # был успешный ответ
    assert "успешным" in f[0].title


def test_bruteforce_with_success(entry):
    d = Detector(DetectorConfig(brute_count=10))
    for i in range(12):
        d.feed(entry(ip="203.0.113.13", t=T0 + timedelta(seconds=i * 10), method="POST", path="/login", status=401))
    plain = d.findings()
    assert kinds(plain) == ["bruteforce"] and plain[0].severity == "low"
    d.feed(entry(ip="203.0.113.13", t=T0 + timedelta(seconds=200), method="POST", path="/login", status=302))
    f = d.findings()[0]
    assert f.severity == "high" and "подобран" in f.title


def test_bruteforce_slow_attempts_ignored(entry):
    d = Detector(DetectorConfig(brute_count=10))
    for i in range(15):  # раз в 5 минут — в окно 10 минут не больше 3
        d.feed(entry(ip="203.0.113.13", t=T0 + timedelta(minutes=5 * i), method="POST", path="/login", status=401))
    assert d.findings() == []


def test_404_burst_and_scanner_dedup(entry):
    d = Detector(DetectorConfig(burst_404_count=20))
    for i in range(25):
        d.feed(entry(ip="192.0.2.200", t=T0 + timedelta(seconds=i * 5), path=f"/f/{i}.zip", status=404))
    for i in range(25):
        d.feed(entry(ip="198.51.100.66", t=T0 + timedelta(seconds=i), path="/.env", status=404))
    f = d.findings()
    assert kinds(f) == ["404-burst", "scanner"]
    assert [x.ip for x in f if x.kind == "404-burst"] == ["192.0.2.200"]


def test_rate_and_spike(entry):
    d = Detector(DetectorConfig(rate_per_minute=100, spike_min_requests=50))
    # фон: 2 запроса в минуту в течение 2 часов
    for m in range(120):
        for k in range(2):
            d.feed(entry(ip=f"192.0.2.{k}", t=T0 + timedelta(minutes=m, seconds=k)))
    # флуд: 150 запросов в одну минуту
    for i in range(150):
        d.feed(entry(ip="203.0.113.250", t=T0 + timedelta(minutes=60, seconds=i * 0.3)))
    f = d.findings()
    assert kinds(f) == ["rate", "spike"]
    rate = next(x for x in f if x.kind == "rate")
    assert rate.ip == "203.0.113.250" and rate.count == 150
    spike = next(x for x in f if x.kind == "spike")
    assert spike.ip is None and spike.count == 152


def test_findings_sorted_by_severity(entry):
    d = Detector(DetectorConfig(burst_404_count=5))
    for i in range(6):
        d.feed(entry(ip="192.0.2.1", t=T0 + timedelta(seconds=i), path=f"/x{i}", status=404))
    for i in range(6):
        d.feed(entry(ip="198.51.100.1", t=T0 + timedelta(seconds=i), path="/.env", status=200))
    f = d.findings()
    assert f[0].severity == "high"
    assert f[0].to_dict()["first"].startswith("2026-11-01T12:00")
