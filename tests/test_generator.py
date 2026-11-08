from log_lens.generator import GeneratorConfig, generate
from log_lens.parser import LogParser


def test_generator_is_deterministic_and_parsable():
    cfg = GeneratorConfig(lines=500, days=1, seed=1)
    a = [line for _, line in generate(cfg)]
    b = [line for _, line in generate(cfg)]
    assert a == b
    assert len(a) >= 500
    p = LogParser()
    entries = list(p.parse(a))
    assert p.malformed == 0 and len(entries) == len(a)
    assert all(e.request_time is not None for e in entries)
    times = [e.time for e in entries]
    assert times == sorted(times)


def test_generator_options():
    cfg = GeneratorConfig(lines=200, days=1, seed=3, with_time=False, attacks=False)
    lines = [line for _, line in generate(cfg)]
    p = LogParser("combined")
    entries = list(p.parse(lines))
    assert p.malformed == 0
    assert all(e.request_time is None for e in entries)
    assert not any(e.ip == "198.51.100.66" for e in entries)  # нет сканера
    # документационные диапазоны IP
    assert all(e.ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for e in entries)
