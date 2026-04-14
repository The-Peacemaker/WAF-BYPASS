from waf_eval.generator import SafePatternGenerator


def test_fuzz_generation_count() -> None:
    generator = SafePatternGenerator(seed=7)
    payloads = generator.generate_fuzzed(count=20)
    assert len(payloads) == 20
    assert all(item.encoded for item in payloads)


def test_exhaustive_cap() -> None:
    generator = SafePatternGenerator(seed=7)
    payloads = generator.generate_exhaustive(limit=10)
    assert len(payloads) == 10
