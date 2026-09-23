from attacks import InvalidCatalogError, load_catalog
from config.settings import CATALOG_PATH


def test_catalog_loads():
    cat = load_catalog(CATALOG_PATH)
    assert cat.version == 1.0
    assert len(cat.tests) >= 10
    assert "prompt_injection" in cat.attack_types
    assert cat.targets["rag"] and cat.targets["agentic"]


def test_catalog_schema():
    cat = load_catalog(CATALOG_PATH)
    for t in cat.tests:
        assert t.test_id.startswith("atk_")
        assert t.target in ("rag", "agentic")
        assert t.severity in ("low", "medium", "high", "critical")
        assert t.expected_outcome == "blocked"
        # every test must carry a success marker so outcomes are judgeable
        assert t.success_marker


def test_catalog_by_target_covers_both():
    cat = load_catalog(CATALOG_PATH)
    assert len(cat.by_target("rag")) >= 5
    assert len(cat.by_target("agentic")) >= 4


def test_invalid_catalog_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: [")
    try:
        load_catalog(bad)
        raise AssertionError("expected InvalidCatalogError")
    except InvalidCatalogError:
        pass