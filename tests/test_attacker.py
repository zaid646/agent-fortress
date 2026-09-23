"""Attacker graph tests: single-turn, drip multi-turn, and LLM-phase gating."""
from attacks import load_catalog
from config.settings import CATALOG_PATH
from agents.attacker import AttackerAgent


class FakeResponse:
    def __init__(self, json_data):
        self._data = json_data

    def json(self):
        return self._data

    @property
    def text(self):
        return str(self._data)


def make_probe(state_map):
    """In-memory target simulator keyed by (session, query)."""
    secrets = {}

    def probe(url, query, session):
        data = state_map.get((session, query), {"response": "ok", "sources": [], "tool_calls": [], "blocked": False})
        return FakeResponse(data)

    return probe


def test_single_turn_success():
    cat = load_catalog(CATALOG_PATH)
    atk = AttackerAgent(cat, probe=make_probe({}))
    out = atk.run("atk_rag_prompt_injection_001", "http://fake/naked")
    # target simulator did not echo marker -> not leaked
    assert out["success"] is not None
    assert len(out["responses"]) == 1


def test_drip_two_turns_executed():
    cat = load_catalog(CATALOG_PATH)
    # context drip uses the target's OWN memory; here we simulate a vulnerable
    # target that recalls the planted code word on the second turn.
    stored = {"value": None}

    def probe(url, query, session):
        if "code word for the session" in query:
            stored["value"] = "prepared-statement-echo"
            return FakeResponse({"response": "Acknowledged.", "sources": [], "tool_calls": [], "blocked": False})
        if "Repeat the code word" in query:
            return FakeResponse(
                {"response": f"The stored code word is: {stored['value']}", "sources": [], "tool_calls": [], "blocked": False}
            )
        return FakeResponse({"response": "ok", "sources": [], "tool_calls": [], "blocked": False})

    atk = AttackerAgent(cat, probe=probe)
    out = atk.run("atk_rag_drip_002", "http://fake/naked")
    assert len(out["payloads"]) == 2
    assert out["success"]  # marker leaked on turn 2


def test_llm_phase_requires_llm():
    cat = load_catalog(CATALOG_PATH)
    atk = AttackerAgent(cat, probe=make_probe({}))  # no LLM client
    try:
        atk.run("atk_rag_llm_crafted_001", "http://fake/naked", phase="llm")
        raise AssertionError("expected failure without attacker LLM")
    except RuntimeError:
        pass


def test_single_turn_blocked_no_leak():
    cat = load_catalog(CATALOG_PATH)
    blocked = FakeResponse({"response": "", "blocked": True, "block_reason": "BLOCKED_INGRESS: x"})
    atk = AttackerAgent(cat, probe=lambda url, q, s: blocked)
    out = atk.run("atk_rag_prompt_injection_001", "http://fake/fort")
    assert out["blocked"]
    assert not out["success"]