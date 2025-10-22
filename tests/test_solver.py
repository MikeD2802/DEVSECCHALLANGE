import json
from pathlib import Path
import sys
import urllib.request

import pytest

# Ensure the repository root is on sys.path when tests are run via pytest.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import solve_challenge as solver


def test_normalise_removes_non_alnum_and_casefolds():
    assert solver.normalise("Prompt Injection!") == "PROMPTINJECTION"


def test_determine_order_matches_sample_payload():
    items = [
        "LLM06 Excessive Agency",
        "LLM01 Prompt Injection",
        "LLM08 Vector and Embedding Weaknesses",
        "LLM04 Data Model Poisoning",
        "LLM03 Supply Chain",
        "LLM05 Improper Output Handling",
        "LLM02 Sensitive Information Disclosure",
        "LLM09 Misinformation",
        "LLM07 System Prompt Leakage",
        "LLM10 Unbounded Consumption",
    ]
    expected = [1, 6, 4, 3, 5, 0, 8, 2, 7, 9]
    assert solver.determine_order(items) == expected


def test_determine_order_raises_for_unknown_entry():
    items = ["Unknown"] + [synonyms[0] for synonyms in solver.CANONICAL_SYNONYMS[:-1]]
    items.append("Extra")
    with pytest.raises(ValueError):
        solver.determine_order(items)


def test_main_submits_with_manual_items(monkeypatch, capsys):
    sample_items = [
        "LLM06 Excessive Agency",
        "LLM01 Prompt Injection",
        "LLM08 Vector and Embedding Weaknesses",
        "LLM04 Data Model Poisoning",
        "LLM03 Supply Chain",
        "LLM05 Improper Output Handling",
        "LLM02 Sensitive Information Disclosure",
        "LLM09 Misinformation",
        "LLM07 System Prompt Leakage",
        "LLM10 Unbounded Consumption",
    ]
    sample_token = "abc123"
    expected_order = solver.determine_order(sample_items)

    captured = {}

    def fake_submit(url, ordered_list, token, opener):
        captured["args"] = (url, list(ordered_list), token, opener)
        return {"success": True, "echo": ordered_list}

    monkeypatch.setattr(solver, "submit_solution", fake_submit)
    dummy_opener = object()
    monkeypatch.setattr(solver, "create_http_opener", lambda *a, **k: dummy_opener)

    exit_code = solver.main(
        [
            "--items",
            json.dumps(sample_items),
            "--token",
            sample_token,
            "--base-url",
            "https://example.test/api",
        ]
    )

    assert exit_code == 0
    assert captured["args"] == (
        "https://example.test/api",
        expected_order,
        sample_token,
        dummy_opener,
    )
    printed = capsys.readouterr().out
    assert '"success": true' in printed.lower()


def test_prepare_proxy_url_injects_credentials():
    proxy = solver.prepare_proxy_url("http://proxy.example:9000", "user", "pass word")
    assert proxy == "http://user:pass%20word@proxy.example:9000"


def test_prepare_proxy_url_rejects_duplicates():
    with pytest.raises(ValueError):
        solver.prepare_proxy_url("http://user:pw@proxy.example", "another", "creds")


def test_create_http_opener_custom_proxy(monkeypatch):
    recorded = {}

    def fake_build_opener(*handlers):
        recorded["handlers"] = handlers

        class DummyOpener:
            def open(self, request, timeout=0):  # pragma: no cover - network avoided
                raise AssertionError("Network access not expected in test")

        return DummyOpener()

    monkeypatch.setattr(solver.urllib.request, "build_opener", fake_build_opener)

    opener = solver.create_http_opener("http://proxy.example:8080")
    assert opener  # opener is returned
    assert len(recorded["handlers"]) == 1
    handler = recorded["handlers"][0]
    assert isinstance(handler, urllib.request.ProxyHandler)
    assert handler.proxies == {
        "http": "http://proxy.example:8080",
        "https": "http://proxy.example:8080",
    }


def test_create_http_opener_disable_proxy(monkeypatch):
    recorded = {}

    def fake_build_opener(*handlers):
        recorded["handlers"] = handlers

        class DummyOpener:
            def open(self, request, timeout=0):  # pragma: no cover - network avoided
                raise AssertionError("Network access not expected in test")

        return DummyOpener()

    monkeypatch.setattr(solver.urllib.request, "build_opener", fake_build_opener)

    solver.create_http_opener(None, disable_proxy=True)
    assert len(recorded["handlers"]) == 1
    handler = recorded["handlers"][0]
    assert isinstance(handler, urllib.request.ProxyHandler)
    assert handler.proxies == {}


def test_main_rejects_proxy_credentials_without_proxy(monkeypatch, capsys):
    monkeypatch.setattr(
        solver,
        "determine_order",
        lambda items: (_ for _ in ()).throw(AssertionError("should not be called")),
    )
    exit_code = solver.main(
        [
            "--items",
            json.dumps([synonyms[0] for synonyms in solver.CANONICAL_SYNONYMS]),
            "--token",
            "tok",
            "--proxy-user",
            "user",
        ]
    )
    assert exit_code == 64
    captured = capsys.readouterr()
    assert "Proxy credentials require --proxy" in captured.err
