import json
from pathlib import Path
import sys

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

    def fake_submit(url, ordered_list, token):
        captured["args"] = (url, list(ordered_list), token)
        return {"success": True, "echo": ordered_list}

    monkeypatch.setattr(solver, "submit_solution", fake_submit)

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
    assert captured["args"] == ("https://example.test/api", expected_order, sample_token)
    printed = capsys.readouterr().out
    assert '"success": true' in printed.lower()
