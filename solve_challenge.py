#!/usr/bin/env python3
"""Solve the DevSecCon OWASP Top 10 for LLMs API challenge.

The challenge provides a shuffled list of the official OWASP Top 10 for LLMs
entries and requires responding with the indices that reorder them back to the
canonical sequence.  The POST request must be sent within three seconds of the
GET request, so this script keeps processing lightweight and avoids extra
network hops.

Usage examples::

    # Run against the live challenge endpoint
    python solve_challenge.py

    # Dry run with a custom item list (useful for tests)
    python solve_challenge.py --no-submit --items '["TWO", "ONE"]'
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import List, Sequence

API_URL = "https://challenge.devseccon.com/api/challenge"

# Synonyms for each canonical position.  We include both the official title and
# a few common aliases to increase our chances of matching the API's wording.
CANONICAL_SYNONYMS: Sequence[Sequence[str]] = (
    ("Prompt Injection", "LLM01"),
    (
        "Sensitive Information Disclosure",
        "Sensitive Info Disclosure",
        "LLM02",
    ),
    ("Supply Chain", "Supply Chain Vulnerabilities", "LLM03"),
    (
        "Data Model Poisoning",
        "Training Data Poisoning",
        "Model Data Poisoning",
        "LLM04",
    ),
    (
        "Improper Output Handling",
        "Insecure Output Handling",
        "LLM05",
    ),
    ("Excessive Agency", "LLM06"),
    ("System Prompt Leakage", "LLM07"),
    (
        "Vector and Embedding Weaknesses",
        "Vector & Embedding Weaknesses",
        "LLM08",
    ),
    ("Misinformation", "LLM09"),
    ("Unbounded Consumption", "LLM10"),
)


def normalise(text: str) -> str:
    """Return a case-insensitive, alphanumeric-only representation."""

    return "".join(ch for ch in text.upper() if ch.isalnum())


def determine_order(items: Sequence[str]) -> List[int]:
    """Return the indices that reorder *items* into the canonical sequence."""

    normalised_items = [normalise(item) for item in items]
    used_indices: set[int] = set()
    ordered_indices: List[int] = []

    for synonyms in CANONICAL_SYNONYMS:
        target_index: int | None = None
        for synonym in synonyms:
            target = normalise(synonym)
            for idx, candidate in enumerate(normalised_items):
                if idx in used_indices:
                    continue
                if target == candidate or target in candidate or candidate in target:
                    target_index = idx
                    break
            if target_index is not None:
                break
        if target_index is None:
            raise ValueError(
                f"Unable to match canonical entry '{synonyms[0]}' in {items!r}"
            )
        ordered_indices.append(target_index)
        used_indices.add(target_index)

    return ordered_indices


def fetch_challenge(url: str) -> tuple[List[str], str]:
    """Fetch the shuffled items and fast-expiring token."""

    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=2.5) as response:
        payload = json.load(response)
    return list(payload["items"]), str(payload["token"])


def submit_solution(url: str, ordered_list: Sequence[int], token: str) -> dict:
    """POST the ordered indices back to the challenge endpoint."""

    body = json.dumps({"orderedList": ordered_list, "token": token}).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=2.5) as response:
        return json.load(response)


def parse_cli(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=API_URL,
        help="Override the challenge endpoint (useful for local testing).",
    )
    parser.add_argument(
        "--items",
        help="JSON array of items to order instead of performing the GET request.",
    )
    parser.add_argument(
        "--no-submit",
        action="store_true",
        help="Skip the POST request and only print the ordered indices.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print additional diagnostic information to stderr.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_cli(sys.argv[1:] if argv is None else argv)

    if args.items:
        items = json.loads(args.items)
        token = ""
    else:
        try:
            fetch_started = time.monotonic()
            items, token = fetch_challenge(args.base_url)
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"Failed to fetch challenge data: {exc}", file=sys.stderr)
            return 1
        if args.verbose:
            elapsed_ms = (time.monotonic() - fetch_started) * 1000
            print(f"Fetched challenge in {elapsed_ms:.2f} ms", file=sys.stderr)

    try:
        ordered_list = determine_order(items)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.no_submit or not token:
        print(json.dumps({"orderedList": ordered_list, "items": items}, indent=2))
        if token:
            print(f"Token (not submitted): {token}")
        return 0

    try:
        response = submit_solution(args.base_url, ordered_list, token)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"Failed to submit solution: {exc}", file=sys.stderr)
        return 3

    print(json.dumps(response, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
