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
from typing import Any, List, Sequence
from urllib.parse import quote, urlsplit, urlunsplit

API_URL = "https://challenge.devseccon.com/api/challenge"
TIMEOUT_SECONDS = 2.5

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


def open_with_timeout(
    request: urllib.request.Request,
    opener: urllib.request.OpenerDirector,
) -> Any:
    """Open *request* with the configured opener using the global timeout."""

    return opener.open(request, timeout=TIMEOUT_SECONDS)


def fetch_challenge(
    url: str, opener: urllib.request.OpenerDirector
) -> tuple[List[str], str]:
    """Fetch the shuffled items and fast-expiring token."""

    request = urllib.request.Request(url, method="GET")
    with open_with_timeout(request, opener) as response:
        payload = json.load(response)
    return list(payload["items"]), str(payload["token"])


def submit_solution(
    url: str,
    ordered_list: Sequence[int],
    token: str,
    opener: urllib.request.OpenerDirector,
) -> dict:
    """POST the ordered indices back to the challenge endpoint."""

    body = json.dumps({"orderedList": ordered_list, "token": token}).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    with open_with_timeout(request, opener) as response:
        return json.load(response)


def redact_proxy(proxy_url: str) -> str:
    """Return a version of *proxy_url* with credentials stripped."""

    parts = urlsplit(proxy_url)
    if not (parts.username or parts.password):
        return proxy_url

    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def prepare_proxy_url(
    proxy_url: str, username: str | None, password: str | None
) -> str:
    """Inject optional credentials into *proxy_url* if provided."""

    parts = urlsplit(proxy_url)
    if parts.scheme not in {"http", "https"}:
        raise ValueError("Proxy URL must start with http:// or https://")
    if parts.username or parts.password:
        if username or password:
            raise ValueError(
                "Proxy URL already contains credentials; do not combine with"
                " --proxy-user/--proxy-password."
            )
        return proxy_url

    if not (username or password):
        return proxy_url

    user = quote(username or "", safe="")
    if password is None:
        credentials = user
    else:
        credentials = f"{user}:{quote(password, safe='')}"

    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"

    netloc = f"{credentials}@{host}" if credentials else host
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def create_http_opener(
    proxy_url: str | None,
    *,
    disable_proxy: bool = False,
) -> urllib.request.OpenerDirector:
    """Return an opener that honours proxy CLI settings."""

    handlers: list[urllib.request.BaseHandler] = []
    if disable_proxy:
        handlers.append(urllib.request.ProxyHandler({}))
    elif proxy_url:
        handlers.append(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )

    return urllib.request.build_opener(*handlers)


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
        "--token",
        help=(
            "Token to use alongside --items when the GET request cannot be performed."
        ),
    )
    proxy_group = parser.add_argument_group("Proxy control")
    proxy_group.add_argument(
        "--proxy",
        help="Override the proxy URL (e.g., http://user:pass@proxy:8080).",
    )
    proxy_group.add_argument(
        "--proxy-user",
        help="Username for the proxy supplied with --proxy.",
    )
    proxy_group.add_argument(
        "--proxy-password",
        help="Password for the proxy supplied with --proxy.",
    )
    proxy_group.add_argument(
        "--no-proxy",
        action="store_true",
        help="Disable environment proxy variables for the HTTP requests.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print additional diagnostic information to stderr.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_cli(sys.argv[1:] if argv is None else argv)

    if args.proxy and args.no_proxy:
        print("Cannot combine --proxy with --no-proxy", file=sys.stderr)
        return 64
    if (args.proxy_user or args.proxy_password) and not args.proxy:
        print(
            "Proxy credentials require --proxy to be set.",
            file=sys.stderr,
        )
        return 64

    proxy_url = args.proxy
    if proxy_url and (args.proxy_user or args.proxy_password):
        try:
            proxy_url = prepare_proxy_url(proxy_url, args.proxy_user, args.proxy_password)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 64

    try:
        opener = create_http_opener(proxy_url, disable_proxy=args.no_proxy)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 64

    if args.verbose:
        if args.no_proxy:
            print("Proxy usage disabled via --no-proxy", file=sys.stderr)
        elif proxy_url:
            print(f"Using proxy {redact_proxy(proxy_url)}", file=sys.stderr)

    if args.items:
        items = json.loads(args.items)
        token = args.token or ""
    else:
        try:
            fetch_started = time.monotonic()
            items, token = fetch_challenge(args.base_url, opener)
        except urllib.error.HTTPError as exc:
            message = (
                "Failed to fetch challenge data: HTTP "
                f"{exc.code} {exc.reason}. "
                "If outbound HTTPS is blocked, run the manual curl workflow and "
                "relaunch this script with --items and --token."
            )
            print(message, file=sys.stderr)
            return 1
        except (urllib.error.URLError, TimeoutError) as exc:
            print(
                "Failed to fetch challenge data: "
                f"{exc}. If outbound HTTPS is blocked, run the manual curl "
                "workflow and relaunch this script with --items and --token.",
                file=sys.stderr,
            )
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
        response = submit_solution(args.base_url, ordered_list, token, opener)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"Failed to submit solution: {exc}", file=sys.stderr)
        return 3

    print(json.dumps(response, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
