# DEVSECCHALLANGE

This repository contains a helper script for the DevSecCon "2025 OWASP Top 10 for LLMs" challenge. The script fetches the shuffled challenge data, derives the correct order of the OWASP Top 10 items, and submits the solution within the required three-second window.

## Usage

```bash
python solve_challenge.py
```

### Helpful flags

- `--no-submit` – compute the ordered list without performing the POST request. Useful when testing locally with sample data.
- `--items` – provide a JSON array of items to order instead of fetching from the live API.
- `--base-url` – override the challenge endpoint (e.g., when running against a mock server).
- `--verbose` – print timing information for the network requests.

Example dry run:

```bash
python solve_challenge.py --no-submit --items '["LLM02 Sensitive Information Disclosure", "LLM01 Prompt Injection"]'
```
