# DEVSECCHALLANGE

This repository contains a helper script for the DevSecCon "2025 OWASP Top 10 for LLMs" challenge. The script fetches the shuffled challenge data, derives the correct order of the OWASP Top 10 items, and submits the solution within the required three-second window.

## Usage

```bash
python solve_challenge.py
```

### Helpful flags

- `--no-submit` – compute the ordered list without performing the POST request. Useful when testing locally with sample data.
- `--items` – provide a JSON array of items to order instead of fetching from the live API. Prefix with `@` to load from a file or use `-` to read the JSON from stdin.
- `--challenge` – supply the full challenge response (`{"items": [...], "token": "..."}`) via string, file (`@path`), or stdin (`-`).
- `--base-url` – override the challenge endpoint (e.g., when running against a mock server).
- `--proxy` – override the proxy used for the HTTP requests (defaults to environment variables).
- `--proxy-user` / `--proxy-password` – provide credentials for the proxy supplied to `--proxy`.
- `--no-proxy` – ignore environment proxy settings and connect directly.
- `--verbose` – print timing information for the network requests.
- `--token` – submit data supplied via `--items` without performing the GET request.

Example dry run:

```bash
python solve_challenge.py --no-submit --items '["LLM02 Sensitive Information Disclosure", "LLM01 Prompt Injection"]'
```

### Manual fallback when outbound HTTPS is blocked

Some environments block the direct GET request. You can still automate the
solution submission by following these steps:

1. Fetch the raw payload manually:

   ```bash
   curl -s https://challenge.devseccon.com/api/challenge
   ```

2. Copy the returned `items` array and `token`.

3. Run the solver with the captured data so it can compute the ordered list and
   submit it on your behalf:

   ```bash
   python solve_challenge.py --items '[copied array here]' --token copied_token_here
   ```

   Use `--no-submit` if you only want to inspect the computed ordering.

   Alternatively, pipe the raw payload directly into the solver so it can
   extract both the `items` and `token` automatically:

   ```bash
   curl -s https://challenge.devseccon.com/api/challenge | python solve_challenge.py --challenge -
   ```
