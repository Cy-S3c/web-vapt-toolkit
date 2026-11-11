# Web VAPT Toolkit

General-purpose Python utilities for authorized web application security testing. The repository contains tools only: no target data, assessment reports, evidence, credentials, or environment-specific configuration.

## Tools

### `jsp_js_miner.py`

Offline-first JSP and JavaScript source miner with an optional guarded crawler.

- Recursively scans `.jsp`, `.jspx`, `.js`, `.map`, `.html`, `.htm`, `.json`, and `.txt` files.
- Extracts endpoints, URL and form parameters, JSP request parameters, JavaScript object keys, comments, and source-map references.
- Identifies review candidates such as DOM sinks, dynamic code execution, SQL operations, file access, redirects, session operations, and possible secrets.
- Redacts detected secret values in saved sources and findings.
- Produces JSONL inventories, endpoint and parameter lists, a JSON summary, and a Markdown report.
- Crawls only supplied seed origins, honors robots.txt by default, uses sequential rate-limited requests, and caps pages, assets, and depth.

### `keycloak_surface_checks.py`

Bounded Keycloak/OIDC configuration checks with sanitized JSON output.

- Reviews authorization response types, redirect behavior, matrix parameters, SAML descriptor exposure, bearer handling, and CORS behavior.
- Uses intentionally invalid credentials; it does not attempt to obtain valid tokens.
- Does not follow redirects.
- Requires explicit target, realm, client, callback, and CA-bundle arguments.
- Skips dynamic client registration unless `--include-registration-check` is explicitly selected with separate authorization.

Observed behavior is evidence for review, not proof of a vulnerability. In particular, CORS headers alone do not demonstrate sensitive cross-origin data access.

## Requirements

- Python 3.9+
- `requests`

Install the dependency in a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Offline source mining

```bash
python3 jsp_js_miner.py scan \
  --input-dir /path/to/exported-sources \
  --output output/miner
```

The offline scan makes no network requests.

## Guarded crawling

Use only systems you are authorized to test. Supply an in-scope seed and a CA bundle appropriate for the target:

```bash
python3 jsp_js_miner.py crawl \
  --seed https://target.example.test/ \
  --ca-bundle /path/to/ca.pem \
  --output output/miner \
  --rate 1 \
  --max-pages 50 \
  --max-assets 100 \
  --max-depth 2
```

The crawler does not submit forms or execute JavaScript. It blocks `logout` by default and limits retries for temporary failures. Do not use `--allow-actions` or `--ignore-robots` without explicit approval.

### Miner outputs

- `files.jsonl`: source and response metadata
- `findings.jsonl`: static security observations
- `secrets.jsonl`: redacted secret candidates and short match hashes
- `errors.jsonl`: processing and request errors
- `endpoints.txt` and `parameters.txt`: sorted inventories
- `summary.json`: result counts and generation timestamp
- `REPORT.md`: readable summary
- `sources/`: crawled sources with detected secret values redacted

## Keycloak surface checks

Use an existing disposable test client and callback. Do not supply production secrets or real user credentials:

```bash
python3 keycloak_surface_checks.py \
  --base-url https://identity.example.test \
  --realm example-realm \
  --client-id example-client \
  --redirect-uri https://app.example.test/callback \
  --origin https://untrusted.invalid \
  --ca-bundle /path/to/ca.pem \
  --output output/keycloak-surface-results.json
```

The registration check is excluded by default because it may change server state. Enable it only when that exact test is authorized.

## Safety and responsible use

- Use these tools only with explicit authorization and within the agreed testing boundaries.
- Keep TLS verification enabled; the scripts do not offer an insecure bypass.
- Do not use them for denial of service, credential brute force, bulk extraction, destructive actions, or unauthorized account creation.
- Review generated output before sharing it. Runtime output can contain target-specific URLs, page titles, parameters, or other sensitive context.
- Static matches and protocol responses require manual validation before they can be called vulnerabilities.

## Offline verification

```bash
python3 -m py_compile jsp_js_miner.py keycloak_surface_checks.py
python3 jsp_js_miner.py --help
python3 keycloak_surface_checks.py --help
```

No live target is needed for these checks.
