#!/usr/bin/env python3
"""Run bounded Keycloak/OIDC surface checks with sanitized JSON output."""

import argparse
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

import requests

SENSITIVE = {
    "code", "state", "nonce", "token", "access_token", "refresh_token",
    "id_token", "client_secret", "password", "session", "sessionid", "session_id",
}


def clean_url(url):
    parts = urlsplit(url)
    query = urlencode([
        (key, "[REDACTED]" if key.lower() in SENSITIVE else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ])
    return parts._replace(query=query).geturl()


def clean(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SENSITIVE else clean(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [clean(item) for item in value]
    return value


def clean_text(text):
    text = re.sub(r"(?i)(token|code|state|nonce|password|secret)=([^&\s]+)", r"\1=[REDACTED]", text)
    return re.sub(r"(?i)Bearer\s+\S+", "Bearer [REDACTED]", text)


def validate_base_url(url):
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("The base URL must be an absolute HTTPS URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Credentials, query strings, and fragments are not allowed in the base URL")
    return url.rstrip("/")


def auth_params(client_id, redirect_uri, response_type="code"):
    return {
        "response_type": response_type,
        "client_id": client_id,
        "scope": "openid",
        "state": "surface-check",
        "nonce": "surface-check",
        "redirect_uri": redirect_uri,
    }


def build_checks(base_url, realm, client_id, redirect_uri, origin, include_registration=False):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", realm):
        raise ValueError("Invalid realm name")
    auth_url = f"{base_url}/realms/{realm}/protocol/openid-connect/auth"
    token_url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"
    params = lambda response_type="code", target=None: auth_params(
        client_id, target or redirect_uri, response_type
    )
    checks = [
        ("authorization-code", "GET", auth_url, params()),
        ("saml-descriptor", "GET", f"{base_url}/realms/{realm}/protocol/saml/descriptor", None),
        ("external-redirect", "GET", auth_url, params(target="https://untrusted.invalid/callback")),
        ("wildcard-path", "GET", auth_url, params(target=redirect_uri + "/../")),
        ("matrix-parameters", "GET", auth_url + ";matrix=1", params()),
        ("implicit-token", "GET", auth_url, params(response_type="token")),
        ("implicit-id-token-token", "GET", auth_url, params(response_type="id_token token")),
        ("bearer-scheme", "POST", token_url, {"grant_type": "client_credentials"}),
        ("cors", "POST", token_url, {"grant_type": "client_credentials"}),
    ]
    if include_registration:
        checks.append((
            "dynamic-client-registration", "POST",
            f"{base_url}/realms/{realm}/clients-registrations/openid-connect", {},
        ))
    return checks


def record(response, check):
    title = re.search(r"<title[^>]*>(.*?)</title>", response.text, re.I | re.S)
    result = {
        "check": check,
        "status": response.status_code,
        "server": response.headers.get("Server"),
        "content_type": response.headers.get("Content-Type"),
        "location": clean_url(response.headers["Location"]) if "Location" in response.headers else None,
        "title": title.group(1).strip() if title else None,
    }
    for header in (
        "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Methods", "Access-Control-Allow-Headers",
    ):
        if header in response.headers:
            result[header.lower().replace("-", "_")] = response.headers[header]
    if response.headers.get("Content-Type", "").startswith("application/json") or response.text.lstrip().startswith("{"):
        try:
            result["body"] = clean(response.json())
        except ValueError:
            result["body"] = clean_text(response.text[:300])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Keycloak base URL, for example https://identity.example.test")
    parser.add_argument("--realm", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--redirect-uri", required=True, help="Existing test-client callback URL")
    parser.add_argument("--origin", default="https://untrusted.invalid", help="Untrusted origin used for the CORS check")
    parser.add_argument("--ca-bundle", required=True, help="CA bundle used for TLS verification")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--output", default="keycloak-surface-results.json")
    parser.add_argument(
        "--include-registration-check",
        action="store_true",
        help="Send an empty dynamic-registration request; use only with explicit authorization",
    )
    args = parser.parse_args()
    if not Path(args.ca_bundle).is_file():
        parser.error("CA bundle not found; TLS verification is required")
    try:
        base_url = validate_base_url(args.base_url)
        checks = build_checks(
            base_url, args.realm, args.client_id, args.redirect_uri,
            args.origin, args.include_registration_check,
        )
    except ValueError as exc:
        parser.error(str(exc))

    session = requests.Session()
    session.trust_env = False
    session.verify = args.ca_bundle
    session.headers["User-Agent"] = "Keycloak-Surface-Checks/1.0"
    results = []
    for check, method, url, data in checks:
        headers = {}
        if check == "bearer-scheme":
            headers["Authorization"] = "bearer invalid"
        elif check == "cors":
            headers["Authorization"] = "Bearer invalid"
            headers["Origin"] = args.origin
        try:
            if method == "GET":
                response = session.get(url, params=data, headers=headers, timeout=args.timeout, allow_redirects=False)
            elif check == "dynamic-client-registration":
                response = session.post(url, json=data, headers=headers, timeout=args.timeout, allow_redirects=False)
            else:
                response = session.post(url, data=data, headers=headers, timeout=args.timeout, allow_redirects=False)
            results.append(record(response, check))
        except requests.RequestException as exc:
            results.append({"check": check, "error": type(exc).__name__, "detail": clean_text(str(exc))[:250]})
    rendered = json.dumps(results, indent=2) + "\n"
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
