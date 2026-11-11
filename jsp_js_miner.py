#!/usr/bin/env python3
"""Offline-first JSP/JavaScript miner with optional guarded crawling."""

import argparse
import hashlib
import json
import re
import sys
import time
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests

BLOCKED_PATHS = {"logout"}
TEXT_TYPES = (".jsp", ".jspx", ".js", ".map", ".html", ".htm", ".json", ".txt")
SOURCE_MAP_RE = re.compile(r"sourceMappingURL\s*=\s*([^\s*]+)")
SECRET_RULES = [
    ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("stripe-key", r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    ("private-key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("basic-auth-url", r"https?://[^\s/:@]+:[^\s/@]+@[^\s]+"),
    ("connection-string", r"(?i)(?:jdbc|mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://[^\s\"'`]+"),
    ("named-secret", r"(?i)(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*[\"'][^\"']{4,}[\"']"),
]
STATIC_RULES = [
    ("dynamic-code-execution", r"\b(?:eval\s*\(|new\s+Function\s*\(|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\()", "high"),
    ("dom-html-sink", r"(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|v-html|ng-bind-html)", "medium"),
    ("dynamic-navigation", r"(?:location\.(?:href|assign|replace)|window\.open|parent\.document\.location)", "medium"),
    ("browser-storage", r"(?:localStorage|sessionStorage|document\.cookie|indexedDB)", "low"),
    ("cross-document-messaging", r"\bpostMessage\s*\(|addEventListener\s*\(\s*[\"']message[\"']", "medium"),
    ("dynamic-script-loading", r"(?:createElement\s*\(\s*[\"']script|\.src\s*=|importScripts\s*\(|require\s*\()", "low"),
    ("network-call", r"(?:fetch\s*\(|XMLHttpRequest|axios\.|\.ajax\s*\(|\.get\s*\(|\.post\s*\(|WebSocket\s*\(|EventSource\s*\()", "low"),
    ("jsp-parameter-source", r"(?:request\.getParameter|getParameterValues|getAttribute|getHeader|getCookies|getReader|getInputStream)", "medium"),
    ("jsp-sql-operation", r"(?:executeQuery|executeUpdate|prepareStatement|createStatement|DriverManager\.getConnection|sql:query|sql:update)", "high"),
    ("jsp-file-or-path", r"(?:getRealPath|getResourceAsStream|getResource\s*\(|FileInputStream|FileOutputStream|FileReader|FileWriter|Paths\.get|new\s+File\s*\()", "high"),
    ("jsp-redirect", r"(?:sendRedirect|RequestDispatcher|jsp:forward|response\.setHeader|response\.addHeader|response\.addCookie)", "medium"),
    ("jsp-session-operation", r"(?:session\.getAttribute|session\.setAttribute|session\.invalidate|request\.getSession|getUserPrincipal|getRemoteUser|isUserInRole)", "medium"),
    ("jsp-output", r"(?:out\.print|out\.println|response\.getWriter|<%=)", "medium"),
    ("jsp-include", r"(?:<%@\s*include|jsp:include|jsp:forward|c:url)", "low"),
    ("debug-or-obsolete", r"(?i)(?:TODO|FIXME|HACK|DEBUG|OBSOLETE|deprecated|temporary|test[_-]?only)", "low"),
]
ENDPOINT_RE = re.compile(r"(?:https?://[^\s\"'`<>]+|/[A-Za-z0-9_./-]+\.(?:jspx?|js|json|map|html?|css)|[A-Za-z0-9_./-]+\.(?:jspx?))")
QUOTED_PATH_RE = re.compile(r"[\"'`]((?:/|https?://)[^\"'`<>]+)[\"'`]")
REQUEST_PARAMETER_RE = re.compile(r"request\.getParameter\s*\(\s*[\"']([^\"']+)[\"']\s*\)")
QUERY_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.-]*)=")
FORM_FIELD_RE = re.compile(r"(?:name|id)\s*=\s*[\"']([A-Za-z_][\w:.-]*)[\"']", re.I)
JS_KEY_RE = re.compile(r"[{\"',]([A-Za-z_$][\w$]*)\s*:\s*(?:[\"'`\w{[(])", re.M)
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)


def sha256(value):
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def redact(text):
    text = str(text)
    for _, pattern in SECRET_RULES:
        text = re.sub(pattern, "[REDACTED]", text)
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+", r"\1[REDACTED]", text)
    return text


def clean_endpoint(value):
    return value.rstrip(".,);]}'\"`")


def canonical_url(url):
    parts = urlsplit(url)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def allowed_url(url, origins, allow_actions):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return False
    origin = f"{parts.scheme}://{parts.netloc}"
    if origin not in origins:
        return False
    if parts.username or parts.password:
        return False
    if not allow_actions and parts.path.rsplit("/", 1)[-1].lower() in BLOCKED_PATHS:
        return False
    return True


def origin(url):
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def local_path(url):
    parts = urlsplit(url)
    name = parts.path.strip("/") or "index"
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    if parts.query:
        name += "_q_" + sha256(parts.query)[:12]
    return name


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
        self.forms = []
        self.fields = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        for key in ("href", "src", "action", "data", "poster"):
            if attributes.get(key):
                self.urls.append(attributes[key])
        if tag == "form":
            self.forms.append(attributes.get("action", ""))
        if tag in ("input", "select", "textarea", "button"):
            for key in ("name", "id"):
                if attributes.get(key):
                    self.fields.append(attributes[key])


class Miner:
    def __init__(self, output, ca_bundle=None, rate=1.0, timeout=15, max_pages=50, max_assets=100, max_depth=2, allow_actions=False, ignore_robots=False):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.ca_bundle = ca_bundle
        self.rate = max(rate, 0.2)
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_assets = max_assets
        self.max_depth = max_depth
        self.allow_actions = allow_actions
        self.ignore_robots = ignore_robots
        self.session = requests.Session()
        self.session.verify = ca_bundle if ca_bundle else True
        self.session.headers["User-Agent"] = "JSP-JS-Miner/1.0"
        self.last_request = 0.0
        self.visited = set()
        self.pages = 0
        self.assets = 0
        self.records = []
        self.endpoints = set()
        self.parameters = set()
        self.findings = []
        self.secrets = []
        self.errors = []
        self.robots = {}

    def robots_for(self, origin):
        if self.ignore_robots:
            return None
        if origin in self.robots:
            return self.robots[origin]
        from urllib.robotparser import RobotFileParser
        parser = RobotFileParser()
        try:
            response = self.session.get(origin + "/robots.txt", timeout=self.timeout)
            if response.status_code == 200:
                parser.parse(response.text.splitlines())
            else:
                parser = None
        except requests.RequestException:
            parser = None
        self.robots[origin] = parser
        return parser

    def fetch(self, url):
        now = time.monotonic()
        wait = self.rate - (now - self.last_request)
        if wait > 0:
            time.sleep(wait)
        self.last_request = time.monotonic()
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            if response.status_code in (429, 500, 502, 503, 504):
                retry_after = response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    time.sleep(min(int(retry_after), 30))
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            return response
        except requests.RequestException as exc:
            self.errors.append({"url": url, "error": type(exc).__name__, "detail": str(exc)[:250]})
            return None

    def analyze(self, source, text, depth=0):
        parser = PageParser()
        parser.feed(text)
        for line_no, line in enumerate(text.splitlines(), 1):
            for category, pattern, confidence in STATIC_RULES:
                if re.search(pattern, line, re.I):
                    self.findings.append({"source": source, "line": line_no, "category": category, "confidence": confidence, "evidence": redact(line.strip())[:500]})
            for name, pattern in SECRET_RULES:
                match = re.search(pattern, line)
                if match:
                    self.secrets.append({"source": source, "line": line_no, "type": name, "confidence": "high" if name != "named-secret" else "medium", "match_sha256": sha256(match.group(0))[:16], "evidence": redact(line.strip())[:500]})
            for match in ENDPOINT_RE.finditer(line):
                endpoint = clean_endpoint(match.group(0))
                if endpoint:
                    self.endpoints.add(endpoint)
            for match in QUOTED_PATH_RE.finditer(line):
                self.endpoints.add(clean_endpoint(match.group(1)))
            for match in REQUEST_PARAMETER_RE.finditer(line):
                self.parameters.add(match.group(1))
            for match in QUERY_PARAM_RE.finditer(line):
                self.parameters.add(match.group(1))
            for match in FORM_FIELD_RE.finditer(line):
                self.parameters.add(match.group(1))
            for match in JS_KEY_RE.finditer(line):
                self.parameters.add(match.group(1))
        for comment in COMMENT_RE.findall(text):
            if re.search(r"(?:\.jspx?|https?://|TODO|FIXME|DEBUG|password|secret|token)", comment, re.I):
                self.findings.append({"source": source, "line": 0, "category": "html-comment", "confidence": "low", "evidence": redact(comment.strip())[:500]})
        return parser

    def save_source(self, url, text):
        path = self.output / "sources" / local_path(url)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(redact(text), encoding="utf-8", errors="replace")
        return str(path)

    def crawl(self, seeds):
        queue = deque((url, 0) for url in seeds)
        origins = {origin(url) for url in seeds}
        while queue and self.pages < self.max_pages and self.assets < self.max_assets:
            url, depth = queue.popleft()
            url = canonical_url(url)
            if url in self.visited or depth > self.max_depth or not allowed_url(url, origins, self.allow_actions):
                continue
            self.visited.add(url)
            robot = self.robots_for(origin(url))
            if robot and not robot.can_fetch("JSP-JS-Miner/1.0", url):
                continue
            response = self.fetch(url)
            if response is None:
                continue
            content_type = response.headers.get("Content-Type", "")
            suffix = urlsplit(url).path.rsplit("/", 1)[-1].lower()
            is_js = suffix.endswith(".js") or "javascript" in content_type
            is_map = suffix.endswith(".map") or "json" in content_type
            if is_js or is_map:
                if self.assets >= self.max_assets:
                    break
                self.assets += 1
            else:
                self.pages += 1
            text = response.text
            record = {
                "url": url,
                "status": response.status_code,
                "content_type": content_type,
                "depth": depth,
                "sha256": sha256(text),
                "bytes": len(response.content),
                "headers": {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower() in {
                        "content-type", "content-length", "cache-control",
                        "x-frame-options", "content-security-policy",
                        "strict-transport-security", "x-content-type-options",
                        "x-xss-protection", "location",
                    }
                },
            }
            record["source_path"] = self.save_source(url, text)
            self.records.append(record)
            parser = self.analyze(url, text, depth)
            for linked in parser.urls + parser.forms:
                child = canonical_url(urljoin(url, linked))
                if not allowed_url(child, origins, self.allow_actions):
                    continue
                child_suffix = urlsplit(child).path.rsplit("/", 1)[-1].lower()
                if child_suffix.endswith((".js", ".map")) and self.assets < self.max_assets:
                    queue.append((child, depth + 1))
                elif depth < self.max_depth and not child_suffix.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".css", ".ico", ".woff", ".woff2", ".ttf", ".pdf")):
                    queue.append((child, depth + 1))
            for match in SOURCE_MAP_RE.finditer(text):
                map_url = canonical_url(urljoin(url, match.group(1).strip("'\"")))
                if allowed_url(map_url, origins, self.allow_actions) and self.assets < self.max_assets:
                    queue.append((map_url, depth + 1))
        self.finish()

    def scan(self, input_dir):
        for path in sorted(Path(input_dir).rglob("*")):
            if not path.is_file() or path.suffix.lower() not in TEXT_TYPES:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.errors.append({"source": str(path), "error": type(exc).__name__, "detail": str(exc)[:250]})
                continue
            relative = str(path.relative_to(input_dir))
            record = {"source": relative, "sha256": sha256(text), "bytes": len(text.encode("utf-8")), "source_path": str(path)}
            self.records.append(record)
            self.analyze(relative, text)
        self.finish()

    def markdown(self, summary):
        def md(value):
            return str(value).replace("|", "\\|").replace("\n", " ")

        lines = [
            "# JSP/JavaScript Mining Report",
            "",
            "Static observations are candidates for review, not confirmed vulnerabilities. Secret values are redacted.",
            "",
            "## Summary",
            "",
        ]
        for key, value in summary.items():
            lines.append(f"- **{key}**: `{value}`")
        lines += [
            "",
            "## Source inventory",
            "",
            "| Source | Status | Content type | Depth | SHA-256 |",
            "|---|---|---|---|---|",
        ]
        for record in self.records:
            lines.append(f"| {md(record.get('url', record.get('source', '')))} | {record.get('status', '')} | {md(record.get('content_type', ''))} | {record.get('depth', '')} | `{record.get('sha256', '')}` |")
        lines += [
            "",
            "## Static findings",
            "",
            "| Source | Line | Category | Confidence | Evidence |",
            "|---|---|---|---|---|",
        ]
        for finding in self.findings:
            lines.append(f"| {md(finding['source'])} | {finding['line']} | {finding['category']} | {finding['confidence']} | {md(finding['evidence'])} |")
        lines += [
            "",
            "## Secret candidates",
            "",
            "| Source | Line | Type | Confidence | Match SHA-256 |",
            "|---|---|---|---|---|",
        ]
        for secret in self.secrets:
            lines.append(f"| {md(secret['source'])} | {secret['line']} | {secret['type']} | {secret['confidence']} | `{secret['match_sha256']}` |")
        lines += ["", "## Endpoints", ""]
        lines.extend(f"- `{endpoint}`" for endpoint in sorted(self.endpoints))
        lines += ["", "## Parameters", ""]
        lines.extend(f"- `{parameter}`" for parameter in sorted(self.parameters))
        lines += ["", "## Errors", ""]
        for error in self.errors:
            lines.append(f"- `{md(error)}`")
        return "\n".join(lines) + "\n"

    def finish(self):
        write_jsonl(self.output / "files.jsonl", self.records)
        write_jsonl(self.output / "findings.jsonl", self.findings)
        write_jsonl(self.output / "secrets.jsonl", self.secrets)
        write_jsonl(self.output / "errors.jsonl", self.errors)
        (self.output / "endpoints.txt").write_text("\n".join(sorted(self.endpoints)) + "\n")
        (self.output / "parameters.txt").write_text("\n".join(sorted(self.parameters)) + "\n")
        summary = {
            "pages": self.pages,
            "javascript_and_map_assets": self.assets,
            "source_files": len(self.records),
            "endpoints": len(self.endpoints),
            "parameters": len(self.parameters),
            "static_findings": len(self.findings),
            "secret_candidates": len(self.secrets),
            "errors": len(self.errors),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        (self.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        (self.output / "REPORT.md").write_text(self.markdown(summary))


def write_jsonl(path, records):
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    crawl = sub.add_parser("crawl")
    crawl.add_argument("--seed", action="append", required=True)
    crawl.add_argument("--output", required=True)
    crawl.add_argument("--ca-bundle", required=True)
    crawl.add_argument("--rate", type=float, default=1.0)
    crawl.add_argument("--timeout", type=float, default=15)
    crawl.add_argument("--max-pages", type=int, default=50)
    crawl.add_argument("--max-assets", type=int, default=100)
    crawl.add_argument("--max-depth", type=int, default=2)
    crawl.add_argument("--allow-actions", action="store_true")
    crawl.add_argument("--ignore-robots", action="store_true")
    scan = sub.add_parser("scan")
    scan.add_argument("--input-dir", required=True)
    scan.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "crawl":
        miner = Miner(args.output, args.ca_bundle, args.rate, args.timeout, args.max_pages, args.max_assets, args.max_depth, args.allow_actions, args.ignore_robots)
        miner.crawl(args.seed)
    else:
        miner = Miner(args.output)
        miner.scan(args.input_dir)


if __name__ == "__main__":
    main()
