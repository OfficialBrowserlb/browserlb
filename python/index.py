from __future__ import annotations

import html
import ipaddress
import re
import secrets
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from flask import Flask, jsonify, request

app = Flask(__name__)

_SQLI_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC)\b.{0,20}\b(FROM|INTO|TABLE)\b)",
    r"(--|;|/\*|\*/)",
    r"(\bOR\b\s+\d+\s*=\s*\d+)",
]
_XSS_PATTERNS = [
    r"<script[^>]*>",
    r"on\w+\s*=\s*['\"]",
    r"javascript:",
]
_COMPILED_SQLI = [re.compile(p, re.IGNORECASE) for p in _SQLI_PATTERNS]
_COMPILED_XSS = [re.compile(p, re.IGNORECASE) for p in _XSS_PATTERNS]

_BLOCKED_HOST_SUFFIXES = (".local", ".internal", "localhost")


def sanitize_input(text: str, max_len: int = 512) -> str:
    """Strip control chars, cap length, and HTML-escape user text before
    it's ever logged, stored, or reflected back to a client."""
    if not isinstance(text, str):
        return ""
    text = text[:max_len]
    text = "".join(ch for ch in text if ch.isprintable())
    return html.escape(text, quote=True)


def looks_malicious(text: str) -> bool:
    """Quick heuristic scan for SQLi/XSS shaped payloads in a query string."""
    return any(p.search(text) for p in _COMPILED_SQLI + _COMPILED_XSS)


def is_safe_url(raw_url: str) -> tuple[bool, str]:
    """Validate a URL before the backend is allowed to fetch/render it.

    Blocks:
      - non-http(s) schemes (file://, ftp://, data:, etc.)
      - requests aimed at loopback/private/link-local IPs (SSRF protection,
        i.e. stops the browser backend from being tricked into hitting
        internal infrastructure like 127.0.0.1 or 169.254.169.254)
      - obviously internal-only hostnames
    """
    try:
        parsed = urlparse(raw_url)
    except ValueError:
        return False, "unparseable URL"

    if parsed.scheme not in ("http", "https"):
        return False, f"scheme '{parsed.scheme}' not allowed"

    hostname = parsed.hostname or ""
    if not hostname:
        return False, "missing hostname"

    if hostname.lower() in _BLOCKED_HOST_SUFFIXES or hostname.lower().endswith(_BLOCKED_HOST_SUFFIXES):
        return False, "internal hostname blocked"

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
      
        return True, "ok"

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False, f"blocked private/internal address {ip_str}"

    return True, "ok"


@dataclass
class RateLimiter:
    """Very small in-memory sliding-window limiter, keyed by client IP."""

    window_seconds: float = 10.0
    max_requests: int = 20
    _hits: dict[str, list[float]] = field(default_factory=dict)

    def allow(self, key: str) -> bool:
        now = time.time()
        bucket = self._hits.setdefault(key, [])
        bucket[:] = [t for t in bucket if now - t < self.window_seconds]
        if len(bucket) >= self.max_requests:
            return False
        bucket.append(now)
        return True


_rate_limiter = RateLimiter()


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)

def render_search_results(query: str) -> list[dict]:
    """Turn a sanitized query into a normalized result list.

    This is a stub: in production this would call a real search API
    (e.g. a Custom Search JSON API) rather than scraping a search
    engine's result page directly. The shape returned here matches the
    SearchResult struct used by the Go core and the JS/TS frontend.
    """
    return [
        {
            "title": f"Results for '{query}' — BrowserLB",
            "url": f"https://example.com/search?q={query}",
            "snippet": "Rendered by the BrowserLB Python backend.",
        }
    ]


@app.before_request
def _enforce_rate_limit():
    client_key = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    if not _rate_limiter.allow(client_key):
        return jsonify(error="rate limit exceeded"), 429


@app.route("/api/search", methods=["GET"])
def api_search():
    raw_query = request.args.get("q", "")
    if not raw_query:
        return jsonify(error="missing q param"), 400

    if looks_malicious(raw_query):
        return jsonify(error="query rejected by security filter"), 400

    query = sanitize_input(raw_query, max_len=256)
    results = render_search_results(query)
    return jsonify(query=query, results=results)


@app.route("/api/render", methods=["GET"])
def api_render():
    """Safely fetch+render a page preview, guarding against SSRF."""
    target = request.args.get("url", "")
    safe, reason = is_safe_url(target)
    if not safe:
        return jsonify(error=f"blocked: {reason}"), 400
    return jsonify(url=target, status="approved-for-fetch", note="Go core performs the actual network fetch")


@app.route("/api/csrf-token", methods=["GET"])
def api_csrf_token():
    return jsonify(csrfToken=generate_csrf_token())


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify(status="ok", service="browserlb-python")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
