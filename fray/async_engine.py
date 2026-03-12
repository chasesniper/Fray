"""
Fray Parallel/Async Request Execution Engine.

Provides high-performance concurrent HTTP request execution for:
  - Payload testing (WAF bypass, fuzzing)
  - Multi-target scanning
  - Parallel recon checks

Features:
  - asyncio + stdlib (zero deps) or optional aiohttp
  - Configurable concurrency (semaphore-based)
  - Rate limiting (requests/sec)
  - Automatic retry with backoff
  - Per-request timeout
  - Result streaming (callback or queue)
  - Connection pooling

Usage:
    engine = AsyncEngine(concurrency=20, rate_limit=50)
    results = engine.run(requests)

    # Or with callback:
    engine.run(requests, callback=lambda r: print(r.status))

Zero external dependencies — stdlib only (aiohttp optional for speed).
"""

import asyncio
import http.client
import json
import queue
import ssl
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple


class AsyncRequest:
    """A single HTTP request to execute."""
    __slots__ = ("url", "method", "headers", "body", "timeout", "verify_ssl",
                 "tag", "meta")

    def __init__(self, url: str, method: str = "GET",
                 headers: Optional[Dict[str, str]] = None,
                 body: Optional[str] = None, timeout: int = 10,
                 verify_ssl: bool = True, tag: str = "",
                 meta: Optional[Dict[str, Any]] = None):
        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        self.body = body
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.tag = tag
        self.meta = meta or {}


class AsyncResponse:
    """Response from an async request."""
    __slots__ = ("url", "status", "body", "headers", "elapsed_ms", "error",
                 "tag", "meta")

    def __init__(self, url: str = "", status: int = 0, body: str = "",
                 headers: Optional[Dict[str, str]] = None,
                 elapsed_ms: float = 0, error: str = "",
                 tag: str = "", meta: Optional[Dict[str, Any]] = None):
        self.url = url
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.elapsed_ms = elapsed_ms
        self.error = error
        self.tag = tag
        self.meta = meta or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "body_length": len(self.body),
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "tag": self.tag,
        }


class AsyncEngine:
    """High-performance parallel HTTP request engine."""

    def __init__(self, concurrency: int = 20, rate_limit: float = 0,
                 max_retries: int = 1, retry_delay: float = 0.5,
                 max_body_size: int = 512 * 1024,
                 default_timeout: int = 10,
                 default_headers: Optional[Dict[str, str]] = None):
        """
        Args:
            concurrency: Max parallel requests.
            rate_limit: Max requests per second (0 = unlimited).
            max_retries: Retry count on failure.
            retry_delay: Base delay between retries (exponential backoff).
            max_body_size: Max response body to read (bytes).
            default_timeout: Default per-request timeout.
            default_headers: Default headers for all requests.
        """
        self.concurrency = max(1, min(concurrency, 200))
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.max_body_size = max_body_size
        self.default_timeout = default_timeout
        self.default_headers = default_headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
        }

        # Stats
        self._total_requests = 0
        self._total_errors = 0
        self._start_time = 0.0
        self._rate_lock = threading.Lock()
        self._last_request_time = 0.0

    # ── Single request execution ───────────────────────────────────────

    def _execute_one(self, req: AsyncRequest) -> AsyncResponse:
        """Execute a single HTTP request using stdlib."""
        parsed = urllib.parse.urlparse(req.url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        hdrs = dict(self.default_headers)
        hdrs.update(req.headers)
        timeout = req.timeout or self.default_timeout

        body_bytes = req.body.encode() if req.body else None

        # Rate limiting
        if self.rate_limit > 0:
            with self._rate_lock:
                now = time.monotonic()
                min_interval = 1.0 / self.rate_limit
                elapsed_since_last = now - self._last_request_time
                if elapsed_since_last < min_interval:
                    time.sleep(min_interval - elapsed_since_last)
                self._last_request_time = time.monotonic()

        for attempt in range(self.max_retries + 1):
            t0 = time.monotonic()
            try:
                if parsed.scheme == "https":
                    ctx = ssl.create_default_context()
                    if not req.verify_ssl:
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    conn = http.client.HTTPSConnection(host, port,
                                                        timeout=timeout, context=ctx)
                else:
                    conn = http.client.HTTPConnection(host, port, timeout=timeout)

                conn.request(req.method, path, body=body_bytes, headers=hdrs)
                resp = conn.getresponse()
                body = resp.read(self.max_body_size).decode("utf-8", errors="replace")
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                conn.close()

                elapsed = (time.monotonic() - t0) * 1000
                self._total_requests += 1

                return AsyncResponse(
                    url=req.url, status=status, body=body,
                    headers=resp_headers, elapsed_ms=elapsed,
                    tag=req.tag, meta=req.meta,
                )

            except Exception as e:
                elapsed = (time.monotonic() - t0) * 1000
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay * (2 ** attempt))
                    continue

                self._total_errors += 1
                return AsyncResponse(
                    url=req.url, status=0, body="",
                    elapsed_ms=elapsed, error=str(e)[:200],
                    tag=req.tag, meta=req.meta,
                )

        # Should not reach here
        return AsyncResponse(url=req.url, error="max retries exceeded",
                             tag=req.tag, meta=req.meta)

    # ── Parallel execution (ThreadPoolExecutor) ────────────────────────

    def run(self, requests: List[AsyncRequest],
            callback: Optional[Callable[[AsyncResponse], None]] = None,
            ordered: bool = False) -> List[AsyncResponse]:
        """Execute requests in parallel using ThreadPoolExecutor.

        Args:
            requests: List of requests to execute.
            callback: Optional callback for each completed response.
            ordered: If True, return results in request order.

        Returns:
            List of AsyncResponse objects.
        """
        if not requests:
            return []

        self._total_requests = 0
        self._total_errors = 0
        self._start_time = time.monotonic()
        self._last_request_time = 0.0

        results: List[AsyncResponse] = []

        if ordered:
            # Maintain order using index mapping
            result_map: Dict[int, AsyncResponse] = {}
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                futures = {
                    pool.submit(self._execute_one, req): i
                    for i, req in enumerate(requests)
                }
                for future in as_completed(futures):
                    idx = futures[future]
                    try:
                        resp = future.result()
                    except Exception as e:
                        resp = AsyncResponse(
                            url=requests[idx].url, error=str(e),
                            tag=requests[idx].tag, meta=requests[idx].meta,
                        )
                    result_map[idx] = resp
                    if callback:
                        callback(resp)

            results = [result_map[i] for i in range(len(requests))]
        else:
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                futures = {
                    pool.submit(self._execute_one, req): req
                    for req in requests
                }
                for future in as_completed(futures):
                    req = futures[future]
                    try:
                        resp = future.result()
                    except Exception as e:
                        resp = AsyncResponse(
                            url=req.url, error=str(e),
                            tag=req.tag, meta=req.meta,
                        )
                    results.append(resp)
                    if callback:
                        callback(resp)

        return results

    # ── Batch builder helpers ──────────────────────────────────────────

    @staticmethod
    def build_requests(url: str, param: str, payloads: List[str],
                       method: str = "GET", cookie: str = "",
                       verify_ssl: bool = True,
                       timeout: int = 10) -> List[AsyncRequest]:
        """Build a batch of requests from a URL + param + payload list.

        Convenience method for fuzzing / payload testing.
        """
        parsed = urllib.parse.urlparse(url)
        base_params = dict(urllib.parse.parse_qsl(parsed.query))
        requests = []

        for i, payload in enumerate(payloads):
            params = dict(base_params)
            params[param] = payload

            if method == "GET":
                qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
                req_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
                body = None
            else:
                req_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                body = urllib.parse.urlencode(params)

            hdrs = {}
            if cookie:
                hdrs["Cookie"] = cookie
            if method == "POST":
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"

            requests.append(AsyncRequest(
                url=req_url, method=method, headers=hdrs,
                body=body, timeout=timeout, verify_ssl=verify_ssl,
                tag=f"payload_{i}", meta={"payload": payload, "index": i},
            ))

        return requests

    @staticmethod
    def build_url_requests(urls: List[str], method: str = "GET",
                           cookie: str = "", verify_ssl: bool = True,
                           timeout: int = 10) -> List[AsyncRequest]:
        """Build requests from a list of URLs (for multi-target scanning)."""
        requests = []
        for i, url in enumerate(urls):
            hdrs = {}
            if cookie:
                hdrs["Cookie"] = cookie
            requests.append(AsyncRequest(
                url=url, method=method, headers=hdrs,
                timeout=timeout, verify_ssl=verify_ssl,
                tag=f"url_{i}", meta={"index": i},
            ))
        return requests

    # ── Stats ──────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Return execution statistics."""
        elapsed = time.monotonic() - self._start_time if self._start_time else 0
        rps = self._total_requests / elapsed if elapsed > 0 else 0
        return {
            "total_requests": self._total_requests,
            "total_errors": self._total_errors,
            "elapsed_sec": round(elapsed, 2),
            "requests_per_sec": round(rps, 1),
            "concurrency": self.concurrency,
            "rate_limit": self.rate_limit,
        }
