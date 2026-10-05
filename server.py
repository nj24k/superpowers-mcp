#!/usr/bin/env python3
"""
SuperPowers MCP server v2.

Gives an AI client (ChatGPT via Developer Mode, Codex CLI, Cursor, Claude, ...)
superpowers WITHOUT touching this computer:
  - web_search / web_fetch : web ability (no API key)
  - http_request           : raw HTTP to any public API / webhook ("connect to anything")
  - github_read_file       : read any file from ANY public GitHub repo
  - github_list_files      : browse any public repo's directories
  - unlock                 : password gate (see Security)

There is deliberately NO shell, NO file access, NO local machine control.
ChatGPT itself is the brain — Codex-level code understanding, ChatGPT's mind.

Transports:
  - Streamable HTTP (default, for ChatGPT remote connectors):  python server.py
  - stdio (for local clients like Codex CLI / Cursor):          python server.py --stdio

Security (three layers):
  1. UNGUESSABLE URL PATH — the MCP endpoint lives at a secret random path
     (e.g. /mcp-9f2c...). Everything else 404s. Set SUPERPOWERS_PATH or a
     random one is generated once, saved to .superpowers_path, and printed.
  2. BEARER TOKEN — set SUPERPOWERS_TOKEN. Clients must send
     Authorization: Bearer <token>.
  3. PASSWORD GATE — set SUPERPOWERS_PASSWORD (or a random one is generated,
     saved to .superpowers_password, and printed). Every tool except `unlock`
     refuses until the model calls unlock(password) with the right password.
     5 wrong attempts = BRICKED for 30 minutes (server keeps running, tools
     all refuse). You give the password to ChatGPT in chat; nobody else has it.
"""

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import socket
import time
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP


def _sanitize_proxy_env() -> None:
    """Fix proxy env vars that crash httpx (malformed values are common in
    sandboxes/containers). Only touches vars that actually break client
    construction, so a working proxy setup is left intact."""
    import httpx as _hx
    for k in list(os.environ):
        if k.lower() in ("http_proxy", "https_proxy", "all_proxy"):
            try:
                _hx.URL(os.environ[k])
            except Exception:
                del os.environ[k]
    # httpx chokes on bracketed IPv6 in no_proxy ("[::1]" -> invalid port).
    for k in list(os.environ):
        if k.lower() == "no_proxy":
            fixed = []
            for entry in os.environ[k].split(","):
                e = entry.strip()
                if len(e) > 2 and e.startswith("[") and e.endswith("]"):
                    e = e[1:-1]
                fixed.append(e)
            os.environ[k] = ",".join(fixed)
    try:
        _hx.Client(trust_env=True).close()
    except Exception:
        for k in list(os.environ):
            if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
                del os.environ[k]


_sanitize_proxy_env()

mcp = FastMCP("SuperPowers")

HERE = Path(__file__).resolve().parent
TOKEN = os.environ.get("SUPERPOWERS_TOKEN", "").strip()


def _secret(name: str, env_var: str, prefix: str, nbytes: int = 18) -> str:
    """Env var wins; else a saved file; else generate once, save, and print."""
    if os.environ.get(env_var, "").strip():
        return os.environ[env_var].strip()
    f = HERE / f".superpowers_{name}"
    if f.exists():
        v = f.read_text().strip()
        if v:
            return v
    v = prefix + secrets.token_hex(nbytes)
    f.write_text(v)
    try:
        os.chmod(f, 0o600)
    except Exception:
        pass
    print(f"[SuperPowers] generated {name}: {v}  (saved to {f.name})", flush=True)
    return v


SECRET_PATH = _secret("path", "SUPERPOWERS_PATH", "/mcp-")
PASSWORD = _secret("password", "SUPERPOWERS_PASSWORD", "", 16)

# ------------------------------------------------------------ lock state ----

_unlocked = not bool(PASSWORD)  # no password configured -> open (with warning)
_failed_attempts = 0
_bricked_until = 0.0
BRICK_SECONDS = 1800
MAX_ATTEMPTS = 5


def _check_access() -> "str | None":
    """None = allowed; otherwise an error string to return."""
    now = time.time()
    if now < _bricked_until:
        mins = int((_bricked_until - now) // 60) + 1
        return f"BRICKED. Too many wrong passwords — try again in ~{mins} min."
    if PASSWORD and not _unlocked:
        return ("LOCKED. Call unlock(password) first — ask the user for the "
                "SuperPowers password.")
    return None


@mcp.tool()
def unlock(password: str) -> str:
    """Unlock SuperPowers with the password the user gives you in chat.
    Call this BEFORE any other tool. 5 wrong attempts bricks the server
    for 30 minutes."""
    global _unlocked, _failed_attempts, _bricked_until
    now = time.time()
    if now < _bricked_until:
        mins = int((_bricked_until - now) // 60) + 1
        return f"BRICKED. Still locked — try again in ~{mins} min."
    if not PASSWORD:
        _unlocked = True
        return "[OK] no password configured — unlocked."
    if password == PASSWORD:
        _unlocked = True
        _failed_attempts = 0
        return ("[OK] unlocked. Web, API, and GitHub superpowers are live. "
                "Note: this server has NO access to the user's computer — "
                "web/GitHub/API tools only.")
    _failed_attempts += 1
    if _failed_attempts >= MAX_ATTEMPTS:
        _bricked_until = now + BRICK_SECONDS
        _failed_attempts = 0
        return ("WRONG password 5 times. SuperPowers is BRICKED for 30 minutes. "
                "The server is still running; just wait it out.")
    left = MAX_ATTEMPTS - _failed_attempts
    return f"[ERROR] wrong password ({left} attempt(s) left before 30-min brick)."


# ---------------------------------------------------------- ssrf guard ----

def _is_public_url(url: str) -> bool:
    """Refuse URLs resolving to private/loopback/link-local/multicast IPs.
    This server must never be usable to poke the user's local network."""
    try:
        host = httpx.URL(url).host
        if not host:
            return False
        hl = host.lower().rstrip(".")
        # Belt-and-suspenders: block local-looking names even if DNS is odd.
        if hl in ("localhost", "local", "internal", "lan", "home") or hl.endswith(
                (".local", ".localhost", ".internal", ".lan", ".home",
                 ".localdomain", ".invalid", ".test", ".example")):
            return False
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
                return False
        return True
    except Exception:
        return False


# ------------------------------------------------------------------ web ----

@mcp.tool()
def web_search(query: str, count: int = 5) -> str:
    """Search the web (DuckDuckGo, no API key needed). Returns titles/URLs/snippets."""
    err = _check_access()
    if err:
        return err
    UA = {"User-Agent": "Mozilla/5.0"}
    try:  # html results page (best quality; occasionally bot-limited)
        r = httpx.get("https://html.duckduckgo.com/html/",
                      params={"q": query}, headers=UA, timeout=20)
        r.raise_for_status()
        results = []
        for m in re.finditer(
                r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>.*?' +
                r'class="result__snippet"[^>]*>(.*?)</a>',
                r.text, re.S):
            url, title, snippet = m.groups()
            um = re.search(r"uddg=([^&]+)", url)
            if um:
                from urllib.parse import unquote
                url = unquote(um.group(1))
            clean = lambda s: re.sub(r"<[^>]+>", "", s).strip()
            results.append(f"- {clean(title)}\n  {url}\n  {clean(snippet)}")
            if len(results) >= count:
                break
        if results:
            return "\n".join(results)
    except Exception:
        pass
    try:  # fallback: instant-answer API (thinner, rarely blocked)
        r = httpx.get("https://api.duckduckgo.com/",
                      params={"q": query, "format": "json", "no_html": "1"},
                      headers=UA, timeout=20)
        d = r.json()
        out = []
        if d.get("Abstract"):
            out.append(f"{d.get('AbstractSource', 'Source')}: "
                       f"{d['Abstract']}\n{d.get('AbstractURL', '')}")
        for t in (d.get("RelatedTopics") or [])[:count]:
            if isinstance(t, dict) and t.get("FirstURL"):
                out.append(f"- {t.get('Text', '')[:200]}\n  {t['FirstURL']}")
        return "\n".join(out) or "(no results)"
    except Exception as e:
        return f"[ERROR] {e}"


@mcp.tool()
def web_fetch(url: str, max_chars: int = 10000) -> str:
    """Fetch a web page and return its readable text. Public URLs only."""
    err = _check_access()
    if err:
        return err
    if not _is_public_url(url):
        return "[ERROR] refused: URL resolves to a private/local address."
    try:
        r = httpx.get(url, headers={"User-Agent": "Mozilla/5.0"},
                      timeout=25, follow_redirects=True)
        r.raise_for_status()
        html = r.text
        html = re.sub(r"(?is)<(script|style|nav|footer|header)[^>]*>.*?</\1>", " ", html)
        text = re.sub(r"(?s)<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:max_chars] + ("..." if len(text) > max_chars else "")
    except Exception as e:
        return f"[ERROR] {e}"


@mcp.tool()
def http_request(method: str, url: str, headers: str = "",
                 body: str = "", timeout: int = 30) -> str:
    """Raw HTTP request to any PUBLIC API/endpoint. headers/body as JSON strings.
    The 'connect to anything' tool: REST APIs, webhooks, public services.
    Local/private network addresses are refused."""
    err = _check_access()
    if err:
        return err
    if not _is_public_url(url):
        return "[ERROR] refused: URL resolves to a private/local address."
    try:
        h = json.loads(headers) if headers.strip() else {}
        data = body.encode() if body else None
        r = httpx.request(method.upper(), url, headers=h, content=data,
                          timeout=timeout, follow_redirects=True)
        return f"[HTTP {r.status_code}]\n{r.text[:12000]}"
    except Exception as e:
        return f"[ERROR] {e}"


# --------------------------------------------------------------- github ----

def _gh_headers() -> dict:
    h = {"Accept": "application/vnd.github+json",
         "User-Agent": "SuperPowers-MCP"}
    if os.environ.get("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    return h


def _gh_default_branch(repo: str) -> str:
    meta = httpx.get(f"https://api.github.com/repos/{repo}",
                     headers=_gh_headers(), timeout=20).json()
    return meta.get("default_branch", "main")


@mcp.tool()
def github_read_file(repo: str, path: str, ref: str = "HEAD") -> str:
    """Read a file from ANY public GitHub repo (Codex-level code reading,
    with YOUR chat's brain). repo like 'owner/name'. ref = branch/tag/HEAD."""
    err = _check_access()
    if err:
        return err
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        return "[ERROR] repo must look like 'owner/name'"
    if ".." in path or path.startswith("/"):
        return "[ERROR] invalid path"
    try:
        if ref == "HEAD":
            ref = _gh_default_branch(repo)
        r = httpx.get(f"https://api.github.com/repos/{repo}/contents/{path}",
                      params={"ref": ref}, headers=_gh_headers(), timeout=25)
        if r.status_code == 404:
            return f"[ERROR] not found: {repo}@{ref}/{path}"
        r.raise_for_status()
        d = r.json()
        if d.get("type") != "file" or "content" not in d:
            return f"[ERROR] not a file (type={d.get('type')})"
        txt = base64.b64decode(d["content"]).decode("utf-8", errors="replace")
        return txt[:30000] + ("..." if len(txt) > 30000 else "")
    except Exception as e:
        return f"[ERROR] {e}"


@mcp.tool()
def github_list_files(repo: str, path: str = "", ref: str = "HEAD") -> str:
    """List files/dirs in ANY public GitHub repo path (browse repo structure)."""
    err = _check_access()
    if err:
        return err
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        return "[ERROR] repo must look like 'owner/name'"
    try:
        if ref == "HEAD":
            ref = _gh_default_branch(repo)
        r = httpx.get(f"https://api.github.com/repos/{repo}/contents/{path}",
                      params={"ref": ref}, headers=_gh_headers(), timeout=25)
        if r.status_code == 404:
            return f"[ERROR] not found: {repo}@{ref}/{path}"
        r.raise_for_status()
        d = r.json()
        if isinstance(d, dict):
            return f"[ERROR] not a directory (type={d.get('type')})"
        lines = [f"[{'dir' if x['type'] == 'dir' else 'file'}] {x['name']}"
                 + (f" ({x['size']}b)" if x['type'] == 'file' else "")
                 for x in d]
        return f"{repo}@{ref}/{path or '.'}:\n" + "\n".join(lines[:200])
    except Exception as e:
        return f"[ERROR] {e}"


# ----------------------------------------------------------------- main ----

def main() -> None:
    ap = argparse.ArgumentParser(description="SuperPowers MCP server")
    ap.add_argument("--stdio", action="store_true",
                    help="stdio transport (for Codex CLI / Cursor / Claude local use)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    if args.stdio:
        if PASSWORD:
            print("Note: password gate is active even over stdio; "
                  "call unlock(password) first.", flush=True)
        mcp.run(transport="stdio")
        return

    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse
    import uvicorn

    inner = mcp.streamable_http_app()

    if TOKEN:
        class TokenAuth(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                if request.headers.get("authorization", "") != f"Bearer {TOKEN}":
                    return JSONResponse({"error": "unauthorized"}, status_code=401)
                return await call_next(request)

        token_app = TokenAuth(inner)
        print("Auth: bearer token required", flush=True)
    else:
        token_app = inner
        print("WARNING: no SUPERPOWERS_TOKEN set — relying on secret URL + "
              "password gate only.", flush=True)

    # Stealth first: unknown paths 404 (scanners learn nothing), then token.
    # The inner MCP app only knows its /mcp route, so rewrite the secret
    # path to /mcp before handing off.
    async def app(scope, receive, send):
        if scope["type"] == "http":
            if scope.get("path") != SECRET_PATH:
                resp = JSONResponse({"error": "not found"}, status_code=404)
                await resp(scope, receive, send)
                return
            scope = dict(scope)
            scope["path"] = "/mcp"
            scope["raw_path"] = b"/mcp"
        await token_app(scope, receive, send)

    if PASSWORD:
        print("Password gate: ACTIVE — model must call unlock(password) first; "
              "5 wrong attempts = 30-min brick.", flush=True)
    else:
        print("WARNING: no SUPERPOWERS_PASSWORD set — password gate disabled.",
              flush=True)

    print(f"SuperPowers MCP endpoint path: {SECRET_PATH}", flush=True)
    print(f"Listening on http://{args.host}:{args.port}{SECRET_PATH}", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
