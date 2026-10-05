#!/usr/bin/env python3
"""
SuperPowers MCP server v2.

Gives an AI client (ChatGPT via Developer Mode, Codex CLI, Cursor, Claude, ...)
superpowers WITHOUT touching this computer:
  - web_search / web_fetch : web ability (no API key)
  - http_request           : raw HTTP to any public API / webhook ("connect to anything")
  - github_read_file       : read any file from ANY public GitHub repo
  - github_list_files      : browse any public repo's directories
  - github_compare         : diff two refs (branch/tag/commit) in any public repo
  - github_list_issues     : list issues/PRs on any public repo (bug reports = gold)
  - youtube_transcript     : full transcript of ANY YouTube video
  - appstore_search        : search the App Store (ratings, reviews, price)
  - appstore_reviews       : read real App Store reviews (complaints = product ideas)
  - hn_search              : search Hacker News stories
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
import csv
import datetime
import glob
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

try:
    from mcp.server.fastmcp import Image as _MCPImage
except Exception:
    _MCPImage = None  # image tools degrade gracefully on old mcp versions

try:
    import feedparser as _feedparser
except Exception:
    _feedparser = None

try:
    from bs4 import BeautifulSoup as _BeautifulSoup
except Exception:
    _BeautifulSoup = None

try:
    from pypdf import PdfReader as _PdfReader
except Exception:
    _PdfReader = None


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
        return ("[OK] unlocked. All 62 SuperPowers are live: web, OSINT, GitHub, "
                "YouTube, App Store, HN, research, live data & more. "
                "Note: this server has NO access to the user's computer — "
                "web/intel/API tools only.")
    _failed_attempts += 1
    if _failed_attempts >= MAX_ATTEMPTS:
        _bricked_until = now + BRICK_SECONDS
        _failed_attempts = 0
        return ("WRONG password 5 times. SuperPowers is BRICKED for 30 minutes. "
                "The server is still running; just wait it out.")
    left = MAX_ATTEMPTS - _failed_attempts
    return f"[ERROR] wrong password ({left} attempt(s) left before 30-min brick)."


# ---------------------------------------------------------- ssrf guard ----

def _host_is_public(host: str) -> bool:
    """True if host doesn't look local AND doesn't resolve to a private IP."""
    try:
        hl = host.lower().rstrip(".")
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


def _is_public_url(url: str) -> bool:
    """Refuse URLs resolving to private/loopback/link-local/multicast IPs.
    This server must never be usable to poke the user's local network."""
    try:
        host = httpx.URL(url).host
        return bool(host) and _host_is_public(host)
    except Exception:
        return False


def _blocked(url: str):
    """SSRF guard for user-supplied URLs. Returns error string or None."""
    if not _is_public_url(url):
        return "[BLOCKED] that address is private/local — refusing (SSRF guard)"
    return None


_UA = {"User-Agent": "SuperPowers-MCP/4.0"}


def _jget(url, params=None, timeout=25, headers=None):
    r = httpx.get(url, params=params, timeout=timeout, follow_redirects=True,
                  headers={**_UA, **(headers or {})})
    r.raise_for_status()
    return r.json()


def _tget(url, timeout=25, headers=None, max_chars=200000):
    r = httpx.get(url, timeout=timeout, follow_redirects=True,
                  headers={**_UA, **(headers or {})})
    r.raise_for_status()
    return r.text[:max_chars]


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


def _gh_repo_ok(repo: str) -> "str | None":
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        return "[ERROR] repo must look like 'owner/name'"
    return None


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
    if err := _gh_repo_ok(repo):
        return err
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

# --------------------------------------------------- power tools: video ----

@mcp.tool()
def youtube_transcript(url: str, max_chars: int = 12000) -> str:
    """Get the transcript/captions of ANY YouTube video. Pass a watch URL or video ID."""
    err = _check_access()
    if err:
        return err
    m = re.search(r"(?:v=|youtu\.be/|shorts/|embed/)([A-Za-z0-9_-]{11})", url)
    vid = m.group(1) if m else url.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{11}", vid):
        return "[ERROR] couldn't parse an 11-char video ID from that input"
    try:
        tmp = tempfile.mkdtemp(prefix="ytcaps_")
        out_tmpl = os.path.join(tmp, "%(id)s.%(ext)s")
        proc = subprocess.run(
            [sys.executable, "-m", "yt_dlp", "--skip-download",
             "--write-auto-subs", "--sub-langs", "en.*",
             "--sub-format", "vtt", "-o", out_tmpl,
             "--no-playlist", "--quiet",
             f"https://www.youtube.com/watch?v={vid}"],
            capture_output=True, text=True, timeout=90)
        vtts = glob.glob(os.path.join(tmp, "*.vtt"))
        if not vtts:
            shutil.rmtree(tmp, ignore_errors=True)
            return (f"[ERROR] no English captions found for {vid} "
                    f"(video may have captions disabled). {proc.stderr[-200:]}")
        lines: list = []
        seen = set()
        with open(vtts[0], encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if (not line or line == "WEBVTT" or "-->" in line
                        or line.startswith("NOTE")):
                    continue
                line = re.sub(r"<[^>]+>", "", line).strip()  # inline tags
                if line and line not in seen:
                    seen.add(line)
                    lines.append(line)
        shutil.rmtree(tmp, ignore_errors=True)
        text = " ".join(lines)
        if not text:
            return f"[ERROR] captions were empty for {vid}"
        return text[:max_chars]
    except subprocess.TimeoutExpired:
        return f"[ERROR] caption fetch timed out for {vid}"
    except Exception as e:
        return f"[ERROR] transcript failed: {e}"

# --------------------------------------------- power tools: app research ----

@mcp.tool()
def appstore_search(term: str, country: str = "US", limit: int = 10) -> str:
    """Search the App Store for apps (name, rating, review count, price, genre, link)."""
    err = _check_access()
    if err:
        return err
    try:
        r = httpx.get("https://itunes.apple.com/search",
                      params={"term": term, "country": country,
                              "entity": "software", "limit": limit},
                      timeout=20).json()
    except Exception as e:
        return f"[ERROR] App Store search failed: {e}"
    hits = r.get("results", [])
    if not hits:
        return f"[INFO] no apps found for '{term}' ({country})"
    out = [f"App Store results for '{term}' ({country}):"]
    for a in hits:
        out.append(
            f"- {a.get('trackName')} (id {a.get('trackId')}) | "
            f"★ {a.get('averageUserRating', '?')}/5 from "
            f"{a.get('userRatingCount', 0):,} ratings | "
            f"price: {a.get('formattedPrice', '?')} | {a.get('primaryGenreName', '?')}\n"
            f"  by {a.get('sellerName', '?')} — {a.get('trackViewUrl', '')}")
    return "\n".join(out)

@mcp.tool()
def appstore_reviews(app_id: str, country: str = "US",
                     sort: str = "mostRecent", max_chars: int = 6000) -> str:
    """Read real App Store reviews for any app (id = numeric App Store ID).
    sort: 'mostRecent' or 'mostHelpful'. Complaints = gold for product research."""
    err = _check_access()
    if err:
        return err
    try:
        r = httpx.get(
            f"https://itunes.apple.com/{country}/rss/customerreviews/"
            f"id={app_id}/sortBy={sort}/json",
            timeout=20).json()
    except Exception as e:
        return f"[ERROR] review fetch failed: {e}"
    try:
        entries = r["feed"]["entry"]
    except KeyError:
        return f"[INFO] no reviews found for app id {app_id} ({country})"
    out = [f"App Store reviews for app id {app_id} ({country}, {sort}):"]
    for e in entries[1:11]:  # first entry is app metadata
        rating = e.get("im:rating", {}).get("label", "?")
        title = e.get("title", {}).get("label", "")
        body = e.get("content", {}).get("label", "")[:400]
        author = e.get("author", {}).get("name", {}).get("label", "?")
        ver = e.get("im:version", {}).get("label", "?")
        out.append(f"- ★{rating} '{title}' by {author} (v{ver}): {body}")
    return "\n".join(out)[:max_chars]

# --------------------------------------------------- power tools: HN --------

@mcp.tool()
def hn_search(query: str, count: int = 8) -> str:
    """Search Hacker News stories — great for finding what devs/users complain about."""
    err = _check_access()
    if err:
        return err
    try:
        r = httpx.get("https://hn.algolia.com/api/v1/search",
                      params={"query": query, "tags": "story",
                              "hitsPerPage": count},
                      timeout=20).json()
    except Exception as e:
        return f"[ERROR] HN search failed: {e}"
    hits = r.get("hits", [])
    if not hits:
        return f"[INFO] no HN stories for '{query}'"
    out = [f"Hacker News results for '{query}':"]
    for h in hits:
        link = f"https://news.ycombinator.com/item?id={h['objectID']}"
        out.append(
            f"- {h.get('title')} | {h.get('points', 0)} pts, "
            f"{h.get('num_comments', 0)} comments | {h.get('url', '')}\n"
            f"  discussion: {link}")
    return "\n".join(out)

# ---------------------------------------------- power tools: github pro -----

@mcp.tool()
def github_compare(repo: str, base: str, head: str) -> str:
    """Diff two refs in a public GitHub repo (branch, tag, or commit SHA).
    Shows status, ahead/behind, and per-file patches (truncated)."""
    err = _check_access()
    if err:
        return err
    if err := _gh_repo_ok(repo):
        return err
    try:
        r = httpx.get(
            f"https://api.github.com/repos/{repo}/compare/{base}...{head}",
            headers=_gh_headers(), timeout=30).json()
    except Exception as e:
        return f"[ERROR] compare failed: {e}"
    if "status" not in r:
        return f"[ERROR] {r.get('message', 'compare unavailable')}"
    out = [f"Compare {repo} {base}...{head}: {r['status']} | "
           f"+{r.get('ahead_by', 0)} ahead, -{r.get('behind_by', 0)} behind | "
           f"{r.get('total_commits', 0)} commits"]
    for f in r.get("files", [])[:12]:
        patch = (f.get("patch") or "")[:1500]
        out.append(
            f"\n{f['status'].upper()} {f['filename']} "
            f"(+{f.get('additions', 0)}/-{f.get('deletions', 0)})\n{patch}")
    n = len(r.get("files", []))
    if n > 12:
        out.append(f"\n... and {n - 12} more files")
    return "\n".join(out)

@mcp.tool()
def github_list_issues(repo: str, state: str = "open",
                       limit: int = 10) -> str:
    """List issues (and PRs) on a public GitHub repo. state: open/closed/all.
    Bug reports + feature requests = competitor gaps and user pain points."""
    err = _check_access()
    if err:
        return err
    if err := _gh_repo_ok(repo):
        return err
    try:
        r = httpx.get(f"https://api.github.com/repos/{repo}/issues",
                      params={"state": state, "per_page": limit,
                              "sort": "updated"},
                      headers=_gh_headers(), timeout=20,
                      follow_redirects=True).json()
    except Exception as e:
        return f"[ERROR] issues fetch failed: {e}"
    if not isinstance(r, list):
        return f"[ERROR] {r.get('message', 'issues unavailable')}"
    if not r:
        return f"[INFO] no {state} issues on {repo}"
    out = [f"{state.capitalize()} issues/PRs on {repo}:"]
    for i in r:
        kind = "PR" if "pull_request" in i else "issue"
        labels = ", ".join(l["name"] for l in i.get("labels", [])) or "no labels"
        body = (i.get("body") or "")[:250].replace("\n", " ")
        out.append(
            f"- #{i['number']} [{kind}] {i['title']} | "
            f"{i['comments']} comments | {labels} | by {i['user']['login']}\n"
            f"  {body}\n  {i['html_url']}")
    return "\n".join(out)

# ============================================================ web / osint ====

@mcp.tool()
def wayback_snapshot(url: str) -> str:
    """Time travel: get the closest Wayback Machine archive of any page (deleted/changed pages)."""
    err = _check_access()
    if err:
        return err
    try:
        d = json.loads(_tget(
            "https://archive.org/wayback/available?url="
            + urllib.parse.quote(url, safe=":/"), timeout=25))
    except Exception as e:
        return f"[ERROR] wayback lookup failed: {e}"
    snap = (d.get("archived_snapshots") or {}).get("closest")
    if not snap:
        return f"[INFO] no archived snapshot found for {url}"
    return (f"Closest snapshot of {url}:\n- taken: {snap.get('timestamp')}\n"
            f"- open: {snap.get('url')}")


@mcp.tool()
def rss_read(url: str, count: int = 10) -> str:
    """Read any RSS/Atom feed — latest headlines with links (blogs, changelogs, releases)."""
    err = _check_access() or _blocked(url)
    if err:
        return err
    if _feedparser is None:
        return "[ERROR] feedparser not installed — pip install -r requirements.txt"
    try:
        f = _feedparser.parse(url)
        if f.bozo and not f.entries:
            return f"[ERROR] couldn't parse a feed at {url}"
        out = [f"Feed: {f.feed.get('title', url)}"]
        for e in f.entries[:count]:
            out.append(f"- {e.get('title', '(no title)')}\n"
                       f"  {e.get('link', '')} | {e.get('published', '')}")
        return "\n".join(out)
    except Exception as e:
        return f"[ERROR] feed read failed: {e}"


@mcp.tool()
def sitemap_urls(domain: str, max_urls: int = 300) -> str:
    """List URLs from a site's sitemap.xml — full content inventory for competitor audits."""
    err = _check_access()
    if err:
        return err
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if not _host_is_public(domain):
        return "[BLOCKED] that host is private/local — refusing (SSRF guard)"
    try:
        import xml.etree.ElementTree as ET
        urls: list = []

        def grab(sm_url: str, depth: int = 0):
            if len(urls) >= max_urls or depth > 1:
                return
            xml = _tget(sm_url, max_chars=2000000)
            root = ET.fromstring(xml)
            ns = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
            if root.tag.endswith("sitemapindex"):
                for sm in root.findall(f"{ns}sitemap/{ns}loc")[:5]:
                    grab(sm.text.strip(), depth + 1)
            else:
                for u in root.findall(f"{ns}url/{ns}loc"):
                    if len(urls) < max_urls:
                        urls.append(u.text.strip())

        grab(f"https://{domain}/sitemap.xml")
        if not urls:
            return f"[INFO] no sitemap found (or empty) at {domain}/sitemap.xml"
        return f"Sitemap URLs for {domain} ({len(urls)} shown):\n" + "\n".join(
            f"- {u}" for u in urls)
    except Exception as e:
        return f"[ERROR] sitemap fetch failed: {e}"


@mcp.tool()
def robots_txt(domain: str) -> str:
    """Fetch a site's robots.txt — see what they hide from crawlers + their sitemap URLs."""
    err = _check_access()
    if err:
        return err
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if not _host_is_public(domain):
        return "[BLOCKED] that host is private/local — refusing (SSRF guard)"
    try:
        txt = _tget(f"https://{domain}/robots.txt", max_chars=8000)
        sitemaps = [l.split(":", 1)[1].strip() for l in txt.splitlines()
                    if l.lower().startswith("sitemap:")]
        out = f"robots.txt for {domain}:\n{txt}"
        if sitemaps:
            out += "\n\nDeclared sitemaps:\n" + "\n".join(f"- {s}" for s in sitemaps)
        return out
    except Exception as e:
        return f"[ERROR] robots.txt fetch failed: {e}"


@mcp.tool()
def dns_lookup(domain: str, rtype: str = "A") -> str:
    """DNS lookup for any domain (A, AAAA, MX, TXT, NS, CNAME, SOA) via DNS-over-HTTPS."""
    err = _check_access()
    if err:
        return err
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    try:
        d = _jget("https://dns.google/resolve",
                  params={"name": domain, "type": rtype.upper()})
    except Exception as e:
        return f"[ERROR] DNS lookup failed: {e}"
    if d.get("Status") != 0 or not d.get("Answer"):
        return f"[INFO] no {rtype.upper()} records for {domain}"
    recs = [a["data"] for a in d["Answer"] if a.get("type") != 46]
    return f"DNS {rtype.upper()} for {domain}:\n" + "\n".join(f"- {r}" for r in recs[:20])


@mcp.tool()
def rdap_lookup(domain: str) -> str:
    """Domain registration intel: registrar, created/expiry dates (RDAP, no key)."""
    err = _check_access()
    if err:
        return err
    domain = re.sub(r"^https?://", "", domain).split("/")[0].lower()
    try:
        d = _jget(f"https://rdap.org/domain/{domain}")
    except Exception as e:
        return f"[ERROR] RDAP lookup failed: {e}"
    if "ldhName" not in d:
        return f"[INFO] no RDAP data for {domain}"
    events = {e.get("eventAction"): e.get("eventDate", "")[:10]
              for e in d.get("events", [])}
    registrar = "?"
    for ent in d.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            vcard = ent.get("vcardArray", [[], []])[1]
            for item in vcard:
                if item[0] == "fn":
                    registrar = item[3]
    return (f"Domain: {d.get('ldhName')}\n- registrar: {registrar}\n"
            f"- registered: {events.get('registration', '?')}\n"
            f"- expires: {events.get('expiration', '?')}\n"
            f"- status: {', '.join(d.get('status', [])) or '?'}")


@mcp.tool()
def ssl_info(domain: str) -> str:
    """TLS certificate details for any domain: issuer, expiry, SANs (spot expiring certs)."""
    err = _check_access()
    if err:
        return err
    domain = re.sub(r"^https?://", "", domain).split("/")[0].split(":")[0]
    if not _host_is_public(domain):
        return "[BLOCKED] that host is private/local — refusing (SSRF guard)"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                cert = ss.getpeercert()
        subj = dict(x[0] for x in cert.get("subject", ()))
        iss = dict(x[0] for x in cert.get("issuer", ()))
        sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"][:15]
        return (f"TLS cert for {domain}:\n"
                f"- subject: {subj.get('commonName', '?')}\n"
                f"- issuer: {iss.get('organizationName', iss.get('commonName', '?'))}\n"
                f"- expires: {cert.get('notAfter', '?')}\n"
                f"- SANs: {', '.join(sans) or '?'}")
    except Exception as e:
        return f"[ERROR] TLS probe failed: {e}"


@mcp.tool()
def http_headers(url: str) -> str:
    """Show a URL's HTTP response headers — server, CDN, tech fingerprints, caching."""
    err = _check_access() or _blocked(url)
    if err:
        return err
    try:
        try:
            r = httpx.head(url, timeout=15, headers=_UA, follow_redirects=True)
            if r.status_code >= 400:
                raise RuntimeError("HEAD rejected")
        except Exception:
            r = httpx.get(url, timeout=15, headers=_UA, follow_redirects=True)
        interesting = ["server", "x-powered-by", "via", "cf-ray", "x-cache",
                       "content-type", "content-length", "strict-transport-security",
                       "x-frame-options", "location", "set-cookie"]
        out = [f"{url} -> HTTP {r.status_code}"]
        for k in interesting:
            if k in r.headers:
                v = r.headers[k][:160]
                out.append(f"- {k}: {v}{'...' if len(r.headers[k]) > 160 else ''}")
        return "\n".join(out)
    except Exception as e:
        return f"[ERROR] header fetch failed: {e}"


@mcp.tool()
def tech_detect(url: str) -> str:
    """Detect what a website is built with — CMS, framework, CDN (competitor recon)."""
    err = _check_access() or _blocked(url)
    if err:
        return err
    if _BeautifulSoup is None:
        return "[ERROR] beautifulsoup4 not installed — pip install -r requirements.txt"
    try:
        r = httpx.get(url, timeout=20, headers=_UA, follow_redirects=True)
        html = r.text[:300000]
        soup = _BeautifulSoup(html, "html.parser")
        found: list = []
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and gen.get("content"):
            found.append(f"generator meta: {gen['content']}")
        blob = html.lower()
        sigs = {
            "wp-content": "WordPress", "wp-includes": "WordPress",
            "_next/static": "Next.js", "__next": "Next.js",
            "__nuxt": "Nuxt.js", "gatsby": "Gatsby",
            "cdn.shopify.com": "Shopify", "myshopify": "Shopify",
            "webflow": "Webflow", "squarespace": "Squarespace",
            "wix.com": "Wix", "framer": "Framer",
            "cdn.jsdelivr.net/npm/react": "React", "vue.global": "Vue.js",
            "angular": "Angular", "svelte": "Svelte",
            "cloudflare": "Cloudflare (headers)", "fastly": "Fastly (headers)",
        }
        hdrs = " ".join(r.headers.values()).lower()
        for sig, name in sigs.items():
            if sig in blob or sig in hdrs:
                if name not in found:
                    found.append(name)
        srv = r.headers.get("server", "")
        if srv:
            found.append(f"server header: {srv[:80]}")
        if not found:
            return f"[INFO] no known fingerprints on {url}"
        return f"Tech detected on {url}:\n" + "\n".join(f"- {x}" for x in found)
    except Exception as e:
        return f"[ERROR] tech detect failed: {e}"


@mcp.tool()
def page_links(url: str, max_links: int = 100) -> str:
    """Extract all outbound links from a page — map a site's structure fast."""
    err = _check_access() or _blocked(url)
    if err:
        return err
    if _BeautifulSoup is None:
        return "[ERROR] beautifulsoup4 not installed — pip install -r requirements.txt"
    try:
        html = _tget(url, max_chars=300000)
        soup = _BeautifulSoup(html, "html.parser")
        links: list = []
        seen = set()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue
            full = urllib.parse.urljoin(url, href).split("#")[0]
            if full not in seen:
                seen.add(full)
                links.append(full)
            if len(links) >= max_links:
                break
        return f"Links on {url} ({len(links)} shown):\n" + "\n".join(
            f"- {l}" for l in links)
    except Exception as e:
        return f"[ERROR] link extraction failed: {e}"


@mcp.tool()
def crtsh_subdomains(domain: str, max_results: int = 100) -> str:
    """Find subdomains via Certificate Transparency logs (crt.sh) — real OSINT recon."""
    err = _check_access()
    if err:
        return err
    domain = re.sub(r"^https?://", "", domain).split("/")[0].lower()
    try:
        d = _jget(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
    except Exception as e:
        return f"[ERROR] crt.sh lookup failed: {e}"
    subs = set()
    for entry in d:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and name.endswith(domain):
                subs.add(name)
    subs = sorted(subs)[:max_results]
    if not subs:
        return f"[INFO] no subdomains found for {domain}"
    return f"Subdomains of {domain} ({len(subs)}):\n" + "\n".join(f"- {s}" for s in subs)


@mcp.tool()
def url_expander(url: str) -> str:
    """Follow a short/redirect URL to its final destination (shows every hop)."""
    err = _check_access() or _blocked(url)
    if err:
        return err
    try:
        chain = [url]
        cur = url
        for _ in range(5):
            r = httpx.get(cur, timeout=15, headers=_UA, follow_redirects=False)
            if r.status_code not in (301, 302, 303, 307, 308):
                break
            nxt = urllib.parse.urljoin(cur, r.headers["location"])
            if not _is_public_url(nxt):
                return ("Hop chain:\n" + "\n".join(f"{i}. {c}" for i, c in enumerate(chain))
                        + "\n[BLOCKED] next hop is private/local — stopping")
            chain.append(f"{r.status_code} -> {nxt}")
            cur = nxt
        return "Hop chain:\n" + "\n".join(f"{i}. {c}" for i, c in enumerate(chain))
    except Exception as e:
        return f"[ERROR] expand failed: {e}"


@mcp.tool()
def site_status(url: str) -> str:
    """Is this site up right now? Status code, response time, server header."""
    err = _check_access() or _blocked(url)
    if err:
        return err
    try:
        t0 = time.perf_counter()
        r = httpx.get(url, timeout=15, headers=_UA, follow_redirects=True)
        ms = int((time.perf_counter() - t0) * 1000)
        return (f"{url}\n- status: HTTP {r.status_code}\n"
                f"- response time: {ms} ms\n"
                f"- server: {r.headers.get('server', '?')}\n"
                f"- size: {len(r.content):,} bytes")
    except Exception as e:
        return f"[ERROR] {url} unreachable: {e}"


@mcp.tool()
def web_screenshot(url: str):
    """Take a real screenshot of any webpage and SEE it (ChatGPT can't do this alone)."""
    err = _check_access() or _blocked(url)
    if err:
        return err
    if _MCPImage is None:
        return "[ERROR] image output needs a newer mcp package"
    try:
        shot = ("https://s0.wp.com/mshots/v1/"
                + urllib.parse.quote(url, safe="") + "?w=1280")
        data = b""
        for attempt in range(2):  # mShots renders async; second pass is fresher
            r = httpx.get(shot, timeout=30, headers=_UA)
            data = r.content
            if attempt == 0:
                time.sleep(8)
        if len(data) < 5000:
            return "[ERROR] screenshot came back empty — try again in a minute"
        return _MCPImage(data=data, format="jpeg")
    except Exception as e:
        return f"[ERROR] screenshot failed: {e}"

# ================================================== search / knowledge ======

@mcp.tool()
def hn_thread(story_id: int, max_comments: int = 12) -> str:
    """Read a Hacker News thread's top comments (pass the story id from hn_search)."""
    err = _check_access()
    if err:
        return err
    try:
        item = _jget(f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json")
    except Exception as e:
        return f"[ERROR] HN thread fetch failed: {e}"
    if not item or item.get("type") != "story":
        return f"[INFO] no HN story with id {story_id}"
    out = [f"{item.get('title')} ({item.get('score', 0)} pts, "
           f"{item.get('descendants', 0)} comments)"]
    if item.get("text"):
        out.append(re.sub(r"<[^>]+>", "", item["text"])[:400] + "\n")
    for kid in (item.get("kids") or [])[:max_comments]:
        try:
            c = _jget(f"https://hacker-news.firebaseio.com/v0/item/{kid}.json")
        except Exception:
            continue
        if c and not c.get("deleted"):
            txt = re.sub(r"<[^>]+>", " ", c.get("text", "")).strip()
            txt = re.sub(r"\s+", " ", txt)[:350]
            out.append(f"- {c.get('by', '?')} ({c.get('score', 0)}↑): {txt}")
    return "\n".join(out)


@mcp.tool()
def tvmaze_search(query: str, count: int = 5) -> str:
    """Search TV shows — rating, status, network, summary (TVMaze, no key)."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://api.tvmaze.com/search/shows", params={"q": query})
    except Exception as e:
        return f"[ERROR] TV search failed: {e}"
    if not d:
        return f"[INFO] no shows for '{query}'"
    out = [f"TV shows for '{query}':"]
    for r in d[:count]:
        s = r.get("show", {})
        rating = (s.get("rating") or {}).get("average", "?")
        net = (s.get("network") or {}).get("name") or (
            s.get("webChannel") or {}).get("name", "?")
        summ = re.sub(r"<[^>]+>", "", s.get("summary") or "")[:220]
        out.append(f"- {s.get('name')} ({s.get('premiered', '?')[:4]}) | "
                   f"★{rating} | {s.get('status', '?')} on {net}\n  {summ}...")
    return "\n".join(out)


# ============================================================ file intel ====

@mcp.tool()
def fetch_file_preview(url: str, max_chars: int = 6000) -> str:
    """Download any file URL and extract readable text — PDFs, CSVs, text (ChatGPT can't fetch files itself)."""
    err = _check_access() or _blocked(url)
    if err:
        return err
    try:
        with httpx.stream("GET", url, timeout=30, headers=_UA,
                          follow_redirects=True) as r:
            r.raise_for_status()
            ctype = r.headers.get("content-type", "").lower()
            size = 0
            chunks = []
            for chunk in r.iter_bytes(65536):
                chunks.append(chunk)
                size += len(chunk)
                if size > 6 * 1024 * 1024:
                    break
        data = b"".join(chunks)
        if "pdf" in ctype or url.lower().endswith(".pdf"):
            if _PdfReader is None:
                return "[ERROR] pypdf not installed — pip install -r requirements.txt"
            reader = _PdfReader(io.BytesIO(data))
            text = "\n".join((p.extract_text() or "") for p in reader.pages[:3])
            return (f"PDF preview ({len(reader.pages)} pages, first 3 shown):\n"
                    + text[:max_chars])
        if "csv" in ctype or url.lower().endswith(".csv"):
            rows = list(csv.reader(io.StringIO(data.decode("utf-8", "ignore"))))
            head = "\n".join(",".join(c[:40] for c in row) for row in rows[:15])
            return (f"CSV preview ({len(rows)} rows x {len(rows[0]) if rows else 0} cols, "
                    f"first 15 rows):\n{head}"[:max_chars])
        text = data.decode("utf-8", "ignore")
        return f"File preview ({ctype or 'unknown type'}, {size:,} bytes):\n{text[:max_chars]}"
    except Exception as e:
        return f"[ERROR] file fetch failed: {e}"

# ========================================================= github pro =======

@mcp.tool()
def github_search_repos(query: str, count: int = 8) -> str:
    """Search GitHub repos by keyword — stars, language, description (find competitors/libs)."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://api.github.com/search/repositories",
                  params={"q": query, "sort": "stars", "order": "desc",
                          "per_page": count}, headers=_gh_headers())
    except Exception as e:
        return f"[ERROR] repo search failed: {e}"
    items = d.get("items", [])
    if not items:
        return f"[INFO] no repos for '{query}'"
    out = [f"GitHub repos for '{query}':"]
    for r in items:
        out.append(f"- {r['full_name']} | ★{r['stargazers_count']:,} | "
                   f"{r.get('language', '?')}\n"
                   f"  {(r.get('description') or '')[:160]}\n"
                   f"  {r['html_url']}")
    return "\n".join(out)


@mcp.tool()
def github_search_code(query: str, count: int = 8) -> str:
    """Search CODE inside GitHub repos (how does anyone implement X?). Needs GITHUB_TOKEN env."""
    err = _check_access()
    if err:
        return err
    if not os.environ.get("GITHUB_TOKEN"):
        return ("[ERROR] code search needs a GitHub token — create one free at "
                "github.com/settings/tokens (no scopes needed for public code), "
                "then set GITHUB_TOKEN and restart the server")
    try:
        d = _jget("https://api.github.com/search/code",
                  params={"q": query, "per_page": count}, headers=_gh_headers())
    except Exception as e:
        return f"[ERROR] code search failed: {e}"
    items = d.get("items", [])
    if not items:
        return f"[INFO] no code results for '{query}'"
    out = [f"GitHub code results for '{query}':"]
    for i in items:
        out.append(f"- {i['repository']['full_name']} / {i['path']}\n  {i['html_url']}")
    return "\n".join(out)


@mcp.tool()
def github_repo_stats(repo: str) -> str:
    """Full stats on any repo — stars, forks, language, license, last push (competitor snapshot)."""
    err = _check_access()
    if err:
        return err
    if err := _gh_repo_ok(repo):
        return err
    try:
        r = _jget(f"https://api.github.com/repos/{repo}", headers=_gh_headers())
    except Exception as e:
        return f"[ERROR] repo stats failed: {e}"
    lic = (r.get("license") or {}).get("spdx_id", "?")
    return (f"{r.get('full_name')}\n"
            f"- ★ {r.get('stargazers_count', 0):,} stars | "
            f"{r.get('forks_count', 0):,} forks | "
            f"{r.get('open_issues_count', 0)} open issues\n"
            f"- language: {r.get('language', '?')} | license: {lic}\n"
            f"- created: {(r.get('created_at') or '')[:10]} | "
            f"last push: {(r.get('pushed_at') or '')[:10]}\n"
            f"- {r.get('description') or ''}\n"
            f"- {r.get('html_url', '')}")


@mcp.tool()
def github_commit_history(repo: str, path: str = "", count: int = 10) -> str:
    """Recent commits on a repo (optionally for one file) — see what's actively changing."""
    err = _check_access()
    if err:
        return err
    if err := _gh_repo_ok(repo):
        return err
    try:
        params = {"per_page": count}
        if path:
            params["path"] = path
        d = _jget(f"https://api.github.com/repos/{repo}/commits",
                  params=params, headers=_gh_headers())
    except Exception as e:
        return f"[ERROR] commit history failed: {e}"
    if not isinstance(d, list) or not d:
        return f"[INFO] no commits found for {repo}"
    out = [f"Recent commits on {repo}{f' ({path})' if path else ''}:"]
    for c in d:
        msg = (c["commit"]["message"] or "").split("\n")[0][:100]
        out.append(f"- {c['sha'][:7]} | {(c['commit']['author'] or {}).get('date', '')[:10]} | "
                   f"{(c.get('author') or {}).get('login', '?')}\n  {msg}")
    return "\n".join(out)


@mcp.tool()
def github_pr_files(repo: str, pr_number: int) -> str:
    """Show every file changed in a pull request with diffs — review any PR anywhere."""
    err = _check_access()
    if err:
        return err
    if err := _gh_repo_ok(repo):
        return err
    try:
        d = _jget(f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files",
                  headers=_gh_headers())
    except Exception as e:
        return f"[ERROR] PR files fetch failed: {e}"
    if not isinstance(d, list):
        return f"[ERROR] {d.get('message', 'PR not found')}"
    if not d:
        return f"[INFO] no files in PR #{pr_number}"
    out = [f"Files in {repo} PR #{pr_number} ({len(d)} files):"]
    for f in d[:10]:
        patch = (f.get("patch") or "")[:1200]
        out.append(f"\n{f['status'].upper()} {f['filename']} "
                   f"(+{f.get('additions', 0)}/-{f.get('deletions', 0)})\n{patch}")
    if len(d) > 10:
        out.append(f"\n... and {len(d) - 10} more files")
    return "\n".join(out)


@mcp.tool()
def github_releases(repo: str, count: int = 5) -> str:
    """Release notes / changelogs of any repo — track what competitors ship."""
    err = _check_access()
    if err:
        return err
    if err := _gh_repo_ok(repo):
        return err
    try:
        d = _jget(f"https://api.github.com/repos/{repo}/releases",
                  params={"per_page": count}, headers=_gh_headers())
    except Exception as e:
        return f"[ERROR] releases fetch failed: {e}"
    if not isinstance(d, list) or not d:
        return f"[INFO] no releases on {repo}"
    out = [f"Releases on {repo}:"]
    for r in d:
        out.append(f"- {r.get('tag_name')} — {r.get('name') or ''} "
                   f"({(r.get('published_at') or '')[:10]})\n"
                   f"  {(r.get('body') or '')[:400].replace(chr(10), ' ')}")
    return "\n".join(out)


@mcp.tool()
def github_user_repos(username: str, count: int = 10) -> str:
    """List anyone's public repos, recently updated first (spy on builders/orgs)."""
    err = _check_access()
    if err:
        return err
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        return "[ERROR] invalid username"
    try:
        d = _jget(f"https://api.github.com/users/{username}/repos",
                  params={"sort": "updated", "per_page": count},
                  headers=_gh_headers())
    except Exception as e:
        return f"[ERROR] user repos fetch failed: {e}"
    if not isinstance(d, list) or not d:
        return f"[INFO] no public repos for {username}"
    out = [f"Recent repos by {username}:"]
    for r in d:
        out.append(f"- {r['name']} | ★{r['stargazers_count']:,} | "
                   f"{r.get('language', '?')} | pushed {(r.get('pushed_at') or '')[:10]}\n"
                   f"  {(r.get('description') or '')[:140]}")
    return "\n".join(out)


@mcp.tool()
def github_trending(days: int = 30, count: int = 10) -> str:
    """Hottest NEW repos on GitHub — most-starred repos created in the last N days."""
    err = _check_access()
    if err:
        return err
    since = (datetime.date.today()
             - datetime.timedelta(days=min(max(days, 1), 365))).isoformat()
    try:
        d = _jget("https://api.github.com/search/repositories",
                  params={"q": f"created:>{since}", "sort": "stars",
                          "order": "desc", "per_page": count},
                  headers=_gh_headers())
    except Exception as e:
        return f"[ERROR] trending fetch failed: {e}"
    items = d.get("items", [])
    out = [f"Trending repos (created since {since}):"]
    for r in items:
        out.append(f"- {r['full_name']} | ★{r['stargazers_count']:,} | "
                   f"{r.get('language', '?')}\n"
                   f"  {(r.get('description') or '')[:160]}")
    return "\n".join(out)

# ============================================================ youtube =======

@mcp.tool()
def youtube_search(query: str, count: int = 6) -> str:
    """Search YouTube videos (titles, channels, durations) — no API key needed."""
    err = _check_access()
    if err:
        return err
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "yt_dlp", f"ytsearch{count}:{query}",
             "--flat-playlist", "--no-playlist",
             "--print", "%(id)s\t%(title)s\t%(uploader)s\t%(duration_string)s",
             "--quiet", "--no-warnings"],
            capture_output=True, text=True, timeout=90)
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        if not lines:
            return f"[ERROR] no YouTube results for '{query}'"
        out = [f"YouTube results for '{query}':"]
        for l in lines[:count]:
            parts = l.split("\t")
            vid = parts[0] if len(parts) > 0 else "?"
            title = parts[1] if len(parts) > 1 else "?"
            chan = parts[2] if len(parts) > 2 else "?"
            dur = parts[3] if len(parts) > 3 and parts[3] != "NA" else "?"
            out.append(f"- {title} | {chan} | {dur}\n"
                       f"  https://www.youtube.com/watch?v={vid}")
        return "\n".join(out)
    except subprocess.TimeoutExpired:
        return "[ERROR] YouTube search timed out"
    except Exception as e:
        return f"[ERROR] YouTube search failed: {e}"


@mcp.tool()
def youtube_channel_videos(channel_url: str, count: int = 10) -> str:
    """Latest videos from any YouTube channel (pass the channel's /videos URL)."""
    err = _check_access()
    if err:
        return err
    if "youtube.com" not in channel_url and "youtu.be" not in channel_url:
        return "[ERROR] pass a youtube.com channel URL"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "yt_dlp", "--flat-playlist",
             "--playlist-end", str(count), "--no-playlist",
             "--print", "%(id)s\t%(title)s\t%(upload_date)s",
             "--quiet", "--no-warnings", channel_url],
            capture_output=True, text=True, timeout=120)
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        if not lines:
            return "[ERROR] no videos found — use the channel's /videos page URL"
        out = [f"Latest videos:"]
        for l in lines[:count]:
            parts = l.split("\t")
            vid = parts[0] if len(parts) > 0 else "?"
            title = parts[1] if len(parts) > 1 else "?"
            date = parts[2] if len(parts) > 2 else ""
            if len(date) == 8:
                date = f"{date[:4]}-{date[4:6]}-{date[6:]}"
            out.append(f"- {title} ({date})\n"
                       f"  https://www.youtube.com/watch?v={vid}")
        return "\n".join(out)
    except subprocess.TimeoutExpired:
        return "[ERROR] channel fetch timed out"
    except Exception as e:
        return f"[ERROR] channel fetch failed: {e}"

# ========================================================= store intel ======

@mcp.tool()
def appstore_top_charts(chart: str = "free", country: str = "US",
                        count: int = 10) -> str:
    """App Store top charts — free, paid, or grossing (chart = free/paid/grossing)."""
    err = _check_access()
    if err:
        return err
    charts = {"free": "topfreeapplications", "paid": "toppaidapplications",
              "grossing": "topgrossingapplications"}
    if chart not in charts:
        return "[ERROR] chart must be free, paid, or grossing"
    try:
        d = _jget(f"https://itunes.apple.com/{country}/rss/"
                  f"{charts[chart]}/limit={count}/json")
        entries = d.get("feed", {}).get("entry", [])
    except Exception as e:
        return f"[ERROR] charts fetch failed: {e}"
    if not entries:
        return "[INFO] no chart data"
    out = [f"App Store top-{chart} ({country}):"]
    for i, e in enumerate(entries, 1):
        name = e.get("im:name", {}).get("label", "?")
        artist = e.get("im:artist", {}).get("label", "?")
        price = e.get("im:price", {}).get("label", "?")
        out.append(f"{i}. {name} — {artist} ({price})")
    return "\n".join(out)


@mcp.tool()
def appstore_details(app_id: str, country: str = "US") -> str:
    """Full App Store metadata for any app — description, version, size, languages, seller URL."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://itunes.apple.com/lookup",
                  params={"id": app_id, "country": country})
    except Exception as e:
        return f"[ERROR] app lookup failed: {e}"
    res = d.get("results", [])
    if not res:
        return f"[INFO] no app found for id {app_id}"
    a = res[0]
    return (f"{a.get('trackName')} (id {a.get('trackId')})\n"
            f"- ★ {a.get('averageUserRating', '?')}/5 from "
            f"{a.get('userRatingCount', 0):,} ratings | {a.get('formattedPrice')}\n"
            f"- version {a.get('version')} | {a.get('fileSizeBytes', '?')} bytes | "
            f"requires {a.get('minimumOsVersion', '?')}+\n"
            f"- genre: {a.get('primaryGenreName')} | content rating: {a.get('contentAdvisoryRating')}\n"
            f"- seller: {a.get('sellerName')} ({a.get('sellerUrl', '')})\n"
            f"- updated: {(a.get('currentVersionReleaseDate') or '')[:10]}\n"
            f"- {(a.get('description') or '')[:600]}...\n"
            f"- {a.get('trackViewUrl', '')}")


@mcp.tool()
def podcast_search(query: str, count: int = 6) -> str:
    """Search podcasts — includes the raw RSS feed URL of each show (no key)."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://itunes.apple.com/search",
                  params={"term": query, "entity": "podcast", "limit": count})
    except Exception as e:
        return f"[ERROR] podcast search failed: {e}"
    hits = d.get("results", [])
    if not hits:
        return f"[INFO] no podcasts for '{query}'"
    out = [f"Podcasts for '{query}':"]
    for p in hits:
        out.append(f"- {p.get('collectionName')} by {p.get('artistName')} | "
                   f"{p.get('trackCount', '?')} episodes | "
                   f"{p.get('primaryGenreName', '?')}\n"
                   f"  RSS: {p.get('feedUrl', '?')}")
    return "\n".join(out)


@mcp.tool()
def movie_search(query: str, country: str = "US", count: int = 6) -> str:
    """Search movies/TV on the iTunes Store — ratings, genre, price, artwork."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://itunes.apple.com/search",
                  params={"term": query, "country": country,
                          "entity": "movie", "limit": count})
    except Exception as e:
        return f"[ERROR] movie search failed: {e}"
    hits = d.get("results", [])
    if not hits:
        return f"[INFO] no movies for '{query}'"
    out = [f"Movies for '{query}':"]
    for m in hits:
        out.append(f"- {m.get('trackName')} ({(m.get('releaseDate') or '')[:4]}) | "
                   f"{m.get('primaryGenreName', '?')} | "
                   f"{m.get('contentAdvisoryRating', '?')} | "
                   f"{m.get('trackPrice', '?')} {m.get('currency', '')}\n"
                   f"  {(m.get('longDescription') or '')[:200]}...")
    return "\n".join(out)


@mcp.tool()
def npm_package_info(name: str) -> str:
    """npm package intel — latest version, weekly downloads, deps, repo link."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget(f"https://registry.npmjs.org/{urllib.parse.quote(name)}/latest")
        try:
            dl = _jget(f"https://api.npmjs.org/downloads/point/last-week/"
                       + urllib.parse.quote(name)).get("downloads", "?")
        except Exception:
            dl = "?"
    except Exception as e:
        return f"[ERROR] npm lookup failed: {e}"
    deps = d.get("dependencies", {}) or {}
    repo = (d.get("repository") or {}).get("url", "")
    return (f"npm: {d.get('name')}@{d.get('version')}\n"
            f"- {d.get('description', '')[:200]}\n"
            f"- {dl:,} downloads last week\n"
            f"- {len(deps)} dependencies | license: {d.get('license', '?')}\n"
            f"- repo: {repo}")


@mcp.tool()
def pypi_package_info(name: str) -> str:
    """PyPI package intel — latest version, summary, links, release date."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    except Exception as e:
        return f"[ERROR] PyPI lookup failed: {e}"
    info = d.get("info", {})
    urls = d.get("urls", [])
    up = urls[0].get("upload_time", "")[:10] if urls else "?"
    return (f"PyPI: {info.get('name')} {info.get('version')}\n"
            f"- {info.get('summary', '')[:200]}\n"
            f"- home: {info.get('home_page', '') or info.get('project_url', '')}\n"
            f"- license: {info.get('license', '?')} | uploaded: {up}")

# ======================================================= data / utils =======

_WCODE = {0: "clear sky", 1: "mostly clear", 2: "partly cloudy", 3: "overcast",
          45: "fog", 48: "icy fog", 51: "light drizzle", 53: "drizzle",
          55: "heavy drizzle", 61: "light rain", 63: "rain", 65: "heavy rain",
          71: "light snow", 73: "snow", 75: "heavy snow", 80: "light showers",
          81: "showers", 82: "violent showers", 95: "thunderstorm",
          96: "storm + hail", 99: "storm + heavy hail"}


@mcp.tool()
def weather_now(place: str) -> str:
    """Live weather anywhere — temp, conditions, wind, humidity (Open-Meteo, no key)."""
    err = _check_access()
    if err:
        return err
    try:
        g = _jget("https://geocoding-api.open-meteo.com/v1/search",
                  params={"name": place, "count": 1})
        if not g.get("results"):
            return f"[INFO] couldn't find '{place}'"
        loc = g["results"][0]
        w = _jget("https://api.open-meteo.com/v1/forecast",
                  params={"latitude": loc["latitude"], "longitude": loc["longitude"],
                          "current": "temperature_2m,relative_humidity_2m,"
                                     "weather_code,wind_speed_10m",
                          "temperature_unit": "fahrenheit",
                          "wind_speed_unit": "mph"})
        cur = w["current"]
        desc = _WCODE.get(cur.get("weather_code"), "?")
        return (f"Weather in {loc['name']}, {loc.get('country', '')}:\n"
                f"- {cur['temperature_2m']}°F, {desc}\n"
                f"- humidity {cur['relative_humidity_2m']}% | "
                f"wind {cur['wind_speed_10m']} mph")
    except Exception as e:
        return f"[ERROR] weather fetch failed: {e}"


@mcp.tool()
def exchange_rates(base: str = "USD", target: str = "", amount: float = 1) -> str:
    """Live currency rates + conversion (free API, no key)."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget(f"https://open.er-api.com/v6/latest/{base.upper()}")
    except Exception as e:
        return f"[ERROR] rates fetch failed: {e}"
    rates = d.get("rates", {})
    if not rates:
        return "[ERROR] no rates returned"
    if target:
        t = target.upper()
        if t not in rates:
            return f"[ERROR] unknown currency '{target}'"
        val = amount * rates[t]
        return f"{amount:,.2f} {base.upper()} = {val:,.2f} {t} (live rate)"
    majors = ["EUR", "GBP", "JPY", "CAD", "AUD", "CHF", "CNY", "INR", "MXN", "BRL"]
    out = [f"1 {base.upper()} = "]
    for m in majors:
        if m in rates:
            out.append(f"- {m}: {rates[m]:,.4f}")
    return "\n".join(out)


@mcp.tool()
def translate_text(text: str, target: str = "es", source: str = "en") -> str:
    """Translate any text (MyMemory API, no key) — e.g. source='en', target='ja'/'fr'/'pt'."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://api.mymemory.translated.net/get",
                  params={"q": text[:900], "langpair": f"{source}|{target}"})
    except Exception as e:
        return f"[ERROR] translation failed: {e}"
    out = (d.get("responseData") or {}).get("translatedText", "")
    if not out:
        return "[ERROR] translation came back empty"
    return f"[{source} → {target}] {out}"


@mcp.tool()
def ip_geolocate(ip: str = "") -> str:
    """Geolocate any IP — city, region, country, ISP (ip-api, no key). Empty = this server's IP."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget(f"http://ip-api.com/json/{ip}" if ip else "http://ip-api.com/json/")
    except Exception as e:
        return f"[ERROR] geolocation failed: {e}"
    if d.get("status") != "success":
        return f"[ERROR] {d.get('message', 'lookup failed')}"
    return (f"{d.get('query')}\n- {d.get('city', '?')}, {d.get('regionName', '?')}, "
            f"{d.get('country', '?')} {d.get('zip', '')}\n"
            f"- ISP: {d.get('isp', '?')} | org: {d.get('org', '?')}\n"
            f"- coords: {d.get('lat')}, {d.get('lon')} | "
            f"timezone: {d.get('timezone', '?')}")


@mcp.tool()
def stock_quote(symbol: str) -> str:
    """Live stock quote — price, day range, volume (Stooq, no key)."""
    err = _check_access()
    if err:
        return err
    sym = symbol.strip().lower()
    if "." not in sym:
        sym += ".us"
    try:
        r = httpx.get(f"https://stooq.com/q/l/?s={sym}&f=sd2t2ohlcv&h&e=csv",
                      timeout=20, headers=_UA)
        r.raise_for_status()
        rows = list(csv.reader(io.StringIO(r.text)))
        if len(rows) < 2:
            return f"[ERROR] no quote for '{symbol}'"
        s, date, tm, o, h, l, c, v = rows[1]
        if c == "N/D":
            return f"[ERROR] no quote for '{symbol}' — check the ticker"
        return (f"{s.upper()} @ {c} (as of {date} {tm})\n"
                f"- open {o} | high {h} | low {l}\n- volume {v}")
    except Exception as e:
        return f"[ERROR] quote failed: {e}"


@mcp.tool()
def crypto_price(symbol: str = "BTC") -> str:
    """Live crypto price in USD (Coinbase public API, no key)."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget(f"https://api.coinbase.com/v2/prices/"
                  f"{symbol.strip().upper()}-USD/spot")
        amt = d["data"]["amount"]
        return f"{symbol.strip().upper()}/USD: ${float(amt):,.2f} (live)"
    except Exception as e:
        return f"[ERROR] crypto price failed: {e}"


@mcp.tool()
def osv_vulns(package: str, ecosystem: str = "PyPI") -> str:
    """Known vulnerabilities for any package (OSV.dev, no key) — audit deps before shipping."""
    err = _check_access()
    if err:
        return err
    try:
        r = httpx.post("https://api.osv.dev/v1/query",
                       json={"package": {"name": package, "ecosystem": ecosystem}},
                       timeout=25, headers=_UA)
        r.raise_for_status()
        vulns = r.json().get("vulns", [])
    except Exception as e:
        return f"[ERROR] vuln lookup failed: {e}"
    if not vulns:
        return f"[INFO] no known vulnerabilities for {package} ({ecosystem})"
    out = [f"Vulnerabilities for {package} ({ecosystem}): {len(vulns)} found"]
    for v in vulns[:8]:
        sev = ""
        for s in v.get("severity", []):
            if s.get("type") == "CVSS_V3":
                sev = f" CVSS {s.get('score')}"
        out.append(f"- {v.get('id')}{sev}: {(v.get('summary') or '')[:160]}")
    return "\n".join(out)


@mcp.tool()
def qr_code(text: str):
    """Generate a QR code image for any text/URL (ChatGPT gets the actual image)."""
    err = _check_access()
    if err:
        return err
    if _MCPImage is None:
        return "[ERROR] image output needs a newer mcp package"
    try:
        r = httpx.get("https://api.qrserver.com/v1/create-qr-code/",
                      params={"size": "400x400", "data": text[:1500]},
                      timeout=25, headers=_UA)
        r.raise_for_status()
        return _MCPImage(data=r.content, format="png")
    except Exception as e:
        return f"[ERROR] QR generation failed: {e}"


@mcp.tool()
def random_joke() -> str:
    """A random programming joke (because why not)."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://official-joke-api.appspot.com/jokes/programming/random")
        j = d[0]
        return f"{j['setup']}\n{j['punchline']}"
    except Exception as e:
        return f"[ERROR] joke failed (even the joke API is down): {e}"

# ============================================ search / knowledge (restored) =

@mcp.tool()
def stackoverflow_search(query: str, count: int = 6) -> str:
    """Search Stack Overflow — top-voted answers to dev questions (no key)."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://api.stackexchange.com/2.3/search/advanced",
                  params={"order": "desc", "sort": "votes", "q": query,
                          "site": "stackoverflow", "pagesize": count,
                          "filter": "default"})
    except Exception as e:
        return f"[ERROR] Stack Overflow search failed: {e}"
    items = d.get("items", [])
    if not items:
        return f"[INFO] no Stack Overflow results for '{query}'"
    out = [f"Stack Overflow results for '{query}':"]
    for i in items:
        out.append(f"- [{i.get('score', 0)}↑, {i.get('answer_count', 0)} answers] "
                   f"{i.get('title')}\n  {i.get('link')}")
    return "\n".join(out)


@mcp.tool()
def arxiv_search(query: str, count: int = 5) -> str:
    """Search arXiv research papers — abstracts, authors, PDF links."""
    err = _check_access()
    if err:
        return err
    try:
        import xml.etree.ElementTree as ET
        xml = _tget("https://export.arxiv.org/api/query?search_query=all:"
                    + urllib.parse.quote(query)
                    + f"&start=0&max_results={count}&sortBy=submittedDate",
                    timeout=30, max_chars=500000)
        root = ET.fromstring(xml)
        ns = "{http://www.w3.org/2005/Atom}"
        entries = root.findall(f"{ns}entry")
        if not entries:
            return f"[INFO] no arXiv papers for '{query}'"
        out = [f"arXiv results for '{query}':"]
        for e in entries:
            title = (e.findtext(f"{ns}title") or "").strip().replace("\n", " ")
            authors = ", ".join(
                a.findtext(f"{ns}name", "").strip()
                for a in e.findall(f"{ns}author")[:4])
            pub = (e.findtext(f"{ns}published") or "")[:10]
            link = e.findtext(f"{ns}id", "").strip()
            abstract = (e.findtext(f"{ns}summary") or "").strip().replace(
                "\n", " ")[:400]
            out.append(f"- {title}\n  {authors} | {pub}\n  {abstract}...\n  {link}")
        return "\n".join(out)
    except Exception as e:
        return f"[ERROR] arXiv search failed: {e}"


@mcp.tool()
def scholar_search(query: str, count: int = 5) -> str:
    """Search Semantic Scholar — papers with citation counts (what research matters)."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://api.semanticscholar.org/graph/v1/paper/search",
                  params={"query": query, "limit": count,
                          "fields": "title,abstract,year,citationCount,url,authors"})
    except Exception as e:
        return f"[ERROR] Semantic Scholar search failed: {e}"
    papers = d.get("data", [])
    if not papers:
        return f"[INFO] no papers for '{query}'"
    out = [f"Semantic Scholar results for '{query}':"]
    for p in papers:
        authors = ", ".join(a.get("name", "") for a in p.get("authors", [])[:3])
        out.append(f"- {p.get('title')} ({p.get('year', '?')}) | "
                   f"{p.get('citationCount', 0)} citations\n"
                   f"  {authors}\n"
                   f"  {(p.get('abstract') or '')[:350]}...\n"
                   f"  {p.get('url', '')}")
    return "\n".join(out)


@mcp.tool()
def wikipedia_summary(topic: str) -> str:
    """Get a clean Wikipedia summary of any topic."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://en.wikipedia.org/api/rest_v1/page/summary/"
                  + urllib.parse.quote(topic.replace(" ", "_")))
    except Exception as e:
        return f"[ERROR] Wikipedia lookup failed: {e}"
    if d.get("type") == "disambiguation":
        return f"[INFO] '{topic}' is ambiguous — try a more specific title"
    return (f"{d.get('title', topic)}\n{d.get('extract', 'no summary')[:1500]}\n"
            f"Read more: {(d.get('content_urls') or {}).get('desktop', {}).get('page', '')}")


@mcp.tool()
def news_search(query: str, count: int = 8) -> str:
    """Fresh news search via Google News RSS — what happened lately (no key)."""
    err = _check_access()
    if err:
        return err
    if _feedparser is None:
        return "[ERROR] feedparser not installed — pip install -r requirements.txt"
    try:
        rss = ("https://news.google.com/rss/search?q="
               + urllib.parse.quote(query) + "&hl=en-US&gl=US&ceid=US:en")
        f = _feedparser.parse(rss)
        if not f.entries:
            return f"[INFO] no news for '{query}'"
        out = [f"News for '{query}':"]
        for e in f.entries[:count]:
            src = e.get("source", {}).get("title", "")
            out.append(f"- {e.get('title', '')}\n"
                       f"  {src} | {e.get('published', '')}\n  {e.get('link', '')}")
        return "\n".join(out)
    except Exception as e:
        return f"[ERROR] news search failed: {e}"


@mcp.tool()
def openlibrary_search(query: str, count: int = 5) -> str:
    """Search books via Open Library — titles, authors, first published."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://openlibrary.org/search.json",
                  params={"q": query, "limit": count})
    except Exception as e:
        return f"[ERROR] book search failed: {e}"
    docs = d.get("docs", [])
    if not docs:
        return f"[INFO] no books for '{query}'"
    out = [f"Books for '{query}':"]
    for b in docs:
        authors = ", ".join(b.get("author_name", [])[:3])
        out.append(f"- {b.get('title')} — {authors} "
                   f"({b.get('first_publish_year', '?')})")
    return "\n".join(out)


@mcp.tool()
def urbandictionary_define(term: str) -> str:
    """Urban Dictionary definitions — what slang actually means right now."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget("https://api.urbandictionary.com/v0/define",
                  params={"term": term})
    except Exception as e:
        return f"[ERROR] UD lookup failed: {e}"
    defs = d.get("list", [])
    if not defs:
        return f"[INFO] no Urban Dictionary entry for '{term}'"
    top = defs[0]
    clean = lambda s: re.sub(r"[\[\]]", "", s or "")[:400]
    return (f"Urban Dictionary: {term} (👍{top.get('thumbs_up', 0)} "
            f"👎{top.get('thumbs_down', 0)})\n"
            f"{clean(top.get('definition'))}\n\n"
            f"Example: {clean(top.get('example'))}")


@mcp.tool()
def define_word(word: str) -> str:
    """Real dictionary definitions with examples (dictionaryapi.dev, no key)."""
    err = _check_access()
    if err:
        return err
    try:
        d = _jget(f"https://api.dictionaryapi.dev/api/v2/entries/en/"
                  + urllib.parse.quote(word.lower()))
    except Exception as e:
        return f"[ERROR] dictionary lookup failed: {e}"
    if isinstance(d, dict) and d.get("title"):
        return f"[INFO] no definition found for '{word}'"
    out = []
    for entry in d[:1]:
        for m in entry.get("meanings", [])[:3]:
            pos = m.get("partOfSpeech", "")
            for df in m.get("definitions", [])[:2]:
                ex = f" — e.g. \"{df['example']}\"" if df.get("example") else ""
                out.append(f"- ({pos}) {df.get('definition', '')}{ex}")
    return f"Definitions of {word}:\n" + "\n".join(out) if out else \
        f"[INFO] no definitions for '{word}'"
