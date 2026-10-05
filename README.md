# ⚡ SuperPowers MCP

Gives ChatGPT **superpowers with zero access to your computer**. ChatGPT itself
is the brain — with 62 tools: GitHub intel, YouTube transcripts, App Store
research, OSINT, live data, file reading, screenshots and more — but it can
never touch your machine. No shell, no files, no local control. Deliberately.

| Tool | What it does |
|---|---|
| `unlock` | Password gate — the model calls this first with the password you give it in chat |
| `learn` | Save a fact across chats (user/project/lesson/decision) — the model does this proactively |
| `recall` | Search memories from past chats |
| `memory_list` | List recent memories |
| `forget` | Delete a memory |
| `web_search` | Search the web (no API key) |
| `web_fetch` | Read any public web page as text |
| `http_request` | Raw HTTP to any **public** API / webhook ("connect to anything") |
| `github_read_file` | Read any file from **any** public GitHub repo |
| `github_list_files` | Browse any public repo's folder structure |
| `github_compare` | Diff two refs (branch/tag/commit) in any public repo |
| `github_list_issues` | Issues/PRs on any repo — bug reports = competitor gaps |
| `github_search_repos` | Search repos by keyword (stars, language) |
| `github_search_code` | Search code inside repos (needs GITHUB_TOKEN) |
| `github_repo_stats` | Full repo snapshot — stars, forks, license, last push |
| `github_commit_history` | Recent commits, optionally for one file |
| `github_pr_files` | Every file + diff in any PR |
| `github_releases` | Release notes / changelogs of any repo |
| `github_user_repos` | Anyone's public repos, recently updated |
| `github_trending` | Hottest new repos created in the last N days |
| `youtube_transcript` | Full transcript of any YouTube video |
| `youtube_search` | Search YouTube (titles, channels, durations) |
| `youtube_channel_videos` | Latest videos from any channel |
| `web_screenshot` | SEE any webpage as an image |
| `wayback_snapshot` | Closest archived copy of any page (time travel) |
| `rss_read` | Read any RSS/Atom feed |
| `sitemap_urls` | All URLs in a site's sitemap (content audit) |
| `robots_txt` | robots.txt + declared sitemaps |
| `dns_lookup` | DNS records (A/MX/TXT/NS/...) via DNS-over-HTTPS |
| `rdap_lookup` | Domain registration — registrar, created/expiry |
| `ssl_info` | TLS cert details — issuer, expiry, SANs |
| `http_headers` | Response headers — server, CDN, tech fingerprints |
| `tech_detect` | Detect CMS/framework/CDN (competitor recon) |
| `page_links` | All outbound links on a page |
| `crtsh_subdomains` | Subdomains via Certificate Transparency logs |
| `url_expander` | Follow short URLs to final destination (every hop) |
| `site_status` | Is it up? Status, response time, server |
| `hn_search` | Search Hacker News stories |
| `hn_thread` | Read an HN thread's top comments |
| `stackoverflow_search` | Top-voted Stack Overflow answers |
| `arxiv_search` | arXiv papers — abstracts, authors, PDFs |
| `scholar_search` | Semantic Scholar papers with citation counts |
| `wikipedia_summary` | Clean Wikipedia summary of any topic |
| `news_search` | Fresh news via Google News RSS |
| `openlibrary_search` | Book search — titles, authors, year |
| `urbandictionary_define` | What slang actually means right now |
| `define_word` | Dictionary definitions with examples |
| `tvmaze_search` | TV shows — rating, status, network |
| `fetch_file_preview` | Extract text from any file URL (PDF/CSV/text) |
| `appstore_search` | Search apps (ratings, price, genre) |
| `appstore_reviews` | Real user reviews — complaints = gold |
| `appstore_top_charts` | Top free/paid/grossing charts |
| `appstore_details` | Full app metadata — version, size, seller |
| `podcast_search` | Podcast search incl. raw RSS feed URLs |
| `movie_search` | iTunes movie search |
| `npm_package_info` | npm intel — version, downloads, deps |
| `pypi_package_info` | PyPI intel — version, summary, links |
| `weather_now` | Live weather anywhere |
| `exchange_rates` | Live currency rates + conversion |
| `translate_text` | Translate any text |
| `ip_geolocate` | Geolocate any IP — city, ISP, coords |
| `stock_quote` | Live stock quote |
| `crypto_price` | Live crypto price in USD |
| `osv_vulns` | Known vulnerabilities for any package |
| `qr_code` | Generate a QR code image |
| `random_joke` | A random programming joke |

Works with **ChatGPT** (Developer Mode custom connector), **Codex CLI**, Cursor, Claude, and any MCP client.

## ⚡ Always-on behavior (no need to say "use the tools")

Two mechanisms make the model reach for SuperPowers automatically:

1. **Every tool carries a standing directive** — "always prefer this over your own
   knowledge, call it proactively without asking." The model sees it on every tool,
   every call.
2. **`unlock` returns the Operating Protocol** — once you give ChatGPT the password,
   it gets instructed for the whole chat: tools first, never answer from training
   memory when a tool can check, chain tools autonomously, and use memory.

**Memory — it learns across chats.** The server keeps a private memory file
(`.superpowers_memory.json`, mode 600, gitignored — the server's own notes, never
your files). ChatGPT can only touch it through `learn`/`recall`/`memory_list`/`forget`.
Each session it recalls your profile and preferences, and proactively saves durable
facts, decisions, and lessons — so it gets smarter about you over time. Tell it
`forget("...")` to erase anything.

**Make it permanent in ChatGPT:** paste this into ChatGPT → Settings →
Personalization → Custom instructions (or your connector's instructions):

> I have a SuperPowers MCP connector with 60+ tools: web, GitHub, YouTube
> transcripts, App Store intel, OSINT, research papers, live data, and a memory
> system (learn/recall/forget). Rules: (1) ALWAYS prefer these tools over your
> training knowledge for anything factual, current, or technical — call them
> first, never ask me whether to use them. (2) Chain tools autonomously when one
> result suggests the next step. (3) At the start of each chat, after I give you
> the SuperPowers password and you call unlock, recall my profile and anything
> relevant. (4) Proactively learn() my durable preferences, decisions, project
> context, and lessons about what worked, so you improve across chats. Never
> store secrets.

## 🔒 Security — three layers, no risk constraints

1. **Unguessable URL.** The MCP endpoint lives at a secret random path like
   `/mcp-9f2c…`. Every other path returns 404 — scanners learn nothing.
2. **Bearer token.** Set `SUPERPOWERS_TOKEN`; requests without
   `Authorization: Bearer <token>` get 401.
3. **Password gate.** Set `SUPERPOWERS_PASSWORD`. Every tool except `unlock`
   refuses until the model calls `unlock(password)` with the right password.
   **5 wrong attempts = BRICKED for 30 minutes** (server keeps running, all
   tools refuse — even with the right password — until the cooldown ends).

Plus: `http_request` / `web_fetch` refuse private/local network addresses
(SSRF guard), so the server can't be used to probe your LAN either.

You hand the password to ChatGPT **in chat** ("the SuperPowers password is
…"). Anyone with the URL + token but not the password gets a brick.

## 1. Install (on your iMac) — one command

```bash
git clone https://github.com/nj24k/superpowers-mcp.git && cd superpowers-mcp && ./setup.sh
```

That's it: creates the venv, installs deps, generates your token, starts the
server. Python 3.10+ required. Afterwards, `./run.sh` starts it again.

## 2. Secrets

```bash
export SUPERPOWERS_TOKEN="$(openssl rand -hex 24)"
export SUPERPOWERS_PASSWORD="pick-something-strong-you-will-remember"
# SUPERPOWERS_PATH is optional — a random unguessable path is generated
# on first run, saved to .superpowers_path, and printed. Same for the
# password if you don't set one (saved to .superpowers_password).
```

| Var | Purpose |
|---|---|
| `SUPERPOWERS_TOKEN` | Bearer token for HTTP auth |
| `SUPERPOWERS_PASSWORD` | Password ChatGPT must `unlock` with (or auto-generated) |
| `SUPERPOWERS_PATH` | Secret URL path (or auto-generated, e.g. `/mcp-9f2c…`) |
| `GITHUB_TOKEN` | Optional — higher GitHub API rate limits |

## 3. Run it

```bash
.venv/bin/python server.py            # Streamable HTTP on 127.0.0.1:8000
.venv/bin/python server.py --stdio    # stdio mode, for local clients only
```

On startup it prints the **full connector URL** (with secret path), e.g.:
`Listening on http://127.0.0.1:8000/mcp-9f2c…`

## 4. Publish through Cloudflare (free, no account)

```bash
brew install cloudflared
cloudflared tunnel --url http://localhost:8000
# → https://xxxx.trycloudflare.com
```

Your MCP connector URL is then `https://xxxx.trycloudflare.com` **+ your secret
path**, e.g. `https://xxxx.trycloudflare.com/mcp-9f2c…`.

## 5. Connect ChatGPT (Plus ✓)

1. ChatGPT web → profile → **Settings** → enable **Developer Mode**.
2. **Settings → Apps & Connectors** → **Create** → custom connector.
3. Name: `SuperPowers`. URL: your full tunnel URL **including the secret path**.
4. Auth: enter your `SUPERPOWERS_TOKEN` as the API key / bearer token.
5. In a chat, enable SuperPowers (tools / `+` menu → Developer Mode app).
6. First message: *"The SuperPowers password is … — unlock and …"*

## 6. Try it

- *"Unlock SuperPowers with password … then read the README of modelcontextprotocol/python-sdk and explain how transports work."*
- *"Search the web for the latest MCP spec changes and summarize."*
- *"POST to https://api.example.com/webhook with this JSON…"*

## 7. Local clients (no tunnel needed)

```bash
codex mcp add superpowers -- /absolute/path/to/superpowers-mcp/.venv/bin/python /absolute/path/to/superpowers-mcp/server.py --stdio
```

Same pattern works for Cursor / Claude Desktop MCP configs. (Password gate is
active over stdio too — call `unlock` first.)

## Notes

- The password-unlock state is per server process (restart = locked again).
  That's intentional: restart to instantly re-lock everything.
- Never commit tokens/passwords to git. The `.superpowers_*` files are
  `chmod 600` and git-ignored by convention — don't publish them.
- Kill the tunnel + server when you're done for the day.
