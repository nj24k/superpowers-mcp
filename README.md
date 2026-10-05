# ⚡ SuperPowers MCP

Gives ChatGPT **superpowers with zero access to your computer**. ChatGPT itself
is the brain — Codex-level code understanding (any GitHub repo, any file), web
ability, and API access — but it can never touch your machine. No shell, no
files, no local control. Deliberately.

| Tool | What it does |
|---|---|
| `unlock` | Password gate — the model calls this first with the password you give it in chat |
| `web_search` | Search the web (no API key) |
| `web_fetch` | Read any public web page as text |
| `http_request` | Raw HTTP to any **public** API / webhook ("connect to anything") |
| `github_read_file` | Read any file from **any** public GitHub repo |
| `github_list_files` | Browse any public repo's folder structure |
| `github_compare` | Diff two refs (branch/tag/commit) in any public repo — code review superpower |
| `github_list_issues` | List issues/PRs on any public repo (bug reports = competitor gaps) |
| `youtube_transcript` | Full transcript of **any** YouTube video |
| `appstore_search` | Search the App Store (ratings, review counts, price, genre) |
| `appstore_reviews` | Read real App Store reviews — complaints = product research gold |
| `hn_search` | Search Hacker News stories |

Works with **ChatGPT** (Developer Mode custom connector), **Codex CLI**, Cursor, Claude, and any MCP client.

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
