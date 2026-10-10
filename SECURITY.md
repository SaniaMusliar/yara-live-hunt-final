# Security

**Official address:** https://yara-live-hunt-file.vercel.app. Treat any other address as unofficial.

**Design:** this site is static (HTML plus a few text files). It has no backend, no database, no cookies, no analytics, no environment variables and no API keys. The optional terminal bridge runs on the user's own machine and is read-only toward the site.

**Never put secrets in this repo.** Nothing here needs any.

**Terminal bridge limits** (see `agent/yara-hunt-agent.py`):
- Listens on 127.0.0.1 only. Rejects any other Host header (blocks DNS rebinding).
- Every request needs a random one-time token AND the exact site origin.
- Reads only `~/yara-lab`. Ignores symlinks. Runs one fixed command: `yara -r -s -m rules/rules.yar fileserver`.
- Never runs anything the website sends. The user pastes commands into their own terminal.
- The shell hook only records commands typed inside `~/yara-lab`.
- Undo everything with `yh_off`.

**Integrity:** `SHA256SUMS` lists the files the connector downloads. Verify with `sha256sum -c SHA256SUMS`.

**Report a vulnerability:** open a private GitHub security advisory (Repo → Security → Report a vulnerability). Please do not post details publicly first.

Educational use only. Test only on systems you own or are authorised to test.
