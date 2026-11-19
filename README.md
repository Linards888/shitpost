# Starpbrīdis

Anonīms teksta forums Latvijas skolēniem. / An anonymous text board for students in Latvia.

- No accounts, names or tripcodes. Everyone is "Anonīms".
- **IP addresses are never stored.** Spam limits and bans use a one-way HMAC of the IP. Its key is held only in RAM
  and replaced every 7 days and on every restart. After that, old tags are wiped and can't be linked to anyone.
- No cookies for posters, no analytics, no external fonts or scripts, and **no JavaScript**. A strict CSP is set.
- No request logging. Deleted posts are purged from disk after 3 days.
- Text only, so no image uploads to moderate or leak metadata (EXIF/GPS).
- Boards, threads, replies, bumping, `>quote`, `>>123` post links, `sage`, pagination and old-thread pruning.
- Report button plus a moderator panel (`/mod`) to delete, ban (1 or 7 days), sticky and lock.

## Run

Requires Node.js 22.13+. There are no dependencies to install.

```bash
MOD_PASSWORD='choose-a-long-password' node server.js
```

Then open http://127.0.0.1:3000.

| Env var          | Default        | Meaning |
|------------------|----------------|---------|
| `PORT`           | `3000`         | Port to listen on |
| `HOST`           | `127.0.0.1`    | Bind address (`0.0.0.0` to expose directly) |
| `MOD_PASSWORD`   | *(empty)*      | Moderator password. Without it you can't moderate. |
| `TRUST_PROXY`    | off            | `1` when behind nginx/Caddy (uses the last `X-Forwarded-For` hop) |
| `SECURE_COOKIES` | off            | `1` when served over HTTPS (adds HSTS + Secure cookie) |
| `DATA_DIR`       | `./data`       | Where the SQLite file lives |

## Deploying anonymously-friendly

1. Put it behind HTTPS (Caddy is the easiest option). **Turn off access logs** in the reverse proxy, for example by
   leaving out the `log` directive in Caddy, or by setting `access_log off;` in nginx. Otherwise the proxy stores IPs
   even though the app doesn't.
2. Choose an EU host and check what it logs on its side.
3. Optionally also publish it as a Tor onion service for users who want maximum anonymity.

## Legal note (Latvia / EU)

Running a public forum makes you a hosting service under the EU Digital Services Act. You have to remove clearly
illegal content once you know about it, and you need to provide a way to report it. That's why the report button
and the mod panel exist. Keep a contact address on the site, and check `/mod` regularly.
