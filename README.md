# Shitpost

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

## 🍓 Raspberry Pi (recommended: Tor-only)

The installer sets Shitpost up as an `.onion`-only site. That means **no router port forwarding, no domain and no
HTTPS certificate**, and your home IP address stays hidden. It starts automatically when the Pi boots.

You need a Raspberry Pi 3, 4, 5 or Zero 2 W running **Raspberry Pi OS Lite (64-bit)**.

```bash
sudo apt update && sudo apt install -y git
git clone -b dev/bold-curie-3q9mbl https://github.com/linards888/shitpost.git
cd shitpost
sudo ./deploy/install-rpi.sh
```

At the end it prints your `.onion` address and a generated moderator password.

- **Update:** `git pull`, then `sudo ./deploy/install-rpi.sh` again. Posts, settings and the address are kept.
- **Settings:** `sudo nano /etc/shitpost.env`, then `sudo systemctl restart shitpost`
- **Status / errors:** `systemctl status shitpost`, or `journalctl -u shitpost -n 50` (no visitor data is ever logged)
- **Back up** `/var/lib/tor/shitpost/` (address key) and `/opt/shitpost/data/` (posts).

## 🧅 Tor onion service (maximum anonymity)

With Tor, visitors use Tor Browser and an `.onion` address. **The server never sees their IP address**, not even
for a moment, and visitors can't see where the server is located either.

How Shitpost handles Tor visitors:

- Tor traffic arrives on a **separate local port** (`ONION_PORT`), so the app knows a visitor came through Tor.
- All Tor visitors look identical, so **they can't be banned individually**. To keep spam under control:
  - every post needs a **CAPTCHA**, which is self-made with no outside service and no JavaScript;
  - **posting limits are shared** by all Tor users together (default: 12 replies per minute and 5 new threads per 10 minutes);
  - moderators get a **"pause Tor posting"** switch in `/mod`, so the board stays readable but nobody can post through Tor.
- Moderators can still **delete** any post. The ban buttons are hidden on Tor posts.
- The normal site sends an `Onion-Location` header, so Tor Browser shows a ".onion available" button.

### Setup on Fedora

1. Install and enable Tor:

```bash
sudo dnf install tor
```

2. Add the lines from [`deploy/torrc-shitpost.conf`](deploy/torrc-shitpost.conf) to the end of `/etc/tor/torrc`:

```bash
sudo tee -a /etc/tor/torrc < deploy/torrc-shitpost.conf
```

3. Start Tor and make it start automatically on boot:

```bash
sudo systemctl enable --now tor
```

4. Read your new `.onion` address:

```bash
sudo cat /var/lib/tor/shitpost/hostname
```

5. Start Shitpost with the onion listener turned on. Replace the address with yours:

```bash
ONION_PORT=3080 ONION_ADDRESS=youraddress.onion MOD_PASSWORD=mypassword node server.js
```

6. Open the `.onion` address in Tor Browser.

**Back up `/var/lib/tor/shitpost/`.** It contains the private key for your `.onion` address. If you lose it, you lose
the address for good. If someone else gets it, they can pretend to be your site.

If it doesn't work, check the Tor log:

```bash
sudo journalctl -u tor -n 50
```

| Env var                 | Default | Meaning |
|-------------------------|---------|---------|
| `ONION_PORT`            | *(off)* | Local port for Tor traffic (always binds to 127.0.0.1) |
| `ONION_ADDRESS`         | *(none)*| Your `.onion` address, shown in the footer and the Onion-Location header |
| `TOR_REPLIES_PER_MIN`   | `12`    | Replies per minute for **all** Tor users combined |
| `TOR_THREADS_PER_10MIN` | `5`     | New threads per 10 minutes for **all** Tor users combined |
| `CAPTCHA_ALL`           | off     | `1` = require the CAPTCHA on the normal site too |

**Onion-only mode** (the most anonymous option, where the server is invisible too): run only Tor, don't open any
public port, and keep `HOST=127.0.0.1` (the default). Then the site can only be reached through `.onion`.

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
