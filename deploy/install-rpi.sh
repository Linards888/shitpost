#!/usr/bin/env bash
# Installs (or updates) Shitpost as a Tor-only .onion site on Raspberry Pi OS / Debian.
# Run from inside the cloned repo:   sudo ./deploy/install-rpi.sh
# Re-run it after `git pull` to update — posts, settings and the .onion address are kept.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Palaid ar sudo:  sudo ./deploy/install-rpi.sh"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/shitpost
ENVF=/etc/shitpost.env
HS=/var/lib/tor/shitpost

case "$(uname -m)" in
  aarch64|x86_64) ;;
  armv7l) echo "BRĪDINĀJUMS: 32-bit sistēma. Ieteicams Raspberry Pi OS Lite (64-bit)." ;;
  *) echo "Neatbalstīts procesors: $(uname -m). Vajag Raspberry Pi 3/4/5 vai Zero 2 W ar 64-bit OS."; exit 1 ;;
esac

echo "==> Atjauno pakotnes"
apt-get update -q
apt-get install -y -q ca-certificates curl tor

node_ok() {
  command -v node >/dev/null 2>&1 || return 1
  node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a>22||(a===22&&b>=13)?0:1)'
}
if ! node_ok; then
  echo "==> Instalē Node.js 22"
  curl -fsSL https://deb.nodesource.com/setup_22.x -o /tmp/nodesource_setup.sh
  bash /tmp/nodesource_setup.sh
  apt-get install -y -q nodejs
  rm -f /tmp/nodesource_setup.sh
fi
node_ok || { echo "Node.js 22.13+ neizdevās uzinstalēt."; exit 1; }
echo "    node $(node --version)"

echo "==> Kopē Shitpost uz $APP"
id shitpost >/dev/null 2>&1 || useradd --system --home-dir "$APP" --shell /usr/sbin/nologin shitpost
install -d -m 755 "$APP" "$APP/public"
install -m 644 "$SRC/server.js" "$SRC/package.json" "$APP/"
install -m 644 "$SRC/public/"* "$APP/public/"
install -d -m 700 -o shitpost -g shitpost "$APP/data"

echo "==> Iestata Tor .onion servisu"
if ! grep -q "HiddenServiceDir $HS/" /etc/tor/torrc; then
  printf '\n' >> /etc/tor/torrc
  cat "$SRC/deploy/torrc-shitpost.conf" >> /etc/tor/torrc
fi
if ! tor --verify-config -f /etc/tor/torrc >/dev/null 2>&1; then
  echo "Tor konfigurācijā ir kļūda:"; tor --verify-config -f /etc/tor/torrc | tail -5; exit 1
fi
systemctl enable tor >/dev/null 2>&1
systemctl restart tor
for _ in $(seq 1 60); do [ -s "$HS/hostname" ] && break; sleep 1; done
[ -s "$HS/hostname" ] || { echo "Tor neizveidoja .onion adresi. Skaties: journalctl -u tor -n 50"; exit 1; }
ONION="$(cat "$HS/hostname")"

NEWPASS=""
if [ ! -f "$ENVF" ]; then
  NEWPASS="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
  cat > "$ENVF" <<CONF
# Shitpost settings. After editing: sudo systemctl restart shitpost
HOST=127.0.0.1
PORT=3000
ONION_PORT=3080
ONION_ADDRESS=$ONION
MOD_PASSWORD=$NEWPASS
DATA_DIR=$APP/data
NODE_NO_WARNINGS=1
CONF
else
  sed -i "s|^ONION_ADDRESS=.*|ONION_ADDRESS=$ONION|" "$ENVF"
fi
chmod 600 "$ENVF"

echo "==> Startē Shitpost"
install -m 644 "$SRC/deploy/shitpost.service" /etc/systemd/system/shitpost.service
systemctl daemon-reload
systemctl enable shitpost >/dev/null 2>&1
systemctl restart shitpost
sleep 3
CODE="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3080/ || true)"
if [ "$CODE" != "200" ]; then
  echo "Shitpost nestartējās (HTTP $CODE). Skaties: journalctl -u shitpost -n 50"; exit 1
fi

echo
echo "=============================================================="
echo " Gatavs! Shitpost darbojas."
echo " Tor adrese:   http://$ONION"
echo " Moderācija:   http://$ONION/mod"
if [ -n "$NEWPASS" ]; then
  echo " Mod parole:   $NEWPASS"
  echo "               (pieraksti to! Tā glabājas arī $ENVF)"
else
  echo " Mod parole:   nemainīta — skaties sudo cat $ENVF"
fi
echo
echo " SVARĪGI: dublē mapi $HS (tā ir tavas .onion adreses atslēga)."
echo "=============================================================="
