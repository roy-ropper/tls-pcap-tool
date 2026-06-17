#!/usr/bin/env bash
# Decrypt local TLS traffic in Wireshark via SSLKEYLOGFILE.
# Covers Firefox, curl, and Python (requests/urllib3/urllib) on Debian/Ubuntu.
set -euo pipefail

# Resolve the real (non-root) user/home even when invoked with sudo.
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "$USER")}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# NOT a dot-directory: Firefox installed via snap is AppArmor-confined and its
# 'home' interface explicitly denies writes to hidden (dot) files/dirs, so a
# hidden keylog path silently fails to ever get written to.
KEYLOG_DIR="$REAL_HOME/tls-debug"
KEYLOG_FILE="$KEYLOG_DIR/sslkeylog.log"
BASHRC="$REAL_HOME/.bashrc"
WS_CONFIG_DIR="$REAL_HOME/.config/wireshark"
WS_PREFS="$WS_CONFIG_DIR/preferences"

run_as_user() {
    if [ "$(id -u)" -eq 0 ] && [ "$REAL_USER" != "root" ]; then
        sudo -u "$REAL_USER" -H "$@"
    else
        "$@"
    fi
}

echo "==> Setting up SSLKEYLOGFILE at $KEYLOG_FILE"
run_as_user mkdir -p "$KEYLOG_DIR"
run_as_user touch "$KEYLOG_FILE"
chmod 600 "$KEYLOG_FILE"
chown "$REAL_USER" "$KEYLOG_FILE" 2>/dev/null || true

echo "==> Ensuring SSLKEYLOGFILE is exported in $BASHRC"
if grep -qs "SSLKEYLOGFILE=" "$BASHRC" 2>/dev/null; then
    # A line already exists (possibly stale/wrong path from an earlier run, in
    # any formatting) - rewrite every such line in place so it always matches
    # what Wireshark is reading. A narrower anchor here previously let a
    # differently-formatted stale line silently survive uncorrected.
    run_as_user sed -i "s|.*SSLKEYLOGFILE=.*|export SSLKEYLOGFILE=\"$KEYLOG_FILE\"|" "$BASHRC"
else
    run_as_user bash -c "echo 'export SSLKEYLOGFILE=\"$KEYLOG_FILE\"' >> '$BASHRC'"
fi

# No Python shim needed: CPython's ssl module (3.8+) and urllib3 (used by
# requests) both already read SSLKEYLOGFILE natively on their own - confirmed
# by reading /usr/lib/python3*/ssl.py and urllib3/util/ssl_.py on this system.
# An earlier version of this script patched ssl.SSLContext.__init__ to force
# this, which broke EVERY Python TLS connection (CPython treats a class that
# defines __new__ but not __init__ as a special case; patching __init__
# defeats that and ssl.SSLContext() starts raising TypeError). Don't add it
# back without re-verifying both of those files on the target Python version.

echo "==> Configuring Wireshark TLS keylog preference"
run_as_user mkdir -p "$WS_CONFIG_DIR"
run_as_user touch "$WS_PREFS"
if grep -q "^tls.keylog_file:" "$WS_PREFS" 2>/dev/null; then
    run_as_user sed -i "s|^tls.keylog_file:.*|tls.keylog_file: $KEYLOG_FILE|" "$WS_PREFS"
else
    run_as_user bash -c "echo 'tls.keylog_file: $KEYLOG_FILE' >> '$WS_PREFS'"
fi

export SSLKEYLOGFILE="$KEYLOG_FILE"

if [ "$(id -u)" -eq 0 ]; then
    echo "==> Launching Wireshark as root (pick your interface and start the capture yourself)"
    # Run as root (not dropped to $REAL_USER) so dumpcap can list/capture on
    # interfaces without needing the user to be in the 'wireshark' group.
    # Still needs the real user's X auth to open a window from a root process.
    DISPLAY="${DISPLAY:-:0}" XAUTHORITY="${XAUTHORITY:-$REAL_HOME/.Xauthority}" \
        SSLKEYLOGFILE="$KEYLOG_FILE" \
        wireshark -o "tls.keylog_file:$KEYLOG_FILE" &
    disown
else
    echo "==> Skipping Wireshark launch (re-run with sudo to capture: sudo $0)"
fi

cat <<EOF

Setup complete. SSLKEYLOGFILE = $KEYLOG_FILE

When you're ready, open a NEW Firefox window/terminal yourself (it must be a
fresh process so it picks up SSLKEYLOGFILE) and:

  1. In the Wireshark window, choose your capture interface and start capturing.
  2. Start Firefox, then browse to any HTTPS site:
       firefox
  3. For curl/python (any terminal), first run:  source ~/.bashrc
     curl -s https://example.com -o /dev/null
     python3 -c "import requests; requests.get('https://example.com')"
  4. In Wireshark, filter on 'tls', then right-click a TLS Application Data
     packet -> Follow -> HTTP/HTTP2 Stream to see decrypted plaintext.
  5. Sanity check: watch the keylog grow with: tail -f $KEYLOG_FILE

Note: if Firefox was already running before this script set SSLKEYLOGFILE,
quit it fully and relaunch it — it only reads the variable at startup.
EOF
