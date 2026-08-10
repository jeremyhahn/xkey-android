#!/usr/bin/env bash
#
# dev-interactive.sh — one-command interactive setup for driving the xKey app
# against a live go-xkms backend on an emulator.
#
# It will:
#   1. boot the AVD (if no device is attached)
#   2. build + install the debug APK
#   3. grant runtime perms, battery-whitelist the app, enable emulator Bluetooth
#   4. enable the "TCP Pairing (ADB)" setting (writes the DataStore preference)
#   5. launch MainActivity and auto-start the BLE service (taps the BLE toggle),
#      then verify the phone's TCP HSM server is listening on :8444
#   6. adb-forward localhost:8444 -> the phone
#   7. build the go-xkms e2eprobe and (default) run the backend E2E once
#
# After it finishes, the phone's pairing server is reachable at localhost:8444,
# so you can drive it interactively:
#     cd <go-xkms>/xkey && go run ./cmd/e2eprobe          # scripted full-flow probe
#     <go-xkms>/xkey/xkey device pair                     # real desktop pairing
#
# Usage: scripts/dev-interactive.sh [--no-emulator] [--no-e2e] [--avd NAME]
#
# Copyright (c) 2025 Jeremy Hahn / Automate The Things, LLC. AGPL-3.0 or commercial.

set -euo pipefail

SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android/Sdk}}"
ADB="$SDK/platform-tools/adb"
EMULATOR_BIN="$SDK/emulator/emulator"
AVD="${AVD:-Medium_Phone_API_36.1}"
PKG="com.automatethethings.xkey.debug"
ACTIVITY="$PKG/com.automatethethings.xkey.ui.MainActivity"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOXKMS="${GOXKMS:-$HOME/sources/go-xkms/xkey}"
PORT=8444
PORT_HEX="20FC"   # 8444 in hex, as it appears in /proc/net/tcp
BOOT_EMULATOR=true
RUN_E2E=true

while [ $# -gt 0 ]; do
  case "$1" in
    --no-emulator) BOOT_EMULATOR=false ;;
    --no-e2e)      RUN_E2E=false ;;
    --avd)         AVD="$2"; shift ;;
    -h|--help)     sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# 1) Emulator -------------------------------------------------------------
if ! "$ADB" devices | awk 'NR>1 && $2=="device"{found=1} END{exit !found}'; then
  if $BOOT_EMULATOR; then
    say "Booting emulator $AVD (headless)"
    HOME="$HOME" "$EMULATOR_BIN" -avd "$AVD" -no-window -no-audio -no-boot-anim \
      -no-snapshot -gpu swiftshader_indirect >/tmp/xkey-emulator.log 2>&1 &
    "$ADB" wait-for-device
    say "Waiting for boot to complete"
    until [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do sleep 2; done
  else
    echo "No device attached and --no-emulator given." >&2; exit 1
  fi
fi
say "Device: $("$ADB" devices | awk 'NR==2{print $1}')"

# 2) Build + install ------------------------------------------------------
say "Building + installing debug APK"
( cd "$APP_DIR" && ./gradlew --console=plain installDebug )

# 3) Permissions / battery / bluetooth -----------------------------------
say "Granting permissions + battery whitelist + enabling Bluetooth"
for p in BLUETOOTH_CONNECT BLUETOOTH_ADVERTISE BLUETOOTH_SCAN POST_NOTIFICATIONS; do
  "$ADB" shell pm grant "$PKG" "android.permission.$p" >/dev/null 2>&1 || true
done
"$ADB" shell dumpsys deviceidle whitelist "+$PKG" >/dev/null 2>&1 || true
"$ADB" shell cmd bluetooth_manager enable >/dev/null 2>&1 || true

# 4) Enable the TCP Pairing setting (DataStore preferences proto) ---------
say "Enabling 'TCP Pairing (ADB)' setting"
"$ADB" shell am force-stop "$PKG" || true
"$ADB" shell run-as "$PKG" mkdir -p files/datastore || true
# PreferencesProto: { "tcp_hsm_enabled": true }
B64="$(printf '\012\025\012\017tcp_hsm_enabled\022\002\010\001' | base64 -w0)"
"$ADB" shell "run-as $PKG sh -c 'echo $B64 | base64 -d > files/datastore/usb_hsm_settings.preferences_pb'"

# 5) Launch + auto-start the BLE service (which starts the TCP server) -----
say "Launching app + starting the BLE/TCP service"
"$ADB" shell am start -n "$ACTIVITY" >/dev/null 2>&1
sleep 4
read -r W H < <("$ADB" shell wm size | sed -E 's/.*: *([0-9]+)x([0-9]+).*/\1 \2/')
TX=$(( W * 89 / 100 )); TY=$(( H * 105 / 1000 ))   # BLE toggle, top-right of the hero
listening() { "$ADB" shell run-as "$PKG" cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -qi ":$PORT_HEX "; }
for attempt in 1 2 3; do
  if listening; then break; fi
  echo "   tapping BLE toggle at ${TX},${TY} (attempt $attempt)"
  "$ADB" shell input tap "$TX" "$TY"
  sleep 4
done
if listening; then
  say "Phone TCP HSM server is listening on :$PORT ✓"
else
  echo "   WARN: :$PORT not listening. Open the app and toggle BLE on manually, then re-run with --no-emulator." >&2
fi

# 6) Forward the port -----------------------------------------------------
"$ADB" forward "tcp:$PORT" "tcp:$PORT" >/dev/null
say "Forwarded localhost:$PORT -> phone:$PORT"

# 7) Backend E2E ----------------------------------------------------------
say "Building go-xkms e2eprobe"
( cd "$GOXKMS" && go build -o /tmp/xkey-e2eprobe ./cmd/e2eprobe )
if $RUN_E2E; then
  say "Running backend E2E (pair -> getInfo -> generateKey -> encrypt/decrypt -> sync)"
  /tmp/xkey-e2eprobe "localhost:$PORT" || echo "   (E2E reported failures — see above)"
fi

cat <<EOF

────────────────────────────────────────────────────────────────────────
Interactive session ready. The phone's pairing server is at localhost:$PORT.
  • Scripted full-flow probe : cd $GOXKMS && go run ./cmd/e2eprobe
  • Real desktop pairing     : $GOXKMS/xkey device pair
  • App logs                 : $ADB logcat | grep -i xkey
  • Stop the emulator        : $ADB emu kill
────────────────────────────────────────────────────────────────────────
EOF
