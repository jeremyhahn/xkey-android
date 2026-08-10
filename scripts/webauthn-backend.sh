#!/usr/bin/env bash
#
# Copyright (c) 2026 Jeremy Hahn
# Copyright (c) 2026 Automate The Things, LLC
#
# Brings up the go-xkms WebAuthn relying party as a backend for xKey Android
# E2E testing, and wires it to a connected device or emulator.
#
# Why `adb reverse` and plain HTTP: WebAuthn only runs in a secure context.
# Reversing the port makes the RP reachable at http://localhost:PORT *on the
# device*, and localhost is a secure context — so no TLS certificate has to be
# trusted on the device just to run a ceremony.
#
# Usage:
#   scripts/webauthn-backend.sh start     # build + run the RP, set up adb reverse
#   scripts/webauthn-backend.sh stop      # stop the RP and remove the tunnel
#   scripts/webauthn-backend.sh status    # report RP and tunnel state
#   scripts/webauthn-backend.sh provider  # register xKey as a credential provider
set -euo pipefail

GO_XKMS="${GO_XKMS:-$HOME/sources/go-xkms}"
PORT="${WEBAUTHN_PORT:-18443}"
ADB="${ADB:-$HOME/Android/Sdk/platform-tools/adb}"
APP_ID="${APP_ID:-com.automatethethings.xkey.debug}"
CREDENTIAL_SERVICE="$APP_ID/com.automatethethings.xkey.credential.XKeyCredentialService"
GMS_SERVICE="com.google.android.gms/com.google.android.gms.auth.api.credentials.credman.service.PasswordAndPasskeyService"

RUNTIME_DIR="${TMPDIR:-/tmp}/xkey-webauthn-backend"
BIN="$RUNTIME_DIR/rpserver"
LOG="$RUNTIME_DIR/rp.log"
PIDFILE="$RUNTIME_DIR/rp.pid"

start() {
    mkdir -p "$RUNTIME_DIR"

    echo "[webauthn-backend] building the RP from $GO_XKMS ..."
    ( cd "$GO_XKMS" && go build -o "$BIN" ./examples/webauthn/server )

    if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "[webauthn-backend] already running (pid $(cat "$PIDFILE"))"
    else
        TLS_ENABLED=false PORT="$PORT" WEBAUTHN_RP_ID=localhost \
            nohup "$BIN" > "$LOG" 2>&1 < /dev/null &
        echo $! > "$PIDFILE"
        echo "[webauthn-backend] started (pid $(cat "$PIDFILE")), log: $LOG"
    fi

    for _ in $(seq 1 30); do
        if curl -sf --max-time 2 "http://localhost:$PORT/health" >/dev/null; then break; fi
        sleep 1
    done
    curl -sf --max-time 2 "http://localhost:$PORT/health" >/dev/null \
        || { echo "[webauthn-backend] RP failed to become healthy; see $LOG" >&2; exit 1; }

    "$ADB" reverse "tcp:$PORT" "tcp:$PORT"
    echo "[webauthn-backend] ready:"
    echo "  host:   http://localhost:$PORT"
    echo "  device: http://localhost:$PORT  (via adb reverse)"
}

stop() {
    if [[ -f "$PIDFILE" ]]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE"
    fi
    "$ADB" reverse --remove "tcp:$PORT" 2>/dev/null || true
    echo "[webauthn-backend] stopped"
}

status() {
    if curl -sf --max-time 2 "http://localhost:$PORT/health" >/dev/null; then
        echo "RP:     healthy on http://localhost:$PORT"
    else
        echo "RP:     not running"
    fi
    echo "tunnel: $("$ADB" reverse --list 2>/dev/null | grep "tcp:$PORT" || echo 'not established')"
    echo "provider: $("$ADB" shell settings get secure credential_service 2>/dev/null | tr -d '\r')"
}

# Registers xKey alongside Google Password Manager as a credential provider.
# This is the same list Settings > Passwords & accounts writes.
provider() {
    "$ADB" shell settings put secure credential_service "$GMS_SERVICE:$CREDENTIAL_SERVICE"
    "$ADB" shell settings put secure credential_service_primary "$CREDENTIAL_SERVICE" || true
    echo "[webauthn-backend] credential providers: $("$ADB" shell settings get secure credential_service | tr -d '\r')"
}

case "${1:-start}" in
    start)    start ;;
    stop)     stop ;;
    status)   status ;;
    provider) provider ;;
    *)        echo "usage: $0 {start|stop|status|provider}" >&2; exit 2 ;;
esac
