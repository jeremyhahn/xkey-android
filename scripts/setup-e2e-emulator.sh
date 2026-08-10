#!/bin/bash
# setup-e2e-emulator.sh — Prepare an Android emulator for xKey E2E tests
#
# Prerequisites:
#   - API 34+ emulator running with Google APIs system image
#   - Chrome installed on the emulator
#   - ADB connected to the emulator
#
# Usage:
#   ./scripts/setup-e2e-emulator.sh [--build] [--run]
#
#   --build  Build debug + test APKs before installing
#   --run    Run the E2E tests after setup

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BUILD=false
RUN=false

for arg in "$@"; do
    case "$arg" in
        --build) BUILD=true ;;
        --run)   RUN=true ;;
        *)       echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

echo "=== xKey E2E Emulator Setup ==="

# Check ADB connectivity
if ! adb devices | grep -q "device$"; then
    echo "ERROR: No Android device/emulator connected via ADB"
    exit 1
fi

# 1. Disable animations for test stability
echo "[1/5] Disabling animations..."
adb shell settings put global window_animation_scale 0
adb shell settings put global transition_animation_scale 0
adb shell settings put global animator_duration_scale 0

# 2. Build APKs if requested
if [ "$BUILD" = true ]; then
    echo "[2/5] Building debug + test APKs..."
    cd "$PROJECT_DIR"
    ./gradlew assembleDebug assembleDebugAndroidTest
else
    echo "[2/5] Skipping build (use --build to build APKs)"
fi

# 3. Install xKey debug APK
echo "[3/5] Installing xKey debug APK..."
APK_PATH="$PROJECT_DIR/app/build/outputs/apk/debug/app-debug.apk"
if [ -f "$APK_PATH" ]; then
    adb install -r "$APK_PATH"
else
    echo "WARNING: $APK_PATH not found. Run with --build or build manually."
fi

# 4. Install test APK
echo "[4/5] Installing test APK..."
TEST_APK_PATH="$PROJECT_DIR/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
if [ -f "$TEST_APK_PATH" ]; then
    adb install -r "$TEST_APK_PATH"
else
    echo "WARNING: $TEST_APK_PATH not found. Run with --build or build manually."
fi

# 5. Verify Chrome is installed
echo "[5/5] Checking Chrome..."
if adb shell pm list packages | grep -q "com.android.chrome"; then
    echo "  Chrome is installed."
else
    echo "  WARNING: Chrome not found on device. E2E tests require Chrome."
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "IMPORTANT: Ensure xKey is enabled as a credential provider:"
echo "  Settings > Passwords & accounts > xKey (toggle ON)"
echo ""

# Run E2E tests if requested
if [ "$RUN" = true ]; then
    echo "=== Running E2E Tests ==="
    adb shell am instrument -w -r \
        -e class com.automatethethings.xkey.e2e.WebAuthnE2ETest \
        com.automatethethings.xkey.debug.test/androidx.test.runner.AndroidJUnitRunner
fi
