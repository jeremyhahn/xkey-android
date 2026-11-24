#!/usr/bin/env bash
# Build a release APK with a throwaway key and verify its single signer. Exit 0 ok, 1 failed (or guard refused under RELEASE_CHECK_OMIT), 2 guard broken.
set -euo pipefail

cd "$(dirname "$0")/.."
root=$(pwd)
# shellcheck source=scripts/tool-pins.sh
. scripts/tool-pins.sh

fail() { echo "release-check: $*" >&2; exit 1; }

# keystore.properties wins over the environment key by key, so the build
# would not be signed with the throwaway key.
[ ! -e keystore.properties ] \
	|| fail "keystore.properties exists at the repository root and would override the throwaway key; move it aside first"

command -v keytool > /dev/null || fail "keytool not found on PATH (it ships with the JDK)"
sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
apksigner=${APKSIGNER:-${sdk:+$sdk/build-tools/$ANDROID_BUILD_TOOLS/apksigner}}
[ -n "$apksigner" ] && [ -x "$apksigner" ] \
	|| fail "apksigner not found (APKSIGNER=${APKSIGNER:-unset}, ANDROID_HOME/ANDROID_SDK_ROOT=${sdk:-unset}, build-tools $ANDROID_BUILD_TOOLS)"

out=$root/build/release-check
keystore=$out/throwaway.p12
alias=xkey-release-check
rm -rf "$out"
mkdir -p "$out"
trap 'rm -f "$keystore" "$out/throwaway.der"' EXIT

# PKCS12 keeps one password for the store and the key.
password=$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')
keytool -genkeypair -noprompt -storetype PKCS12 -keystore "$keystore" \
	-storepass "$password" -keypass "$password" -alias "$alias" \
	-keyalg RSA -keysize 2048 -validity 1 \
	-dname "CN=xKey release-check throwaway" > "$out/keytool.log" 2>&1 \
	|| { cat "$out/keytool.log" >&2; fail "keytool -genkeypair failed"; }
keytool -exportcert -keystore "$keystore" -storepass "$password" -alias "$alias" \
	-file "$out/throwaway.der" > /dev/null 2>&1 || fail "keytool -exportcert failed"
expected=$(sha256sum "$out/throwaway.der" | cut -d' ' -f1)

export XKEY_KEYSTORE_FILE=$keystore
export XKEY_KEYSTORE_PASSWORD=$password
export XKEY_KEY_ALIAS=$alias
export XKEY_KEY_PASSWORD=$password
if [ -n "${RELEASE_CHECK_OMIT:-}" ]; then
	case "$RELEASE_CHECK_OMIT" in
		XKEY_KEYSTORE_FILE | XKEY_KEYSTORE_PASSWORD | XKEY_KEY_ALIAS | XKEY_KEY_PASSWORD) ;;
		*) fail "RELEASE_CHECK_OMIT=$RELEASE_CHECK_OMIT is not one of the four XKEY_* variables" ;;
	esac
	echo "release-check: building without $RELEASE_CHECK_OMIT (RELEASE_CHECK_OMIT)"
	unset "$RELEASE_CHECK_OMIT"
fi

apk=app/build/outputs/apk/release/app-release.apk
rm -f "$apk"
set +e
# shellcheck disable=SC2086 # GRADLE may carry flags (--offline)
${GRADLE:-./gradlew} assembleRelease 2>&1 | tee "$out/gradle.log"
status=${PIPESTATUS[0]}
set -e

if [ -n "${RELEASE_CHECK_OMIT:-}" ]; then
	# The guard's message (app/build.gradle.kts, the release task doFirst).
	guard="Release signing is not configured."
	broken() { echo "release-check: GUARD BROKEN: $*" >&2; exit 2; }
	[ "$status" -ne 0 ] \
		|| broken "assembleRelease succeeded without $RELEASE_CHECK_OMIT: the release guard did not refuse the build"
	[[ $(< "$out/gradle.log") == *"$guard"* ]] \
		|| broken "assembleRelease failed without $RELEASE_CHECK_OMIT, but not with the release guard's \"$guard\" (see $out/gradle.log)"
	echo "release-check: release build refused without $RELEASE_CHECK_OMIT, as the guard requires" >&2
	exit 1
fi

[ "$status" -eq 0 ] || fail "assembleRelease failed (exit $status)"
[ -f "$apk" ] || fail "$apk was not built"

"$apksigner" verify --print-certs "$apk" > "$out/apksigner.txt" 2>&1 \
	|| { cat "$out/apksigner.txt" >&2; fail "apksigner verify failed for $apk"; }
signers=$(awk '/^Signer #[0-9]+ certificate SHA-256 digest:/ { print $NF }' "$out/apksigner.txt")
[ "$(printf '%s\n' "$signers" | awk 'NF' | wc -l)" -eq 1 ] \
	|| { cat "$out/apksigner.txt" >&2; fail "expected exactly one signer in $apk"; }
[ "$signers" = "$expected" ] \
	|| fail "$apk is signed by certificate $signers, not the throwaway $expected"

echo "release-check: $apk verifies, signed by the throwaway certificate $expected"
