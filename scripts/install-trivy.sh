#!/bin/sh
# Install the trivy pinned in scripts/tool-pins.sh, verified against its SHA-256 before anything runs. Usage: scripts/install-trivy.sh <install-dir>

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

INSTALL_DIR=${1:-}
if [ -z "${INSTALL_DIR}" ]; then
	echo "usage: $0 <install-dir>" >&2
	exit 2
fi

# Version and SHA-256 come from the one pin file, the same pins the
# devcontainer image installs.
# shellcheck source-path=SCRIPTDIR source=tool-pins.sh
. "${SCRIPT_DIR}/tool-pins.sh"
VERSION=${TRIVY_VERSION:-}
if [ -z "${VERSION}" ]; then
	echo "error: TRIVY_VERSION is missing from scripts/tool-pins.sh" >&2
	exit 1
fi

# Refuse a version string that is not a plain semver. It is interpolated into a
# download URL, and a pinned installer that will fetch whatever it is handed is
# not pinned.
if ! printf '%s' "${VERSION}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "error: trivy version '${VERSION}' is not a bare semver (expected e.g. 0.74.0)" >&2
	exit 1
fi

for tool in curl tar sha256sum; do
	command -v "${tool}" > /dev/null 2>&1 || {
		echo "error: ${tool} is required and was not found" >&2
		exit 1
	}
done

OS=$(uname -s)
ARCH=$(uname -m)
case "${OS}:${ARCH}" in
	Linux:x86_64)          ARTIFACT="trivy_${VERSION}_Linux-64bit.tar.gz" SHA256=${TRIVY_SHA256_X64} ;;
	Linux:aarch64|Linux:arm64) ARTIFACT="trivy_${VERSION}_Linux-ARM64.tar.gz" SHA256=${TRIVY_SHA256_ARM64} ;;
	*)
		# Deliberately not guessing. A wrong artifact name would fail the
		# checksum step anyway, but failing here says why.
		echo "error: unsupported platform ${OS}/${ARCH} — add its artifact name here" >&2
		exit 1
		;;
esac

# Always download and verify: a binary's self-reported version is not a trust anchor.

BASE_URL="https://github.com/aquasecurity/trivy/releases/download/v${VERSION}"
TMP=$(mktemp -d)
# shellcheck disable=SC2064  # expand TMP now, on purpose: it must not change
trap "rm -rf '${TMP}'" EXIT INT TERM

echo "→ downloading trivy ${VERSION} (${ARTIFACT})"
curl -sSfL --proto '=https' --tlsv1.2 -o "${TMP}/${ARTIFACT}" "${BASE_URL}/${ARTIFACT}"

echo "→ verifying SHA-256 against scripts/tool-pins.sh"
echo "${SHA256}  ${ARTIFACT}" > "${TMP}/expected.sha256"
if ! (cd "${TMP}" && sha256sum -c expected.sha256); then
	echo "error: CHECKSUM MISMATCH for ${ARTIFACT} — refusing to install" >&2
	echo "       The download does not match the checksum published for v${VERSION}." >&2
	echo "       Do not work around this. Re-run; if it persists, treat it as a" >&2
	echo "       supply-chain event and escalate before installing anything." >&2
	exit 1
fi

echo "→ installing to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
tar -xzf "${TMP}/${ARTIFACT}" -C "${TMP}" trivy
install -m 0755 "${TMP}/trivy" "${INSTALL_DIR}/trivy"

"${INSTALL_DIR}/trivy" --version | head -1
echo "✓ trivy ${VERSION} installed at ${INSTALL_DIR}/trivy"
