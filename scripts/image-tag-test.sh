#!/usr/bin/env bash
# Tests the package index sums in the image tags (Codex review 7678) and
# scripts/apt-index-sum.sh (Software comment 158438, ruling 223(13)).
#
# Tags, from the real `make -s it-image` and `make -s toolchain-image`: two
# different non-empty APK_INDEX_SUM or APT_INDEX_SUM values give different
# integration tags; unset and empty give the tree's tag; the toolchain tag is
# the same in every case. apt-index-sum.sh, against a stub docker whose `run`
# runs the script's own probe on a fixture lists directory with a stub
# apt-get: it runs the pinned BASE_IMAGE with --rm and dropped capabilities
# and prints one sha256 of the _Packages files alone; it fails (exit 1, no
# stdout) with no _Packages file, when `docker run` or `apt-get update`
# fails, and with no docker. Needs bash, git and make only.
# `make image-tag-test` (make lint-gates).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
T=$(mktemp -d)
trap 'rm -rf "${T}"' EXIT
FAILED=0

check() {
	local what=$1
	shift
	if "$@"; then
		echo "ok   ${what}"
	else
		echo "FAIL ${what}"
		FAILED=1
	fi
}
eq() { [ "$1" = "$2" ]; }
ne() { [ "$1" != "$2" ]; }
is_sum() { [[ $1 =~ ^[0-9a-f]{64}$ ]]; }

# ---- the tags ----

# tag <kind> [VAR=value...]: `make -s <kind>-image` with neither sum set but
# the ones given.
tag() {
	local kind=$1
	shift
	env -u APK_INDEX_SUM -u APT_INDEX_SUM "$@" make -s -C "${ROOT}" "${kind}-image"
}

it0=$(tag it)
tc0=$(tag toolchain)
check "tag: the integration tag is xkey-android-ci-it:<hash>" eq "${it0%%:*}" xkey-android-ci-it
for var in APK_INDEX_SUM APT_INDEX_SUM; do
	check "tag: ${var} empty: the integration tag is the tree's" eq "$(tag it "${var}=")" "${it0}"
	one=$(tag it "${var}=sum1")
	two=$(tag it "${var}=sum2")
	check "tag: ${var} set: the integration tag moves" ne "${one}" "${it0}"
	check "tag: ${var}: two sums give two integration tags" ne "${one}" "${two}"
	check "tag: ${var}: one sum gives one integration tag" eq "$(tag it "${var}=sum1")" "${one}"
	for v in "" sum1 sum2; do
		check "tag: ${var}=${v}: the toolchain tag stays" eq "$(tag toolchain "${var}=${v}")" "${tc0}"
	done
done
check "tag: both empty: the integration tag is the tree's" eq "$(tag it APK_INDEX_SUM= APT_INDEX_SUM=)" "${it0}"
check "tag: one value as APK_INDEX_SUM or APT_INDEX_SUM: two integration tags" \
	ne "$(tag it APK_INDEX_SUM=sum1)" "$(tag it APT_INDEX_SUM=sum1)"
check "tag: the apt sum moves a tag the apk sum set" \
	ne "$(tag it APK_INDEX_SUM=none APT_INDEX_SUM=sum1)" "$(tag it APK_INDEX_SUM=none APT_INDEX_SUM=sum2)"
check "tag: both set: the toolchain tag stays" eq "$(tag toolchain APK_INDEX_SUM=none APT_INDEX_SUM=sum1)" "${tc0}"

# ---- apt-index-sum.sh ----

S="${T}/state"
mkdir -p "${T}/bin" "${T}/apt-bin"
# docker: `run` only. Records its flags and image under $S, then runs the
# probe in place of the container, its /var/lib/apt/lists and /etc/apt moved
# under $S, with the -e variables and the stub apt-get first on PATH.
cat > "${T}/bin/docker" << 'EOF'
#!/usr/bin/env bash
S=${STUB_STATE:?}
[ "$1" = run ] || { echo "stub docker: unexpected $1" >&2; exit 99; }
shift
[ -z "${STUB_RUN_FAIL:-}" ] || { echo "docker: Error response from daemon: stub" >&2; exit 125; }
envs=() img= probe=
while [ $# -gt 0 ]; do
	case $1 in
	-e) envs+=("$2"); shift 2 ;;
	--pull | --network | --user | --cap-drop | --cap-add | --security-opt | --entrypoint)
		echo "$1 $2" >> "${S}/flags"; shift 2 ;;
	--rm) echo "$1" >> "${S}/flags"; shift ;;
	-c) probe=$2; shift 2 ;;
	-*) echo "stub docker: unexpected flag $1" >&2; exit 99 ;;
	*) [ -z "${img}" ] || { echo "stub docker: a second image $1" >&2; exit 99; }; img=$1; shift ;;
	esac
done
echo "${img}" >> "${S}/image"
probe=${probe//\/var\/lib\/apt\/lists/${S}/lists}
probe=${probe//\/etc\/apt/${S}/etc}
env -u APT_PROXY "${envs[@]}" PATH="${STUB_APT_BIN:?}:${PATH}" sh -c "${probe}"
EOF
cat > "${T}/apt-bin/apt-get" << 'EOF'
#!/bin/sh
exit "${STUB_APT_RC:-0}"
EOF
chmod +x "${T}/bin/docker" "${T}/apt-bin/apt-get"

# lists [file...]: a fresh state whose lists directory holds the files.
lists() {
	rm -rf "${S}"
	mkdir -p "${S}/lists/partial" "${S}/etc/apt.conf.d"
	: > "${S}/lists/lock"
	local f
	for f in "$@"; do echo "Package: ${f}" > "${S}/lists/${f}"; done
}
MAIN=deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages.lz4
SEC=deb.debian.org_debian-security_dists_trixie-security_main_binary-amd64_Packages.lz4

# sum [VAR=value...]: the script against the stub, with no proxy but the one
# given; sets RC and OUT.
sum() {
	RC=0
	OUT=$(env -u DEVCACHE_APT_PROXY PATH="${T}/bin:${PATH}" STUB_STATE="${S}" STUB_APT_BIN="${T}/apt-bin" "$@" \
		"${BASH}" "${ROOT}/scripts/apt-index-sum.sh" 2> "${T}/err") || RC=$?
}

# shellcheck source-path=SCRIPTDIR source=tool-pins.sh
PINNED=$(. "${ROOT}/scripts/tool-pins.sh" && printf '%s' "${BASE_IMAGE}")

lists "${MAIN}" "${SEC}" deb.debian.org_debian_dists_trixie_InRelease
sum
check "apt: with _Packages files: exit 0" eq "${RC}" 0
check "apt: with _Packages files: one sha256" is_sum "${OUT}"
check "apt: it runs the pinned BASE_IMAGE once" eq "$(cat "${S}/image")" "${PINNED}"
check "apt: --rm" grep -qxF -- --rm "${S}/flags"
check "apt: as root" grep -qxF -- "--user 0" "${S}/flags"
check "apt: every capability dropped" grep -qxF -- "--cap-drop ALL" "${S}/flags"
check "apt: no new privileges" grep -qxF -- "--security-opt no-new-privileges" "${S}/flags"
check "apt: no proxy unless DEVCACHE_APT_PROXY" test ! -e "${S}/etc/apt.conf.d/01proxy"
first=${OUT}

echo "Valid-Until: later" > "${S}/lists/deb.debian.org_debian_dists_trixie_InRelease"
sum
check "apt: a non-_Packages file leaves the sum alone" eq "${OUT}" "${first}"
echo "Package: fixed" > "${S}/lists/${SEC}"
sum
check "apt: a changed _Packages file moves the sum" ne "${OUT}" "${first}"

lists "${SEC}" "${MAIN}"
sum DEVCACHE_APT_PROXY=http://devcache:3142
check "apt: the sum is the same through the proxy" eq "${OUT}" "${first}"
check "apt: DEVCACHE_APT_PROXY is apt's proxy" \
	grep -qF 'Acquire::http::Proxy "http://devcache:3142";' "${S}/etc/apt.conf.d/01proxy"

lists deb.debian.org_debian_dists_trixie_InRelease
sum
check "apt: no _Packages file: exit 1" eq "${RC}" 1
check "apt: no _Packages file: no sum" eq "${OUT}" ""

lists "${MAIN}"
sum STUB_RUN_FAIL=1
check "apt: docker run fails: exit 1" eq "${RC}" 1
check "apt: docker run fails: no sum" eq "${OUT}" ""
check "apt: docker run fails: says so" grep -q "reading the Debian package index of ${PINNED} failed" "${T}/err"

lists "${MAIN}"
sum STUB_APT_RC=100
check "apt: apt-get update fails: exit 1" eq "${RC}" 1
check "apt: apt-get update fails: no sum" eq "${OUT}" ""

# No docker: PATH holds only what the script runs before it looks.
mkdir -p "${T}/nodocker"
ln -s "$(command -v dirname)" "${T}/nodocker/dirname"
RC=0
OUT=$(env -u DEVCACHE_APT_PROXY PATH="${T}/nodocker" "${BASH}" "${ROOT}/scripts/apt-index-sum.sh" 2> "${T}/err") || RC=$?
check "apt: no docker: exit 1" eq "${RC}" 1
check "apt: no docker: no sum" eq "${OUT}" ""
check "apt: no docker: says so" grep -q "docker not found" "${T}/err"

if [ "${FAILED}" != 0 ]; then
	echo "image-tag-test: FAILED"
	exit 1
fi
echo "image-tag-test: ok"
