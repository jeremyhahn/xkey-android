#!/usr/bin/env bash
# Tests the package index sums in the image tags and
# scripts/apt-index-sum.sh.
#
# Tags, from the real `make -s it-image` and `make -s toolchain-image`: two
# different non-empty APK_INDEX_SUM or APT_INDEX_SUM values give different
# integration tags; unset and empty give the tree's tag; the toolchain tag is
# the same in every case. apt-index-sum.sh, against a stub docker whose `run`
# runs the script's own probe on a fixture lists directory with a stub
# apt-get: it runs the pinned BASE_IMAGE with --rm and dropped capabilities
# and prints one sha256 of the _Packages files alone; it fails (exit 1, no
# stdout) with no _Packages file, when `docker run` or `apt-get update`
# fails, and with no docker. Every `apt-get update` the integration tag
# depends on (the Dockerfile's integration stage, the probe) passes
# APT::Update::Error-Mode=any. Needs bash, git and make only.
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
not() { ! "$@" 2> /dev/null; }
is_sum() { [[ $1 =~ ^[0-9a-f]{64}$ ]]; }

# strict_words <args>: apt-get arguments that hold `-o
# APT::Update::Error-Mode=any`, so an index apt cannot refresh fails the
# update instead of a warning.
strict_words() {
	local -a w
	read -ra w <<< "$1"
	local i
	for ((i = 0; i + 1 < ${#w[@]}; i++)); do
		[ "${w[i]}" = -o ] && [ "${w[i + 1]}" = APT::Update::Error-Mode=any ] && return 0
	done
	return 1
}

# strict_updates <file> [stage]: every `apt-get ... update` in the file, or in
# the Dockerfile stage named, is strict (strict_words), and there is one at
# least. Comment lines are skipped, continuation lines joined, and commands
# split at &&, ||, | and ;.
strict_updates() {
	local file=$1 stage=${2:-} in=1 n=0 line logical='' cmd i seen
	local -a cmds w
	[ -z "${stage}" ] || in=0
	while IFS= read -r line || [ -n "${line}" ]; do
		[[ ${line} =~ ^[[:space:]]*# ]] && continue
		if [[ ${line} == *\\ ]]; then
			logical+="${line%\\} "
			continue
		fi
		logical+=${line}
		if [ -n "${stage}" ] && [[ ${logical} =~ ^FROM[[:space:]] ]]; then
			in=0
			[[ ${logical} =~ [[:space:]][Aa][Ss][[:space:]]+${stage}[[:space:]]*$ ]] && in=1
		fi
		if [ "${in}" = 1 ]; then
			logical=${logical//&&/;}
			logical=${logical//|/;}
			IFS=';' read -ra cmds <<< "${logical}"
			for cmd in "${cmds[@]}"; do
				read -ra w <<< "${cmd}"
				seen=0
				for ((i = 0; i < ${#w[@]}; i++)); do
					[ "${w[i]}" = apt-get ] && seen=1
					[ "${seen}" = 1 ] && [ "${w[i]}" = update ] || continue
					n=$((n + 1))
					strict_words "${cmd}" || { echo "not strict: ${file}: ${cmd}" >&2; return 1; }
					break
				done
			done
		fi
		logical=
	done < "${file}"
	[ "${n}" -gt 0 ]
}

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
echo "$*" >> "${STUB_STATE:?}/apt-get"
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
check "apt: the probe's apt-get update is strict" \
	strict_words "$(cat "${S}/apt-get")"
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

# ---- strict index refresh ----

# Every `apt-get update` the APT_INDEX_SUM tag depends on fails on an index it
# cannot refresh: the integration stage's, whose upgrade the tag reruns, and
# the probe's, whose index the tag hashes. A warning would cache a stale
# upgrade under the new tag. base and toolchain do not take APT_INDEX_SUM.
check "strict: the integration stage's apt-get update" \
	strict_updates "${ROOT}/build/docker/devcontainer/Dockerfile" integration
check "strict: apt-index-sum.sh's apt-get update" \
	strict_updates "${ROOT}/scripts/apt-index-sum.sh"

# The checker bites: a plain update, one strict and one plain, a stage with no
# update, and a strict update in another stage only.
F="${T}/Dockerfile"
printf 'FROM a AS integration\nRUN apt-get update && apt-get upgrade -y\n' > "${F}"
check "strict: a plain update fails" not strict_updates "${F}" integration
printf 'FROM a AS integration\nRUN apt-get -o APT::Update::Error-Mode=any update \\\n && apt-get update\n' > "${F}"
check "strict: a second, plain update fails" not strict_updates "${F}" integration
printf 'FROM a AS integration\nRUN apt-get install -y make\n' > "${F}"
check "strict: no update fails" not strict_updates "${F}" integration
printf 'FROM a AS base\nRUN apt-get -o APT::Update::Error-Mode=any update\nFROM base AS integration\nRUN apt-get update\n' > "${F}"
check "strict: only the named stage counts" not strict_updates "${F}" integration
printf 'FROM a AS integration\nRUN x \\\n # apt-get update\n && apt-get update -qq -o APT::Update::Error-Mode=any || exit 3\n' > "${F}"
check "strict: a strict update passes" strict_updates "${F}" integration

if [ "${FAILED}" != 0 ]; then
	echo "image-tag-test: FAILED"
	exit 1
fi
echo "image-tag-test: ok"
