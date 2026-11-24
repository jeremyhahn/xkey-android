#!/usr/bin/env bash
# Checks every apt-get stage has Acquire::Retries and that apt recovers from transient 500s against a stub mirror. `make apt-retry-test`.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DOCKERFILE=${ROOT}/build/docker/devcontainer/Dockerfile
CONF=${ROOT}/build/docker/devcontainer/apt-retries.conf
STUB=${ROOT}/scripts/apt-stub-mirror.java
FAILED=0
T=$(mktemp -d)
STUB_PID=
cleanup() {
	[ -z "${STUB_PID}" ] || kill "${STUB_PID}" 2> /dev/null
	rm -rf "${T}"
}
trap cleanup EXIT

not() { ! "$@"; }

check() {
	local name=$1
	shift
	if "$@"; then
		echo "ok   ${name}"
	else
		echo "FAIL ${name}"
		FAILED=1
	fi
}

# retries_covered <dockerfile>: prints each apt-get stage without the retry setting.
retries_covered() {
	local file=$1 line logical='' stage='' parent words n=0 bad=0
	local -A has=() runs=()
	while IFS= read -r line || [ -n "${line}" ]; do
		[[ ${line} =~ ^[[:space:]]*# ]] && continue
		logical+="${line%\\} "
		[[ ${line} == *\\ ]] && continue
		read -r -a words <<< "${logical}"
		logical=''
		[ "${#words[@]}" -gt 0 ] || continue
		case "${words[0]^^}" in
		FROM)
			stage=${words[1]}
			parent=${words[1]}
			if [ "${#words[@]}" -ge 4 ] && [ "${words[2]^^}" = AS ]; then
				stage=${words[3]}
			fi
			has[${stage}]=${has[${parent}]:-0}
			;;
		RUN | COPY)
			case "${words[*]}" in
			*Acquire::Retries* | COPY*apt-retries.conf*/etc/apt/apt.conf.d/*) has[${stage}]=1 ;;
			esac
			if [ "${words[0]^^}" = RUN ] && [[ " ${words[*]} " == *" apt-get "* ]]; then
				n=$((n + 1))
				if [ "${has[${stage}]:-0}" != 1 ] && [ -z "${runs[${stage}]:-}" ]; then
					echo "apt-retry-test: stage ${stage} runs apt-get without Acquire::Retries" >&2
					bad=1
				fi
				runs[${stage}]=1
			fi
			;;
		esac
	done < "${file}"
	[ "${n}" -gt 0 ] && [ "${bad}" = 0 ]
}

# without <pattern> <k>: a copy of the Dockerfile with the k-th line (from 1)
# matching pattern removed, printed as its path.
without() {
	local out=${T}/Dockerfile.$2 seen=0 line
	while IFS= read -r line || [ -n "${line}" ]; do
		if [[ ${line} == *"$1"* ]] && [ "$((++seen))" = "$2" ]; then
			continue
		fi
		printf '%s\n' "${line}"
	done < "${DOCKERFILE}" > "${out}"
	[ "${seen}" -ge "$2" ] || { echo "apt-retry-test: no line $2 matches '$1'" >&2; return 1; }
	echo "${out}"
}

echo "== static: the Dockerfile's stages"
check "every stage that runs apt-get retries" retries_covered "${DOCKERFILE}"
conf_retries() {
	local line re='^Acquire::Retries[[:space:]]+"[1-9][0-9]*";'
	[ -f "${CONF}" ] || return 1
	while IFS= read -r line; do
		[[ ${line} =~ ${re} ]] && return 0
	done < "${CONF}"
	return 1
}
check "apt-retries.conf sets Acquire::Retries above 0" conf_retries
copies=()
while IFS= read -r line; do
	[[ ${line} == 'COPY build/docker/devcontainer/apt-retries.conf '* ]] && copies+=("${line}")
done < "${DOCKERFILE}"
check "two stages copy apt-retries.conf (fetch, base)" test "${#copies[@]}" = 2
for k in $(seq 1 "${#copies[@]}"); do
	f=$(without 'COPY build/docker/devcontainer/apt-retries.conf ' "${k}") || { FAILED=1; continue; }
	check "a copy without apt-retries.conf copy ${k} of ${#copies[@]} fails" not retries_covered "${f}"
done
F=${T}/Dockerfile.bite
printf 'FROM a AS one\nRUN apt-get update\n' > "${F}"
check "a stage with no setting fails" not retries_covered "${F}"
printf 'FROM a AS one\nRUN apt-get update\nRUN echo Acquire::Retries\n' > "${F}"
check "a setting after the first apt-get fails" not retries_covered "${F}"
printf 'FROM a AS one\nRUN echo Acquire::Retries\nFROM a AS two\nRUN apt-get update\n' > "${F}"
check "a sibling stage's setting does not count" not retries_covered "${F}"
printf 'FROM a AS one\nRUN echo Acquire::Retries\nFROM one AS two\nRUN x \\\n && apt-get update\n' > "${F}"
check "a parent stage's setting counts" retries_covered "${F}"

# --- behaviour --------------------------------------------------------------

# A flat repository: an empty Packages and a Release that lists it.
REPO=${T}/repo
mkdir -p "${REPO}" "${T}/parts" "${T}/prefs"
: > "${REPO}/Packages"
{
	echo 'Origin: apt-retry-test'
	echo 'Date: Thu, 01 Jan 2026 00:00:00 UTC'
	echo 'SHA256:'
	echo " $(sha256sum < "${REPO}/Packages" | cut -d' ' -f1) 0 Packages"
} > "${REPO}/Release"
: > "${T}/empty.conf"

# stub <fail_n>: start the stub mirror, set PORT and STUB_PID; failing to start is a failure.
stub() {
	[ -z "${STUB_PID}" ] || { kill "${STUB_PID}" 2> /dev/null; wait "${STUB_PID}" 2> /dev/null; }
	STUB_PID=
	PORT=
	rm -f "${T}/port"
	java "${STUB}" "${REPO}" "$1" "${T}/port" 2>> "${T}/stub.log" &
	STUB_PID=$!
	for _ in $(seq 1 120); do
		[ -s "${T}/port" ] && break
		kill -0 "${STUB_PID}" 2> /dev/null || break
		sleep 0.5
	done
	PORT=$(cat "${T}/port" 2> /dev/null) || PORT=
	[[ ${PORT} =~ ^[0-9]+$ ]] || { PORT=; return 1; }
	# Listening: a connection opens (bash's /dev/tcp, no extra tool).
	if ! (exec 3<> "/dev/tcp/127.0.0.1/${PORT}") 2> /dev/null; then
		PORT=
		return 1
	fi
}

# with_stub <fail_n> <name> <command...>: run the command against a stub mirror.
with_stub() {
	local fail_n=$1 name=$2
	shift 2
	if ! stub "${fail_n}"; then
		echo "FAIL ${name} (the stub mirror did not start)"
		FAILED=1
		return
	fi
	check "${name}" "$@"
}

# stub_cannot_start: a missing stub must produce a FAIL line, in a subshell.
stub_cannot_start() (
	STUB=${T}/no-such-stub.java STUB_PID='' FAILED=0
	! stub 0 || exit 1
	[ -z "${PORT}" ] || exit 1
	out=$(with_stub 0 probe true; echo "FAILED=${FAILED}")
	[[ ${out} == *"FAIL probe (the stub mirror did not start)"* && ${out} == *FAILED=1 ]]
)

# update <apt-get args...>: apt-get update against the stub, as this user,
# with private state, cache, sources and config, and the image builds'
# strict update mode.
update() {
	local s=${T}/apt.$((++UPDATE_N))
	mkdir -p "${s}/state/lists/partial" "${s}/cache/archives/partial"
	echo "deb [trusted=yes] http://127.0.0.1:${PORT}/ ./" > "${s}/sources.list"
	APT_CONFIG=${T}/empty.conf apt-get -q \
		-o Dir::State="${s}/state" -o Dir::State::status="${s}/status" \
		-o Dir::Cache="${s}/cache" -o Dir::Etc::sourcelist="${s}/sources.list" \
		-o Dir::Etc::sourceparts=- -o Dir::Etc::parts="${T}/parts" \
		-o Dir::Etc::preferencesparts="${T}/prefs" -o Debug::NoLocking=1 \
		-o APT::Sandbox::User="$(id -un)" -o Acquire::Languages=none \
		-o Acquire::Retries::Delay::Maximum=1 \
		-o APT::Update::Error-Mode=any "$@" update >> "${T}/apt.log" 2>&1
}
UPDATE_N=0
: > "${T}/status"

echo "== behaviour: apt-get update against a stub mirror"
if ! command -v apt-get > /dev/null || ! command -v java > /dev/null; then
	echo "FAIL apt-get and java are needed for the behaviour check"
	FAILED=1
else
	# The self-check: a stub that cannot start fails its check and the test.
	check "a stub that cannot start is a failure, not a skip" stub_cannot_start
	with_stub 0 "a healthy mirror updates (no retry needed)" update -o Acquire::Retries=0
	with_stub 2 "two HTTP 500s then success: apt-retries.conf recovers" update -c "${CONF}"
	with_stub 2 "two HTTP 500s then success: Acquire::Retries 0 fails" not update -o Acquire::Retries=0
	with_stub -1 "a mirror that always returns 500 still fails" not update -c "${CONF}"
fi

if [ "${FAILED}" != 0 ]; then
	echo "--- apt log (tail)"
	tail -n 20 "${T}/apt.log" 2> /dev/null
	echo "apt-retry-test: FAILED"
	exit 1
fi
echo "apt-retry-test: ok"
