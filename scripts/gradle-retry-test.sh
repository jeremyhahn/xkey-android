#!/usr/bin/env bash
# gradle-retry-test: the toolchain image's Gradle download retry, checked two
# ways.
#
# The warm stage of build/docker/devcontainer/Dockerfile runs the gates once,
# online, to fill the Gradle dependency cache. One transient repository error
# (an artifact Gradle "Could not resolve") must not fail the image build, so
# that run goes through /usr/local/bin/gradle-retry, a script the Dockerfile
# writes with a COPY heredoc: a bounded retry, with gradle-quiesce between
# attempts, that still fails closed.
#
# 1. Static: in the warm stage, every online RUN of the gates (assembleDebug)
#    runs them through gradle-retry, after the COPY that writes it; no bare
#    `gradle ... assembleDebug` online run remains, and the offline proof is
#    never retried (there a missing dependency is a gap in the cache). Copies of the Dockerfile with the
#    retry removed from the RUN, or with the script's COPY removed, fail.
# 2. Behaviour: the gradle-retry script itself, extracted from the Dockerfile
#    (the heredoc body between its COPY line and EOF, never a copy), run with
#    a stubbed gradle and gradle-quiesce on PATH and no backoff. It passes
#    when an attempt fails to resolve a dependency and a later one succeeds;
#    fails after exactly the bound when every attempt fails, printing the log
#    tail; makes no attempt after a success; and does not retry a failure
#    that is not a download failure (a failing test). Mutants of the script
#    (the bound removed, the last attempt failing open, every failure
#    retried) are caught.
#
# Needs bash and coreutils; offline. `make gradle-retry-test` (make
# lint-gates).
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DOCKERFILE=${ROOT}/build/docker/devcontainer/Dockerfile
SCRIPT_PATH=/usr/local/bin/gradle-retry
BOUND=3
FAILED=0
T=$(mktemp -d)
cleanup() { rm -rf "${T}"; }
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

# warm_uses_retry <dockerfile>: the warm stage writes gradle-retry with a COPY
# heredoc, and every RUN in it naming assembleDebug runs `gradle-retry`, after
# that COPY; at least one does. Comment lines and heredoc bodies are skipped,
# continuation lines joined.
warm_uses_retry() {
	local file=$1 line logical='' words in_warm=0 heredoc='' copied=0 runs=0 bad=0
	while IFS= read -r line || [ -n "${line}" ]; do
		if [ -n "${heredoc}" ]; then
			[ "${line}" = "${heredoc}" ] && heredoc=''
			continue
		fi
		[[ ${line} =~ ^[[:space:]]*# ]] && continue
		logical+="${line%\\} "
		[[ ${line} == *\\ ]] && continue
		read -r -a words <<< "${logical}"
		logical=''
		[ "${#words[@]}" -gt 0 ] || continue
		if [[ " ${words[*]} " =~ \<\<-?\'?([A-Za-z_]+)\'?\  ]]; then
			heredoc=${BASH_REMATCH[1]}
		fi
		case "${words[0]^^}" in
		FROM)
			in_warm=0
			[ "${#words[@]}" -ge 4 ] && [ "${words[3]}" = warm ] && in_warm=1
			;;
		COPY)
			[ "${in_warm}" = 1 ] && [ "${words[-1]}" = "${SCRIPT_PATH}" ] && [ -n "${heredoc}" ] && copied=1
			;;
		RUN)
			[ "${in_warm}" = 1 ] || continue
			[[ " ${words[*]} " == *" assembleDebug "* ]] || continue
			if [[ " ${words[*]} " == *" --offline "* ]]; then
				if [[ " ${words[*]} " == *" gradle-retry "* ]]; then
					echo "gradle-retry-test: the offline proof runs through gradle-retry" >&2
					bad=1
				fi
				continue
			fi
			runs=$((runs + 1))
			if [ "${words[1]}" != gradle-retry ]; then
				echo "gradle-retry-test: a warm RUN runs the gates without gradle-retry" >&2
				bad=1
			elif [ "${copied}" != 1 ]; then
				echo "gradle-retry-test: a warm RUN uses gradle-retry before the COPY that writes it" >&2
				bad=1
			fi
			;;
		esac
	done < "${file}"
	[ "${runs}" -gt 0 ] && [ "${bad}" = 0 ]
}

# extract <dockerfile> <out>: the body of the heredoc that writes gradle-retry,
# from the line after its COPY to the line before EOF. Fails if there is none.
extract() {
	local line in=0 found=0
	while IFS= read -r line || [ -n "${line}" ]; do
		if [ "${in}" = 1 ]; then
			if [ "${line}" = EOF ]; then
				in=0
				found=1
				continue
			fi
			printf '%s\n' "${line}"
		elif [[ ${line} == COPY*"<<'EOF' ${SCRIPT_PATH}" ]]; then
			in=1
		fi
	done < "$1" > "$2"
	[ "${found}" = 1 ] && [ -s "$2" ] && chmod +x "$2"
}

# replace <file> <from> <to> <out>: a copy of file with every from replaced;
# fails unless from occurs.
replace() {
	local s
	s=$(< "$1")
	[[ ${s} == *"$2"* ]] || { echo "gradle-retry-test: '$2' not in $1" >&2; return 1; }
	printf '%s\n' "${s//"$2"/"$3"}" > "$4"
	chmod +x "$4"
}

echo "== static: the warm stage"
check "the warm stage's gates run through gradle-retry" warm_uses_retry "${DOCKERFILE}"
F=${T}/Dockerfile.bare
if replace "${DOCKERFILE}" 'RUN gradle-retry /tmp/warm.log ' 'RUN gradle ' "${F}" 2> /dev/null; then
	check "a copy with the warm RUN's retry removed fails" not warm_uses_retry "${F}"
else
	check "the warm RUN calls gradle-retry /tmp/warm.log" false
fi
F=${T}/Dockerfile.nocopy
if replace "${DOCKERFILE}" "<<'EOF' ${SCRIPT_PATH}" "<<'EOF' /usr/local/bin/other" "${F}" 2> /dev/null; then
	check "a copy without the script's COPY fails" not warm_uses_retry "${F}"
else
	check "the warm stage writes ${SCRIPT_PATH} with a COPY heredoc" false
fi
printf 'FROM fetch AS warm\nRUN gradle --no-daemon assembleDebug \\\n  lintDebug\n' > "${T}/Dockerfile.bite"
check "a bare gradle gates run fails" not warm_uses_retry "${T}/Dockerfile.bite"
printf 'FROM fetch AS warm\nRUN gradle-retry /tmp/w.log assembleDebug\n' > "${T}/Dockerfile.bite"
check "gradle-retry used without its COPY fails" not warm_uses_retry "${T}/Dockerfile.bite"
printf "FROM fetch AS warm\nCOPY <<'EOF' %s\nexit 0\nEOF\nRUN gradle-retry /tmp/w.log assembleDebug\nRUN gradle-retry /tmp/p.log --offline assembleDebug\n" "${SCRIPT_PATH}" > "${T}/Dockerfile.bite"
check "a retried offline proof fails" not warm_uses_retry "${T}/Dockerfile.bite"
printf "FROM fetch AS warm\nCOPY <<'EOF' %s\nRUN gradle assembleDebug\nEOF\nRUN gradle-retry /tmp/w.log assembleDebug\nRUN gradle --offline assembleDebug\n" "${SCRIPT_PATH}" > "${T}/Dockerfile.bite"
check "heredoc bodies are skipped and the bare offline proof passes" warm_uses_retry "${T}/Dockerfile.bite"

# --- behaviour --------------------------------------------------------------

# The stubs: gradle reads its outcome for attempt n from line n of
# ${STUB_DIR}/plan (ok, resolve, test; ok past the end), counts its calls in
# ${STUB_DIR}/calls and its arguments in ${STUB_DIR}/args; gradle-quiesce
# counts its calls in ${STUB_DIR}/quiesce.
BIN=${T}/bin
mkdir -p "${BIN}"
cat > "${BIN}/gradle" << 'STUB'
#!/usr/bin/env bash
n=$(($(wc -l < "${STUB_DIR}/calls") + 1))
echo "$n" >> "${STUB_DIR}/calls"
printf '%s\n' "$*" >> "${STUB_DIR}/args"
mapfile -t plan < "${STUB_DIR}/plan"
outcome=${plan[n - 1]:-}
case "${outcome:-ok}" in
ok) echo "BUILD SUCCESSFUL (attempt $n)"; exit 0 ;;
resolve)
	echo "> Could not resolve all files for configuration ':app:debugCompileClasspath'."
	echo "   > Could not resolve com.google.code.gson:gson:2.11.0."
	echo "STUB-MARK attempt $n"
	echo "BUILD FAILED"
	exit 1
	;;
test)
	echo "WarmTest > sums FAILED"
	echo "STUB-MARK attempt $n"
	echo "BUILD FAILED"
	exit 1
	;;
esac
STUB
cat > "${BIN}/gradle-quiesce" << 'STUB'
#!/usr/bin/env bash
echo q >> "${STUB_DIR}/quiesce"
STUB
chmod +x "${BIN}/gradle" "${BIN}/gradle-quiesce"

# run_retry <script> <plan words...>: run script with the stubs and that plan;
# sets RC, CALLS, QUIESCE and OUT (its output), LOG (the log it was given).
run_retry() {
	local script=$1
	shift
	export STUB_DIR=${T}/stub.$((++RUN_N))
	mkdir -p "${STUB_DIR}"
	: > "${STUB_DIR}/calls"
	: > "${STUB_DIR}/quiesce"
	printf '%s\n' "$@" > "${STUB_DIR}/plan"
	LOG=${STUB_DIR}/warm.log
	OUT=$(PATH="${BIN}:${PATH}" GRADLE_RETRY_DELAY=0 "${script}" "${LOG}" --no-daemon assembleDebug 2>&1)
	RC=$?
	CALLS=$(wc -l < "${STUB_DIR}/calls")
	QUIESCE=$(wc -l < "${STUB_DIR}/quiesce")
}
RUN_N=0

# The cases, each on a script; each returns 0 when the script behaves.
case_recovers() {
	run_retry "$1" resolve ok resolve
	[ "${RC}" = 0 ] && [ "${CALLS}" = 2 ] && [ "${QUIESCE}" = 1 ] \
		&& [[ $(< "${STUB_DIR}/args") == "--no-daemon assembleDebug"* ]]
}
case_recovers_last() {
	local plan=() i
	for ((i = 1; i < BOUND; i++)); do plan+=(resolve); done
	run_retry "$1" "${plan[@]}" ok
	[ "${RC}" = 0 ] && [ "${CALLS}" = "${BOUND}" ]
}
case_bounded() {
	run_retry "$1" resolve resolve resolve resolve resolve resolve resolve resolve resolve resolve
	[ "${RC}" != 0 ] && [ "${CALLS}" = "${BOUND}" ] \
		&& [[ ${OUT} == *"STUB-MARK attempt ${BOUND}"* ]] && [[ ${OUT} == *"Could not resolve"* ]]
}
case_no_attempt_after_success() {
	run_retry "$1" ok resolve
	[ "${RC}" = 0 ] && [ "${CALLS}" = 1 ] && [ "${QUIESCE}" = 0 ] && [ -s "${LOG}" ]
}
case_other_failure_not_retried() {
	run_retry "$1" test ok
	[ "${RC}" != 0 ] && [ "${CALLS}" = 1 ] && [[ ${OUT} == *"WarmTest > sums FAILED"* ]]
}
case_other_failure_after_resolve() {
	run_retry "$1" resolve test ok
	[ "${RC}" != 0 ] && [ "${CALLS}" = 2 ] && [[ ${OUT} == *"STUB-MARK attempt 2"* ]]
}
CASES=(case_recovers case_recovers_last case_bounded case_no_attempt_after_success
	case_other_failure_not_retried case_other_failure_after_resolve)

all_cases() {
	local c
	for c in "${CASES[@]}"; do "${c}" "$1" || return 1; done
}

echo "== behaviour: gradle-retry from the Dockerfile, against a stubbed gradle"
S=${T}/gradle-retry
if ! extract "${DOCKERFILE}" "${S}"; then
	check "the Dockerfile writes ${SCRIPT_PATH} with a COPY <<'EOF' heredoc" false
else
	check "a resolution failure, then success, passes" case_recovers "${S}"
	check "success on the last of ${BOUND} attempts passes" case_recovers_last "${S}"
	check "every attempt failing fails after exactly ${BOUND}, with the log tail" case_bounded "${S}"
	check "no attempt after a success" case_no_attempt_after_success "${S}"
	check "a failing test is not retried" case_other_failure_not_retried "${S}"
	check "a failing test after a resolution failure stops there" case_other_failure_after_resolve "${S}"

	# The mutants: each must fail at least one case. The patterns are the
	# script's literal text, so they do not expand.
	M=${T}/mutant
	if replace "${S}" "attempts=${BOUND}" "attempts=99" "${M}.bound"; then
		check "a mutant with the bound raised is caught" not all_cases "${M}.bound"
	else
		check "the script sets attempts=${BOUND}" false
	fi
	# shellcheck disable=SC2016
	if replace "${S}" '[ "${n}" -ge "${attempts}" ] || ' '' "${M}.unbounded"; then
		check "a mutant with the bound removed is caught" not all_cases "${M}.unbounded"
	else
		check "the script stops at the bound" false
	fi
	# shellcheck disable=SC2016
	if replace "${S}" 'exit "${rc}"' 'exit 0' "${M}.open"; then
		check "a mutant failing open is caught" not all_cases "${M}.open"
	else
		check "the script exits with the last attempt's status" false
	fi
	if replace "${S}" '! grep -Eq' 'false && ! grep -Eq' "${M}.any"; then
		check "a mutant retrying every failure is caught" not all_cases "${M}.any"
	else
		check "the script retries only download failures" false
	fi
fi

if [ "${FAILED}" != 0 ]; then
	echo "gradle-retry-test: FAILED"
	exit 1
fi
echo "gradle-retry-test: ok"
