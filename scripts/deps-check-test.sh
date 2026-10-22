#!/usr/bin/env bash
# Tests scripts/deps-check.sh's evaluation against fixture reports and a
# fixture repository on disk (file:// URLs, release dates set as file mtimes),
# so it runs offline and without Gradle. `make deps-check-test`.
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d)
# shellcheck disable=SC2064  # expand TMP now
trap "rm -rf '${TMP}'" EXIT INT TERM

# release name date-offset version...: publishes com.example:name, each
# version's POM dated by its offset ("10 days ago").
release() {
	local name=$1 dir="${TMP}/repo/com/example/$1" spec v when
	shift
	mkdir -p "${dir}"
	{
		echo "<metadata><versioning><versions>"
		for spec in "$@"; do echo "<version>${spec%%@*}</version>"; done
		echo "</versions></versioning></metadata>"
	} > "${dir}/maven-metadata.xml"
	for spec in "$@"; do
		v=${spec%%@*} when=${spec#*@}
		mkdir -p "${dir}/${v}"
		touch -d "${when}" "${dir}/${v}/${name}-${v}.pom"
	done
}

# report file name current latest...: a dependencyUpdates JSON report.
report() {
	local file=$1
	shift
	jq -n --args '{unresolved: {dependencies: []}, outdated: {dependencies: [$ARGS.positional | _nwise(3)
		| {group: "com.example", name: .[0], version: .[1], available: {release: .[2]}}]}}' "$@" > "${file}"
}

release young "1.0@40 days ago" "1.1@3 days ago"
release old "1.0@40 days ago" "1.1@10 days ago"
release held "1.0@40 days ago" "2.0@30 days ago"
release mixed "1.0@40 days ago" "1.1@10 days ago" "1.2@3 days ago"
release pre "1.0@40 days ago" "1.1-alpha01@20 days ago" "1.1@2 days ago"
# Metadata order is not version order: 1.1 is older than 2.0, 1.2 newer than 1.1.
release maint "1.0@40 days ago" "2.0@30 days ago" "1.1@20 days ago" "2.1@3 days ago"
release later "1.0@40 days ago" "1.2@10 days ago" "1.1@30 days ago" "1.3@2 days ago"
# Numbers compare as numbers: 1.9 < 1.9.1 < 1.10.
release num "1.9@40 days ago" "1.10@3 days ago" "1.9.1@10 days ago"
# Qualifiers: alpha < beta < rc < release, whatever the listing order.
release qual "2.0-alpha01@40 days ago" "2.0-rc01@30 days ago" "2.0-beta01@35 days ago" "2.0@2 days ago"
# 1.1's POM is missing, so it has no release date.
release undated "1.0@40 days ago" "1.1@10 days ago" "1.2@3 days ago"
# Maven orders 1.0-1 before 1.0.1: the separator is not punctuation to drop.
release sep "1.0-1@40 days ago" "1.0.1@10 days ago" "1.0.2@3 days ago"
rm "${TMP}/repo/com/example/undated/1.1/undated-1.1.pom"
mkdir -p "${TMP}/repo/com/example/empty"
echo "<metadata><versioning></versioning></metadata>" > "${TMP}/repo/com/example/empty/maven-metadata.xml"

printf '%s\n' '# fixture' 'com.example:held  fixture reason, test, 2026-10-20' > "${TMP}/exempt"
printf '%s\n' 'com.example:held' > "${TMP}/exempt-noreason"

export DEPS_CHECK_REPOS="file://${TMP}/repo" DEPS_CHECK_PROTO='=file' DEPS_CHECK_EXEMPT="${TMP}/exempt"

fails=0 runs=0
# verify rc verdict label command...: the exit code, and the verdict (report,
# FAIL, exempt) the output's first line must start with.
verify() {
	local want=$1 verdict=$2 label=$3 got=0
	shift 3
	runs=$((runs + 1))
	"$@" > "${TMP}/out" 2>&1 || got=$?
	if [ "${got}" -ne "${want}" ] || ! head -n 1 "${TMP}/out" | grep -q "^${verdict} "; then
		echo "FAIL: ${label} exited ${got}, want ${want} and ${verdict}:"
		cat "${TMP}/out"
		fails=$((fails + 1))
	else
		echo "ok:   ${label} -> ${want} ${verdict}"
	fi
}

# expect rc verdict exempt-file name current latest...: a report of those
# libraries, evaluated.
expect() {
	local want=$1 verdict=$2 exempt=$3
	shift 3
	report "${TMP}/report.json" "$@"
	verify "${want}" "${verdict}" "$*" env DEPS_CHECK_EXEMPT="${exempt}" \
		"${SCRIPT_DIR}/deps-check.sh" --report "${TMP}/report.json"
}

# raw rc verdict label json: an evaluated report with that content.
raw() {
	printf '%s\n' "$4" > "${TMP}/raw.json"
	verify "$1" "$2" "$3" "${SCRIPT_DIR}/deps-check.sh" --report "${TMP}/raw.json"
}

expect 0 report "${TMP}/exempt" young 1.0 1.1             # 3 days old: reported
expect 1 FAIL "${TMP}/exempt" old 1.0 1.1                 # 10 days old: fails
expect 0 exempt "${TMP}/exempt" held 1.0 2.0              # exempted with a reason
expect 1 FAIL "${TMP}/exempt-noreason" held 1.0 2.0       # exemption without a reason
expect 1 FAIL "${TMP}/exempt" mixed 1.0 1.2               # newest young, 1.1 is old: fails
expect 0 report "${TMP}/exempt" pre 1.0 1.1               # the old alpha is skipped
expect 1 report "${TMP}/exempt" young 1.0 1.1 old 1.0 1.1 # one failure fails the run
expect 0 report "${TMP}/exempt" maint 2.0 2.1             # the old 1.1 is older than 2.0
expect 1 FAIL "${TMP}/exempt" later 1.1 1.3               # 1.2, listed before 1.1, is newer
expect 1 FAIL "${TMP}/exempt" num 1.9 1.10                 # 1.9.1 is between, and old
expect 0 report "${TMP}/exempt" qual 2.0-rc01 2.0         # beta01 is older than rc01
expect 1 FAIL "${TMP}/exempt" qual 2.0-beta01 2.0         # rc01 is newer than beta01, and old
expect 1 FAIL "${TMP}/exempt" young 1.0 1.2               # the newest is not in the metadata
expect 1 FAIL "${TMP}/exempt" undated 1.0 1.2             # 1.1 has no release date
expect 1 FAIL "${TMP}/exempt" absent 1.0 1.1              # no repository serves its metadata
expect 1 FAIL "${TMP}/exempt" empty 1.0 1.1               # metadata without versions
expect 1 FAIL "${TMP}/exempt" sep 1.0-1 1.0.2             # 1.0.1 is newer than 1.0-1, and old

# A metadata fetch that fails, not a missing file: curl refuses the protocol.
report "${TMP}/report.json" young 1.0 1.1
verify 1 FAIL "metadata fetch fails" env DEPS_CHECK_REPOS="http://127.0.0.1:9" \
	"${SCRIPT_DIR}/deps-check.sh" --report "${TMP}/report.json"

raw 1 FAIL "malformed JSON" '{"outdated": {"dependencies": ['
raw 1 FAIL "{}" '{}'
raw 1 FAIL "no unresolved section" '{"outdated": {"dependencies": []}}'
raw 1 FAIL "dependencies not an array" '{"outdated": {"dependencies": {}}, "unresolved": {"dependencies": []}}'
raw 1 FAIL "entry without a version" '{"outdated": {"dependencies": [{"group": "g", "name": "n", "available": {"release": "1"}}]}, "unresolved": {"dependencies": []}}'
raw 0 deps-check: "empty report" '{"outdated": {"dependencies": []}, "unresolved": {"dependencies": []}}'

# Maven's version order, ported from maven-artifact's ComparableVersionTest:
# each list is ascending (--order) or all one version (--equal). Either mode
# prints the first pair out of order and exits 1, or prints nothing and exits 0.
order() {
	local want=$1 label=$2 got=0
	shift 2
	runs=$((runs + 1))
	"${SCRIPT_DIR}/deps-check.sh" "$@" > "${TMP}/out" 2>&1 || got=$?
	if [ "${got}" -ne "${want}" ]; then
		echo "FAIL: ${label} exited ${got}, want ${want}:"
		cat "${TMP}/out"
		fails=$((fails + 1))
	else
		echo "ok:   ${label} -> ${want}"
	fi
}

order 0 VERSIONS_QUALIFIER --order 1-alpha2snapshot 1-alpha2 1-alpha-123 1-beta-2 1-beta123 \
	1-m2 1-m11 1-rc 1-cr2 1-rc123 1-SNAPSHOT 1 1-sp 1-sp2 1-sp123 1-abc 1-def 1-pom-1 \
	1-1-snapshot 1-1 1-2 1-123
order 0 VERSIONS_NUMBER --order 2.0 2-1 2.0.a 2.0.0.a 2.0.2 2.0.123 2.1.0 2.1-a 2.1b 2.1-c \
	2.1-1 2.1.0.1 2.2 2.123 11.a2 11.a11 11.b2 11.b11 11.m2 11.m11 11 11.a 11b 11c 11m
order 0 "1.0-1 < 1.0.1" --order 1.0-1 1.0.1
order 1 "1.0.1 < 1.0-1 is refused" --order 1.0.1 1.0-1
order 0 "trailing zeros and release aliases" --equal 1 1.0 1.0.0 1-0 1.0-0 1ga 1release 1final 1-ga
order 0 "a is alpha" --equal 1a 1-a 1.0-a 1.0.0-a 1.0a 1.0.0a
order 0 "case and the alpha alias" --equal 1a1 1-alpha-1 1A1
order 0 "cr is rc" --equal 1cr 1rc
order 1 "1 = 1.1 is refused" --equal 1 1.1

[ "${fails}" -eq 0 ] || { echo "deps-check-test: ${fails} of ${runs} failed"; exit 1; }
echo "deps-check-test: all ${runs} passed"
