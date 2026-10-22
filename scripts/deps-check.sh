#!/usr/bin/env bash
# The latest-version check, `make deps-check` (handbook ci-standard.md section 1,
# devops.md section 9). Fails when a library or Gradle plugin is behind a release
# older than 7 days; reports, without failing, one younger than that.
#
#   usage: scripts/deps-check.sh               run Gradle, then evaluate
#          scripts/deps-check.sh --report FILE evaluate a dependencyUpdates JSON report
#          scripts/deps-check.sh --order V...  exit 1 unless V... ascend in Maven's order
#          scripts/deps-check.sh --equal V...  exit 1 unless V... are one version
#
# This is the one stage that needs the network: Gradle asks the repositories
# for newer versions, and each candidate's release date is the Last-Modified of
# its POM on Google Maven, Maven Central or the Gradle plugin portal. It runs
# Gradle without --offline, whatever GRADLE_OFFLINE says.
#
# How a candidate is chosen: a stable version is compared with stable releases
# only (the init script and STABLE_RE agree); one already on a pre-release is
# compared with every release. Every release in maven-metadata.xml newer than
# the current version and not newer than the newest, by Maven's version order
# (MAVEN_JQ, a port of ComparableVersion), is dated; one older than DEPS_CHECK_GRACE_DAYS (7) fails the check.
# The newest must be among them. A report that is not a dependencyUpdates
# report, a repository that cannot be read, metadata without versions and a
# release without a date all fail the check: nothing is passed unread.
#
# Exemptions (devops.md section 9: a pin held below latest carries its reason):
# scripts/deps-check-exempt.txt, one line per library, '#' starts a comment:
#
#   group:name  reason, who decided, YYYY-MM-DD
#
# An exempt library is reported with its reason and never fails the check. A
# line without a reason is refused.
#
# Environment: GRADLEW (the Makefile's), DEPS_CHECK_REPOS (space-separated
# repository URLs), DEPS_CHECK_EXEMPT, DEPS_CHECK_GRACE_DAYS, DEPS_CHECK_PROTO
# (curl's --proto; the test sets it to allow file://).
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)
REPOS=${DEPS_CHECK_REPOS:-https://dl.google.com/dl/android/maven2 https://repo1.maven.org/maven2 https://plugins.gradle.org/m2}
EXEMPT=${DEPS_CHECK_EXEMPT:-${SCRIPT_DIR}/deps-check-exempt.txt}
GRACE_DAYS=${DEPS_CHECK_GRACE_DAYS:-7}
PROTO=${DEPS_CHECK_PROTO:-=https}
STABLE_RE='[.-]([Aa][Ll][Pp][Hh][Aa]|[Bb][Ee][Tt][Aa]|[Rr][Cc]|[Cc][Rr]|[Mm]|[Ee][Aa][Pp]|[Dd][Ee][Vv]|[Ss][Nn][Aa][Pp][Ss][Hh][Oo][Tt]|[Pp][Rr][Ee][Vv][Ii][Ee][Ww])[.0-9-]*$'

for tool in curl jq; do
	command -v "${tool}" > /dev/null || { echo "deps-check: ${tool} not found" >&2; exit 1; }
done

fetch() { curl -sSfL --proto "${PROTO}" --max-time 30 "$@"; }

non_stable() { [[ $1 =~ ${STABLE_RE} ]]; }

# exempt_reason group:name: prints the reason; 1 when not exempt, 2 when the
# line has no reason.
exempt_reason() {
	[ -f "${EXEMPT}" ] || return 1
	local key reason
	while read -r key reason; do
		case "${key}" in '' | '#'*) continue ;; esac
		[ "${key}" = "$1" ] || continue
		if [ -z "${reason}" ]; then
			return 2
		fi
		printf '%s\n' "${reason}"
		return 0
	done < "${EXEMPT}"
	return 1
}

# Maven's version order: org.apache.maven.artifact.versioning.ComparableVersion
# (Maven 3.8/3.9), ported to jq, which has the recursion it needs. A version
# is a list of items: '.' separates items, and '-' or a change between digit
# and letter opens a nested list for the rest. Numbers compare as numbers; a
# qualifier ranks alpha < beta < milestone < rc (= cr) < snapshot < "" (= ga
# = final = release) < sp < any other, the others alphabetically; a, b and m
# directly before a digit are alpha, beta and milestone. Against a missing
# item a number is 0 and a qualifier is "". A number is newer than a list,
# which is newer than a qualifier. Each list drops its trailing nulls (0, "",
# an empty list), looking past nested lists, so 1.0 = 1 and 1.0-ga = 1.
# scripts/deps-check-test.sh holds Maven's own ComparableVersionTest orders.
# shellcheck disable=SC2016  # a jq program: $a and the rest are jq's
MAVEN_JQ='
def mv_q: . as $q | (["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"] | index($q)) as $i
	| if $i == null then "7-\($q)" else "\($i)" end;
def mv_item($digit; $buf; $before_digit):
	if $digit then {i: ($buf | sub("^0+(?=.)"; ""))}
	else {s: ($buf
		| if $before_digit and length == 1 then ({a: "alpha", b: "beta", m: "milestone"}[.] // .) else . end
		| ({ga: "", final: "", release: "", cr: "rc"}[.] // .))}
	end;
def mv_null: . == [] or . == {i: "0"} or . == {s: ""};
def mv_norm: map(if type == "array" then mv_norm else . end)
	| reduce range(length - 1; -1; -1) as $k ({l: ., stop: false};
		if .stop then .
		elif (.l[$k] | mv_null) then .l |= del(.[$k])
		elif (.l[$k] | type) == "array" then .
		else .stop = true end)
	| .l;
def mv_add($item): .segs[(.segs | length) - 1] += [$item];
def mv_parse: ascii_downcase | explode | map([.] | implode)
	| reduce .[] as $c ({segs: [[]], buf: "", digit: false};
		if $c == "." or $c == "-" then
			mv_add(if .buf == "" then {i: "0"} else mv_item(.digit; .buf; false) end)
			| .buf = ""
			| if $c == "-" then .segs += [[]] else . end
		elif ($c | test("^[0-9]$")) then
			(if (.digit | not) and .buf != "" then mv_add(mv_item(false; .buf; true)) | .buf = "" | .segs += [[]] else . end)
			| .digit = true | .buf += $c
		else
			(if .digit and .buf != "" then mv_add(mv_item(true; .buf; false)) | .buf = "" | .segs += [[]] else . end)
			| .digit = false | .buf += $c
		end)
	| (if .buf != "" then mv_add(mv_item(.digit; .buf; false)) else . end)
	| reduce (.segs | reverse | .[]) as $s (null; if . == null then $s else $s + [.] end)
	| mv_norm;
def mv_sign: if . > 0 then 1 elif . < 0 then -1 else 0 end;
def mv_cmp($b):
	if type == "array" then
		if $b == null then first(.[] | mv_cmp(null) | select(. != 0)) // 0
		elif ($b | type) == "array" then
			. as $a
			| first(range(0; [length, ($b | length)] | max) as $k
				| if $a[$k] == null then ($b[$k] | mv_cmp(null) | 0 - .) else ($a[$k] | mv_cmp($b[$k])) end
				| select(. != 0)) // 0
		elif ($b | has("i")) then -1
		else 1 end
	elif has("i") then
		if $b == null then (if .i == "0" then 0 else 1 end)
		elif ($b | type) == "object" and ($b | has("i")) then
			if (.i | length) != ($b.i | length) then ((.i | length) - ($b.i | length) | mv_sign)
			elif .i == $b.i then 0 elif .i > $b.i then 1 else -1 end
		else 1 end
	else
		(.s | mv_q) as $p
		| if $b == null then (if $p == "5" then 0 elif $p > "5" then 1 else -1 end)
		elif ($b | type) == "object" and ($b | has("s")) then
			($b.s | mv_q) as $r | if $p == $r then 0 elif $p > $r then 1 else -1 end
		else -1 end
	end;
def mv_compare($a; $b): ($a | mv_parse) | mv_cmp($b | mv_parse);
'

# newer_releases current latest: of the versions on stdin, one per line, those
# newer than current and not newer than latest in Maven's order.
newer_releases() {
	jq -Rr --arg cur "$1" --arg latest "$2" "${MAVEN_JQ}"'
		select(. != "") | select(mv_compare(.; $cur) > 0 and mv_compare(.; $latest) <= 0)'
}

# age_days url: days since the file's Last-Modified (the last one, after redirects).
age_days() {
	local hdr lm t
	hdr=$(fetch -I "$1" 2> /dev/null) || return 1
	lm=$(tr -d '\r' <<< "${hdr}" | awk 'tolower($1) == "last-modified:" { sub(/^[^:]*: */, ""); v = $0 } END { print v }') || return 1
	[ -n "${lm}" ] || return 1
	t=$(date -d "${lm}" +%s) || return 1
	echo $(( ($(date +%s) - t) / 86400 ))
}

# check group name current latest: 0 pass, 1 fail; prints one line. It runs
# under `||`, so errexit is off: every fetch and parse is checked here.
check() {
	local g=$1 n=$2 cur=$3 latest=$4 repo base="" meta="" versions candidates v age reason rc young="" dated=""
	if reason=$(exempt_reason "${g}:${n}"); then
		echo "exempt  ${g}:${n} ${cur} (newest ${latest}): ${reason}"
		return 0
	elif [ $? -eq 2 ]; then
		echo "FAIL    ${g}:${n} ${cur}: exempted in ${EXEMPT} without a reason"
		return 1
	fi
	# The first repository that serves the metadata publishes the library. Not
	# found there (curl 22, an HTTP error; 37, no such file) moves on; any
	# other failure fails, rather than ask the next repository.
	for repo in ${REPOS}; do
		base="${repo}/${g//.//}/${n}"
		rc=0
		meta=$(fetch "${base}/maven-metadata.xml" 2> /dev/null) || rc=$?
		[ "${rc}" -eq 0 ] && break
		case ${rc} in
			22 | 37) meta="" ;;
			*)
				echo "FAIL    ${g}:${n} ${cur}: fetching ${base}/maven-metadata.xml failed (curl exit ${rc})"
				return 1
				;;
		esac
	done
	if [ -z "${meta}" ]; then
		echo "FAIL    ${g}:${n} ${cur}: no repository serves its maven-metadata.xml"
		return 1
	fi
	versions=$(grep -o '<version>[^<]*</version>' <<< "${meta}" | sed 's/<[^>]*>//g') || versions=""
	if [ -z "${versions}" ]; then
		echo "FAIL    ${g}:${n} ${cur}: ${base}/maven-metadata.xml lists no versions"
		return 1
	fi
	if ! grep -qxF -- "${latest}" <<< "${versions}"; then
		echo "FAIL    ${g}:${n} ${cur}: the newest, ${latest}, is not in ${base}/maven-metadata.xml"
		return 1
	fi
	if ! candidates=$(newer_releases "${cur}" "${latest}" <<< "${versions}"); then
		echo "FAIL    ${g}:${n} ${cur}: could not order the versions in ${base}/maven-metadata.xml"
		return 1
	fi
	while read -r v; do
		[ -n "${v}" ] || continue
		if non_stable "${v}" && ! non_stable "${cur}" && [ "${v}" != "${latest}" ]; then
			continue
		fi
		if ! age=$(age_days "${base}/${v}/${n}-${v}.pom"); then
			echo "FAIL    ${g}:${n} ${cur}: no release date for ${v} (Last-Modified of ${base}/${v}/${n}-${v}.pom)"
			return 1
		fi
		if [ "${age}" -ge "${GRACE_DAYS}" ]; then
			echo "FAIL    ${g}:${n} ${cur}: behind ${v}, released ${age} days ago (newest ${latest})"
			return 1
		fi
		young="${young:+${young}, }${v} (${age}d)"
		if [ "${v}" = "${latest}" ]; then dated=1; fi
	done <<< "${candidates}"
	if [ -z "${dated}" ]; then
		echo "FAIL    ${g}:${n} ${cur}: the newest, ${latest}, is not newer than ${cur} in Maven's version order"
		return 1
	fi
	echo "report  ${g}:${n} ${cur}: newer release under ${GRACE_DAYS} days old: ${young}"
	return 0
}

# The parts of a dependencyUpdates JSON report the gate reads, each present
# and of its type. Optional selectors would pass a report missing them.
REPORT_SHAPE='def dep: type == "object" and all(.group, .name, .version; type == "string" and length > 0);
	type == "object"
	and (.outdated | type) == "object" and (.outdated.dependencies | type) == "array"
	and (.unresolved | type) == "object" and (.unresolved.dependencies | type) == "array"
	and all(.unresolved.dependencies[]; dep)
	and all(.outdated.dependencies[]; dep and (.available | type) == "object"
		and ((.available.release // .available.milestone // .available.integration) | type) == "string")'

evaluate() {
	local report=$1 rc=0 g n cur latest err unresolved outdated
	if [ ! -s "${report}" ]; then
		echo "FAIL    no report at ${report}"
		return 1
	fi
	if ! err=$(jq -e "${REPORT_SHAPE}" "${report}" 2>&1 > /dev/null); then
		echo "FAIL    ${report} is not a dependencyUpdates report: it needs outdated.dependencies and unresolved.dependencies arrays of {group, name, version}, each outdated one with an available version"
		[ -z "${err}" ] || echo "        ${err}"
		return 1
	fi
	if ! unresolved=$(jq -r '.unresolved.dependencies[] | [.group, .name, .version] | @tsv' "${report}") \
		|| ! outdated=$(jq -r '.outdated.dependencies[]
			| [.group, .name, .version, (.available.release // .available.milestone // .available.integration)]
			| @tsv' "${report}"); then
		echo "FAIL    could not read ${report}"
		return 1
	fi
	while IFS=$'\t' read -r g n cur; do
		[ -n "${g}" ] || continue
		echo "FAIL    ${g}:${n} ${cur}: unresolved, so it could not be checked"
		rc=1
	done <<< "${unresolved}"
	while IFS=$'\t' read -r g n cur latest; do
		[ -n "${g}" ] || continue
		check "${g}" "${n}" "${cur}" "${latest}" || rc=1
	done <<< "${outdated}"
	[ "${rc}" -eq 0 ] && echo "deps-check: no library behind a release older than ${GRACE_DAYS} days"
	return "${rc}"
}

case ${1:-} in
	--report)
		evaluate "${2:?usage: $0 --report FILE}"
		exit
		;;
	--order | --equal)
		# For scripts/deps-check-test.sh: exit 0 when the versions are in
		# strictly ascending (--order) or equal (--equal) Maven order, compared
		# pairwise both ways; otherwise print the first pair that is not.
		mode=$1
		shift
		jq -nr --arg mode "${mode}" "${MAVEN_JQ}"'
			$ARGS.positional as $v
			| [range(0; $v | length) as $i | range(0; $v | length) as $j
				| (if $mode == "--equal" or $i == $j then 0 elif $i < $j then -1 else 1 end) as $want
				| mv_compare($v[$i]; $v[$j]) as $got
				| select($got != $want)
				| "\($v[$i]) vs \($v[$j]): \($got), want \($want)"]
			| if length == 0 then empty else (first + "\n" | halt_error(1)) end' --args "$@"
		exit
		;;
esac

# Run the plugin: its jar is checked against the pin before Gradle loads it.
# shellcheck source-path=SCRIPTDIR source=tool-pins.sh
. "${SCRIPT_DIR}/tool-pins.sh"
OUT="${REPO_ROOT}/build/deps-check"
mkdir -p "${OUT}"
JAR="${OUT}/gradle-versions-plugin-${DEPS_CHECK_PLUGIN_VERSION}.jar"
fetch -o "${JAR}" "https://plugins.gradle.org/m2/com/github/ben-manes/gradle-versions-plugin/${DEPS_CHECK_PLUGIN_VERSION}/gradle-versions-plugin-${DEPS_CHECK_PLUGIN_VERSION}.jar"
echo "${DEPS_CHECK_PLUGIN_SHA256}  ${JAR}" | sha256sum -c --quiet - \
	|| { echo "deps-check: CHECKSUM MISMATCH for the gradle-versions-plugin jar" >&2; rm -f "${JAR}"; exit 1; }
rm -f "${OUT}/report.json"
# GRADLEW is a command line (e.g. "gradle --no-daemon"): split on purpose.
# gradle.properties turns on parallel execution and the configuration cache
# for every other build; dependencyUpdates supports neither. It fails under
# parallel execution ("run this task with --no-parallel"), and it reads
# Task.project at execution time, so Gradle discards its cache entry anyway.
# shellcheck disable=SC2086
DEPS_CHECK_PLUGIN_JAR="${JAR}" DEPS_CHECK_OUT="${OUT}" \
	${GRADLEW:-./gradlew} --no-parallel --no-configuration-cache \
	--init-script "${SCRIPT_DIR}/deps-check.init.gradle" dependencyUpdates > "${OUT}/gradle.log" 2>&1 \
	|| { tail -n 40 "${OUT}/gradle.log"; exit 1; }
evaluate "${OUT}/report.json"
