#!/usr/bin/env bash
# Tests the closing-link parse revert-red-main.yml uses to reopen the issues a
# reverted PR closed and to copy them into a reland PR: its CLOSING_LINK and
# closes(), read from the workflow itself, against fixture PR bodies, and
# CLOSING_LINK against the grammar of automerge.yml's links(), which it must
# match verbatim. Needs bash and jq only. `make closing-links-test`.
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
WORKFLOW="${ROOT}/.github/workflows/revert-red-main.yml"
AUTOMERGE="${ROOT}/.github/workflows/automerge.yml"

# The env value and the shell function, as the workflow's run step sees them.
CLOSING_LINK="" fn="" in_fn=0
while IFS= read -r line; do
	t=${line#"${line%%[![:space:]]*}"}
	case ${t} in
	"CLOSING_LINK: '"*"'") CLOSING_LINK=${t#"CLOSING_LINK: '"} CLOSING_LINK=${CLOSING_LINK%"'"} ;;
	esac
	if [ "${in_fn}" = 1 ] || [[ ${t} == "closes() {"* ]]; then
		in_fn=1 fn+="${t}"$'\n'
		if [ "${t}" = "}" ]; then in_fn=0; fi
	fi
done < "${WORKFLOW}"
[ -n "${CLOSING_LINK}" ] || { echo "closing-links-test: no CLOSING_LINK in ${WORKFLOW}"; exit 1; }
[ -n "${fn}" ] || { echo "closing-links-test: no closes() in ${WORKFLOW}"; exit 1; }
eval "${fn}"

runs=0 fails=0
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }

# links() writes the regex as a jq string inside single quotes: each
# backslash doubled.
runs=$((runs + 1))
if ! grep -qF -- "scan(\"${CLOSING_LINK//\\/\\\\}\")" "${AUTOMERGE}"; then
	fail "CLOSING_LINK is not the grammar of automerge.yml's links(): ${CLOSING_LINK}"
fi

# expect name self body want: closes() on body, excluding self, prints want
# (the issue numbers, space-separated).
expect() {
	local got
	runs=$((runs + 1))
	got=$(printf '%s' "$3" | closes "$2" | tr '\n' ' ')
	got=${got% }
	[ "${got}" = "$4" ] || fail "$1: want '$4', got '${got}'"
}

expect "colon" 99 "Fixes: #123" "123"
expect "two spaces" 99 "Closes  #123" "123"
expect "tab" 99 $'resolves\t#4' "4"
expect "case" 99 "FIXED #11" "11"
expect "mid-line" 99 "This closes #12." "12"
expect "comma list: the keyword covers only #1" 99 "closes #1, #2" "1"
expect "one per line, sorted and unique" 99 $'Resolved #6\nfixes #5\nFix #5' "5 6"
expect "every keyword form" 99 "close #1 closes #2 closed #3 fix #4 fixes #5 fixed #6 resolve #7 resolves #8 resolved #9" "1 2 3 4 5 6 7 8 9"
expect "self" 99 "Closes #99 and fixes #100" "100"
expect "no link" 99 "See #123; refs #4" ""
expect "inside a word" 99 "Prefixes #7, unfixed #8" ""
expect "no whitespace" 99 "Closes#8" ""
expect "no hash" 99 "Fixes 123" ""
expect "empty body" 99 "" ""

[ "${fails}" -eq 0 ] || { echo "closing-links-test: ${fails} of ${runs} failed"; exit 1; }
echo "closing-links-test: all ${runs} passed"
