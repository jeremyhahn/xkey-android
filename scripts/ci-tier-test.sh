#!/usr/bin/env bash
# Tests ci.yml's tiers: integration runs on every pull request but a
# docs-only one, whatever its labels, and CI Gate, its run script read from
# the workflow itself, passes a skipped integration only on a docs-only PR.
# Needs bash only. `make ci-tier-test`.
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
CI="${ROOT}/.github/workflows/ci.yml"
T=$(mktemp -d)
trap 'rm -rf "${T}"' EXIT
fails=0
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
pass() { echo "PASS: $*"; }

# The integration job's if:.
want="if: \${{ !github.event.pull_request.draft && needs.preflight.outputs.docs_only != 'true' }}"
got=$(awk '/^  integration:$/ { job = 1; next } job && /^    if:/ { sub(/^    /, ""); print; exit }' "${CI}")
if [ "${got}" = "${want}" ]; then
	pass "integration runs on every event but a docs-only or draft PR"
else
	fail "integration's if: is ${got}, want ${want}"
fi

# CI Gate's run script, with the needs results filled in per case.
awk '
	/^      - name: Fail closed on any non-success$/ { step = 1; next }
	step && /^        run: \|$/ { run = 1; next }
	run && /^          / { print substr($0, 11); next }
	run && /^$/ { print ""; next }
	run { exit }
' "${CI}" > "${T}/gate.tmpl"
[ -s "${T}/gate.tmpl" ] || { echo "ci-tier-test: no CI Gate run script in ${CI}"; exit 1; }

# gate <name> <want: pass|fail> <docs only> <integration result>
gate() {
	sed -e "s/\${{ needs\.integration\.result }}/$4/" \
		-e 's/\${{ needs\.soak\.result }}/skipped/' \
		-e 's/\${{ needs\.[a-z-]*\.result }}/success/g' "${T}/gate.tmpl" > "${T}/gate.sh"
	local rc=0 out
	out=$(env -i PATH="${PATH}" DOCS_ONLY="$3" DISPATCH=false DRAFT=false bash -e "${T}/gate.sh" 2>&1) || rc=$?
	local got=pass
	[ "${rc}" = 0 ] || got=fail
	if [ "${got}" = "$2" ]; then pass "$1"; else fail "$1: gate ${got}, want $2: ${out}"; fi
}
gate "a code PR with integration green passes" pass false success
gate "a code PR with integration skipped fails" fail false skipped
gate "a docs-only PR with integration skipped passes" pass true skipped
gate "a code PR with integration failed fails" fail false failure

[ "${fails}" = 0 ] || { echo "ci-tier-test: ${fails} failed"; exit 1; }
echo "ci-tier-test: all passed"
