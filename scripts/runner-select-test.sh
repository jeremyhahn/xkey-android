#!/usr/bin/env bash
# Tests ci.yml's runner selection: the run script of preflight's `Balanced
# runner pool` step, read from the workflow itself, against a curl stub that
# answers the Actions API from files and logs every URL. Checks the pool each
# case picks (the less-used pool, a tie to the self-hosted pool), that a fork
# and every event but a push to main or a pull request stay hosted with no
# call, and that preflight's runs-on and the review scope job never send an
# event the self-hosted runners refuse to them. Needs bash and jq only.
# `make runner-select-test`.
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
CI="${ROOT}/.github/workflows/ci.yml"
REVIEW="${ROOT}/.github/workflows/code-review.yml"
T=$(mktemp -d)
trap 'rm -rf "${T}"' EXIT
fails=0
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
pass() { echo "PASS: $*"; }

# The step's run script, as the runner sees it.
awk '
	/^      - name: Balanced runner pool$/ { step = 1; next }
	step && /^        run: \|$/ { run = 1; next }
	run && /^          / { print substr($0, 11); next }
	run && /^$/ { print ""; next }
	run { exit }
' "${CI}" > "${T}/run.sh"
[ -s "${T}/run.sh" ] || { echo "runner-select-test: no Balanced runner pool run script in ${CI}"; exit 1; }

mkdir -p "${T}/bin"
cat > "${T}/bin/curl" << 'EOF'
#!/usr/bin/env bash
out=/dev/null url=""
while [ $# -gt 0 ]; do
	case $1 in
	-o) out=$2; shift 2 ;;
	-w | -H | --max-time) shift 2 ;;
	-*) shift ;;
	*) url=$1; shift ;;
	esac
done
echo "${url}" >> "${FAKE}/calls.log"
key=${url//[^A-Za-z0-9]/_}
if [ -f "${FAKE}/${key}" ]; then cp "${FAKE}/${key}" "${out}"; printf 200; else printf '{}' > "${out}"; printf 404; fi
EOF
chmod +x "${T}/bin/curl"

API=https://api.example/repos/o/r/actions
# fixture <queued jobs> <in-progress jobs>: run 7 holds every job, each given
# as label sets ("h" hosted, "s1" bigdisk, "s2" bigdisk-docker).
fixture() {
	rm -rf "${T}/fake"; mkdir -p "${T}/fake"; : > "${T}/fake/calls.log"
	local jobs="" l st
	for st in queued in_progress; do
		for l in ${1}; do
			case ${l} in
			h) labels='["ubuntu-latest"]' ;;
			s1) labels='["self-hosted","linux","x64","bigdisk"]' ;;
			s2) labels='["self-hosted","linux","x64","bigdisk-docker"]' ;;
			esac
			jobs="${jobs:+${jobs},}{\"run_id\":7,\"status\":\"${st}\",\"labels\":${labels}}"
		done
		shift
	done
	put() { local k=${1//[^A-Za-z0-9]/_}; printf '%s' "$2" > "${T}/fake/${k}"; }
	put "${API}/runs?status=queued&per_page=100&page=1" '{"total_count":0,"workflow_runs":[]}'
	put "${API}/runs?status=in_progress&per_page=100&page=1" '{"total_count":1,"workflow_runs":[{"id":7}]}'
	local n; n=$(jq -n "[${jobs}] | length")
	put "${API}/runs/7/jobs?filter=latest&per_page=100&page=1" "{\"total_count\":${n},\"jobs\":[${jobs}]}"
}

# pick <name> <want: hosted|self> <calls: yes|no> <event> <ref> <head repo> <queued> <in progress>
pick() {
	local name=$1 want=$2 calls=$3
	fixture "$7" "$8"
	: > "${T}/out"
	local log
	log=$(env -i PATH="${T}/bin:${PATH}" FAKE="${T}/fake" RUNNER_TEMP="${T}" GITHUB_OUTPUT="${T}/out" \
		SERVER=https://github.com EVENT="$4" REF="$5" HEAD_REPO="$6" REPO=o/r API="${API}" RUN_ID=1000 \
		JOB_TOKEN=t HS=12 C1=4 C2=4 bash -eo pipefail "${T}/run.sh" 2>&1) || { fail "${name}: the step exited non-zero: ${log}"; return; }
	local got=hosted
	grep -q '^runner=\["self-hosted","linux","x64","bigdisk"\]$' "${T}/out" && got=self
	local called=no
	[ -s "${T}/fake/calls.log" ] && called=yes
	if [ "${got}" != "${want}" ] || [ "${called}" != "${calls}" ]; then
		fail "${name}: picked ${got} (calls: ${called}), want ${want} (calls: ${calls}): ${log}"
	else
		pass "${name}"
	fi
}

M=refs/heads/main
pick "an idle repository: a tie goes self-hosted" self yes push "${M}" "" "" ""
pick "equal use goes self-hosted" self yes push "${M}" "" "" "h h h s1"
pick "hosted busier goes self-hosted" self yes push "${M}" "" "" "h h h"
pick "the self-hosted pool busier goes hosted" hosted yes push "${M}" "" "" "h s1"
pick "both full, equal queues: self-hosted" self yes push "${M}" "" "" "h h h h h h h h h h h h s1 s1 s1 s1"
pick "both full, more self-hosted queued: hosted" hosted yes push "${M}" "" "s1" "h h h h h h h h h h h h s1 s1 s1 s1"
pick "a same-repository pull request" self yes pull_request refs/pull/1/merge o/r "" ""
pick "a fork pull request" hosted no pull_request refs/pull/1/merge someone/r "" ""
pick "a same-repository pull_request_target" hosted no pull_request_target "${M}" o/r "" ""
pick "a schedule run" hosted no schedule "${M}" "" "" ""
pick "a workflow_dispatch run" hosted no workflow_dispatch "${M}" "" "" ""
pick "a push to another branch" hosted no push refs/heads/topic "" "" ""

# preflight takes CI_PREFLIGHT_RUNS_ON only on a push to main or a
# same-repository pull_request.
clause="((github.event_name == 'push' && github.ref == 'refs/heads/main') || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) && fromJSON(vars.CI_PREFLIGHT_RUNS_ON)"
if grep -A12 '^  preflight:$' "${CI}" | grep -F 'runs-on:' | grep -qF "${clause}"; then
	pass "preflight's runs-on takes the variable only on a push to main or a same-repository pull_request"
else
	fail "preflight's runs-on does not carry ${clause}"
fi
# The review scope job runs on pull_request_target, which the self-hosted
# runners refuse: it stays hosted on github.com.
scope=$(awk '/^  scope:$/ { job = 1; next } job && /^    runs-on:/ { print; exit }' "${REVIEW}")
if [ "${scope}" = "    runs-on: \${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}" ]; then
	pass "the review scope job stays on ubuntu-latest on github.com"
else
	fail "the review scope job's runs-on is not ubuntu-latest on github.com: ${scope}"
fi

[ "${fails}" = 0 ] || { echo "runner-select-test: ${fails} failed"; exit 1; }
echo "runner-select-test: all passed"
