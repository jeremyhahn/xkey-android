#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2154 # workflow text is matched literally; extract assigns by name
# code-review-test.sh -- regression fixtures for .github/workflows/code-review.yml
# (template v5.10.10 and v5.10.11).
#
# pull_request_target runs the base branch's copy of the workflow, so a change
# to it is never exercised by its own pull request's review run. These
# fixtures run the changed programs offline instead. The code under test is
# read out of the workflow by marker, never copied: each start marker must be
# found exactly once, or the test stops with FATAL (exit 9) and measures
# nothing. Nothing reaches the network: forge reads are stubbed functions, and
# curl on PATH is a stub that fails the run if anything calls it.
#
#   A. Twins are runs of the same pull request: the run-name, the guard's read
#      of its own run's display_title, and the twin filter (keeps a run of the
#      same PR, drops this run and another PR's run on the same sha).
#   B. Owner-resume freshness, on GitHub and Gitea timeline fixtures.
#   C. The resume marker is written and read back; the reconcile block takes
#      a leftover label off and keeps a fresh one.
#   D. api_all (both copies) joins every page through stdin, past the 128 KiB
#      argument limit, and fails closed on a failed or unreadable page.
#
# Needs bash and jq (the lint-gates job has no python3).
# CODE_REVIEW_WORKFLOW overrides the workflow path (for a mutation check).
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
WORKFLOW=${CODE_REVIEW_WORKFLOW:-"${ROOT}/.github/workflows/code-review.yml"}
T=$(mktemp -d)
trap 'rm -rf "${T}"' EXIT
REVIEWER=agent-codex
SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
OTHER_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

fatal() {
	echo "FATAL: $*" >&2
	exit 9
}
command -v jq > /dev/null || fatal "jq is not on PATH"
[ -r "${WORKFLOW}" ] || fatal "cannot read ${WORKFLOW}"

# No network: curl on PATH records the call and fails.
mkdir -p "${T}/bin"
printf '#!/bin/sh\necho "curl $*" >> "%s/curl.log"\nexit 99\n' "${T}" > "${T}/bin/curl"
chmod +x "${T}/bin/curl"
export PATH="${T}/bin:${PATH}"

# extract VAR FILE START END WHAT: VAR is the text of FILE between START,
# which must occur exactly once, and the first END after it.
extract() {
	local got
	got=$(jq -Rrsj --arg s "$3" --arg e "$4" '
		split($s) | if length != 2 then error("start marker found \(length - 1) times, want 1") else .[1] end
		| split($e) | if length < 2 then error("no end marker after the start marker") else .[0] end' "$2") ||
		fatal "$5: not found exactly once in ${2##*/}"
	printf -v "$1" '%s' "${got}"
}
# need_once FILE TEXT WHAT: TEXT occurs exactly once in FILE.
need_once() {
	local n
	n=$(jq -Rrs --arg s "$2" 'split($s) | length - 1' "$1")
	[ "${n}" = 1 ] || fatal "$3: found ${n} times in ${1##*/}, want 1"
}
# pos FILE TEXT: the offset of TEXT's first occurrence in FILE, or -1.
pos() { jq -Rrs --arg s "$2" 'split($s) | if length < 2 then -1 else .[0] | length end' "$1"; }
# count_re FILE REGEX: how many times REGEX matches in FILE.
count_re() { jq -Rrs --arg r "$2" '[match($r; "g")] | length' "$1"; }

fails=0 total=0
check() { # name got want
	total=$((total + 1))
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		fails=$((fails + 1))
		echo "FAIL $1: got '$2', want '$3'"
	fi
}
contains() { [[ $1 == *"$2"* ]]; }
ends_with() { [[ $1 == *"$2" ]]; }
before() { [ "$1" -ge 0 ] && [ "$1" -lt "$2" ]; } # offset $1 is found and precedes $2
yn() { if "$@"; then echo yes; else echo no; fi; }

extract GUARD "${WORKFLOW}" $'\n      - name: Check the container, the request, the head and any standing verdict\n' \
	$'\n      - ' "the guard step"
printf '%s\n' "${GUARD}" > "${T}/guard.txt"
extract POST "${WORKFLOW}" $'\n      - name: Post the verdict\n' $'\n      - ' "the posting step"
printf '%s\n' "${POST}" > "${T}/post.txt"
extract OGUARD "${WORKFLOW}" \
	$'\n      - name: Check the token, the request, the head, any standing verdict and the model\n' \
	$'\n      - ' "the opencode guard step"
printf '%s\n' "${OGUARD}" > "${T}/oguard.txt"

# ---- A: the twin filter -----------------------------------------------------
extract run_name "${WORKFLOW}" $'\nrun-name: "' $'"\n' "the top-level run-name"
check "A the run-name names the PR number" "$(yn contains "${run_name}" '${{ github.event.pull_request.number }}')" yes
check "A the run-name names the base ref" "$(yn contains "${run_name}" '${{ github.event.pull_request.base.ref }}')" yes
check "A the run-name names the head sha" "$(yn contains "${run_name}" '${{ github.event.pull_request.head.sha }}')" yes
rn=$(pos "${WORKFLOW}" $'\nrun-name: ')
jb=$(pos "${WORKFLOW}" $'\njobs:')
check "A the run-name is top level (before jobs:)" "$(yn before "${rn}" "${jb}")" yes
need_once "${T}/guard.txt" 'me_run=$(gha "/actions/runs/$GITHUB_RUN_ID")' "the guard's read of its own run"
extract my_title_prog "${T}/guard.txt" "my_title=\$(jq -r '" "' <<<\"\$me_run\")" "the guard's read of its run-name"
check "A the guard's run-name is its run's display_title" \
	"$(jq -r "${my_title_prog}" <<< '{"id": 500, "workflow_id": 3, "name": "Code Review", "display_title": "T"}')" T
check "A a run with no display_title gives no run-name" "$(jq -r "${my_title_prog}" <<< '{"id": 500}')" ""
check "A an empty run-name stops the guard" "$(yn contains "${GUARD}" '[ -n "$my_title" ] || die')" yes
extract expect "${T}/guard.txt" '[ "$my_title" = "' '" ] ||' "the guard's run-name check"
as_env=${run_name//'${{ github.event.pull_request.number }}'/'$PR_NUM'}
as_env=${as_env//'${{ github.event.pull_request.base.ref }}'/'$BASE_REF'}
as_env=${as_env//'${{ github.event.pull_request.head.sha }}'/'$EVENT_SHA'}
check "A the guard checks its run-name against the workflow's run-name" "${expect}" "${as_env}"
extract twins_prog "${T}/guard.txt" $'twins=$(jq -r --argjson me "$GITHUB_RUN_ID" --arg mine "$my_title" \'\n' \
	$'\' <<<"$runs")' "the twin filter"
check "A the twin filter does not read pull_requests" "$(yn contains "${twins_prog}" pull_requests)" no

mine="Code Review: PR #12 into main at ${SHA}"
twins() { jq -r --argjson me 500 --arg mine "${mine}" "${twins_prog}" <<< "$1"; }
twins_fail() { ! twins "$1" > /dev/null 2>&1; }
runs=$(jq -cn --arg m "${mine}" --arg s "${SHA}" --arg o "${OTHER_SHA}" '{workflow_runs: [
	{id: 500, display_title: $m},
	{id: 501, display_title: $m},
	{id: 502, display_title: "Code Review: PR #13 into release at \($s)"},
	{id: 503, display_title: "Code Review: PR #12 into main at \($o)"},
	{id: 504, display_title: "Code Review: PR #120 into main at \($s)"}]}')
out=$(twins "${runs}")
check "A only the same-PR twin is a twin (not self, not another PR on the same sha)" "${out//$'\n'/ }" 501
out=$(twins "$(jq -cn --arg m "${mine}" '{workflow_runs: [{id: 500, display_title: $m}]}')")
check "A alone: no twins" "${out}" ""
check "A a body with no workflow_runs is unreadable (jq fails)" "$(yn twins_fail '{"message": "Not Found"}')" yes

# ---- B: owner-resume freshness ----------------------------------------------
extract hist_prog "${T}/guard.txt" $'hist=$(jq -c --arg u "$REVIEWER" \'\n' $'\' <<<"$all")' "the hist parser"
extract vhist_prog "${T}/guard.txt" $'timeline=$(api_all "/issues/$PR_NUM/timeline?")\n            jq -c \'' \
	$'\' <<<"$hist" > "$WORK/resume-hist.json"' "the resume-hist projection"
extract ores_prog "${T}/guard.txt" \
	$'ores=$(jq -c --arg f "$FORGE" --slurpfile h "$WORK/resume-hist.json" \'\n' $'\' <<<"$timeline")' \
	"the owner-resume freshness program"

review() { # id at round [resume] [state]
	local body="<!-- codex-review:verdict head=${SHA} round=$3${4:+ resume=$4} -->"$'\n'"## Codex review"
	jq -cn --argjson id "$1" --arg at "$2" --arg u "${REVIEWER}" --arg b "${body}" --arg s "${SHA}" \
		--arg st "${5:-REQUEST_CHANGES}" '{id: $id, user: {login: $u}, state: $st, body: $b, commit_id: $s, submitted_at: $at}'
}
arr() { if [ $# -eq 0 ]; then echo '[]'; else printf '%s\n' "$@" | jq -cs .; fi; }
gh_add() { # id at [name] [event]; at "-" is a JSON null
	jq -cn --argjson id "$1" --arg at "$2" --arg n "${3:-owner-resume}" --arg e "${4:-labeled}" \
		'{id: $id, event: $e, label: {name: $n}, created_at: (if $at == "-" then null else $at end)}'
}
gt_add() { # id at [body] [name]
	jq -cn --argjson id "$1" --arg at "$2" --arg b "${3-1}" --arg n "${4:-owner-resume}" \
		'{id: $id, type: "label", body: $b, label: {name: $n}, created_at: $at}'
}
hist_of() { jq -c --arg u "${REVIEWER}" "${hist_prog}" <<< "$1"; }
freshness() { # forge reviews timeline
	hist_of "$2" > "${T}/hist.json"
	jq -c "${vhist_prog}" "${T}/hist.json" > "${T}/resume-hist.json"
	jq -c --arg f "$1" --slurpfile h "${T}/resume-hist.json" "${ores_prog}" <<< "$3"
}
fresh() { freshness "$@" | jq -r '"\(.fresh) \(.id // "-") \(.why // "-")"'; }

R7=$(review 7 2026-11-09T10:00:00Z 4)
R9=$(review 9 2026-11-09T10:09:00Z 5)
R11=$(review 11 2026-11-09T10:20:00Z 1 80)
V=$(arr "${R7}" "${R9}")
CONSUMED=$(arr "${R7}" "${R9}" "${R11}")

check "B GitHub: an addition after the latest verdict is fresh" \
	"$(fresh github "${V}" "$(arr "$(gh_add 61 2026-11-09T11:00:00Z)")")" "true 61 -"
check "B GitHub: an addition before the latest verdict is a leftover" \
	"$(fresh github "${V}" "$(arr "$(gh_add 61 2026-11-09T10:05:00Z)")")" "false 61 stale"
check "B GitHub: an addition in the latest verdict's second is a leftover" \
	"$(fresh github "${V}" "$(arr "$(gh_add 61 2026-11-09T10:09:00Z)")")" "false 61 stale"
check "B GitHub: the latest addition decides (a new one after an old one)" \
	"$(fresh github "${V}" "$(arr "$(gh_add 70 2026-11-09T11:00:00Z)" "$(gh_add 60 2026-11-09T09:00:00Z)")")" "true 70 -"
check "B GitHub: the latest addition decides (by time, not by timeline id)" \
	"$(fresh github "${V}" "$(arr "$(gh_add 60 2026-11-09T11:00:00Z)" "$(gh_add 70 2026-11-09T09:59:00Z)")")" "true 60 -"
check "B GitHub: an unlabeled event is not an addition" \
	"$(fresh github "${V}" "$(arr "$(gh_add 61 2026-11-09T09:00:00Z)" "$(gh_add 62 2026-11-09T11:00:00Z owner-resume unlabeled)")")" \
	"false 61 stale"
check "B GitHub: another label is not an owner-resume addition" \
	"$(fresh github "${V}" "$(arr "$(gh_add 62 2026-11-09T11:00:00Z needs-owner)")")" "false - undated"
check "B an addition whose id a marker records as resume= is a leftover" \
	"$(fresh github "${CONSUMED}" "$(arr "$(gh_add 80 2026-11-09T10:30:00Z)")")" "false 80 consumed"
check "B ... and the leftover names the round that consumed it" \
	"$(freshness github "${CONSUMED}" "$(arr "$(gh_add 80 2026-11-09T10:30:00Z)")" | jq -r '.round')" 1
check "B no verdict yet: any datable addition is fresh" \
	"$(fresh github '[]' "$(arr "$(gh_add 61 2026-11-09T08:00:00Z)")")" "true 61 -"
check "B no addition in the timeline is not evidence" "$(fresh github "${V}" '[]')" "false - undated"
check "B an addition with no time is not evidence" \
	"$(fresh github "${V}" "$(arr "$(gh_add 61 -)")")" "false - undated"
check "B an addition with an unreadable time is not evidence" \
	"$(fresh github "${V}" "$(arr "$(gh_add 61 yesterday)")")" "false - undated"
check "B one undatable addition beside a fresh one is not evidence" \
	"$(fresh github "${V}" "$(arr "$(gh_add 61 2026-11-09T11:00:00Z)" "$(gh_add 62 '')")")" "false - undated"
check "B a latest verdict with no time makes any addition a leftover" \
	"$(fresh github "$(arr "$(review 9 '' 5)")" "$(arr "$(gh_add 61 2026-11-09T11:00:00Z)")")" "false 61 stale"
check "B Gitea: an addition (body 1) after the latest verdict, in an offset, is fresh" \
	"$(fresh gitea "${V}" "$(arr "$(gt_add 61 2026-11-09T06:00:00-05:00)")")" "true 61 -"
check "B Gitea: an addition before the latest verdict, in an offset, is a leftover" \
	"$(fresh gitea "${V}" "$(arr "$(gt_add 61 2026-11-09T05:05:00-05:00)")")" "false 61 stale"
check "B Gitea: an addition in the latest verdict's second, in an offset, is a leftover" \
	"$(fresh gitea "${V}" "$(arr "$(gt_add 61 2026-11-09T05:09:00-05:00)")")" "false 61 stale"
check "B Gitea: fractional seconds and +HH:MM read" \
	"$(fresh gitea "${V}" "$(arr "$(gt_add 61 2026-11-09T12:00:00.123+01:00)")")" "true 61 -"
check "B Gitea: a removal (body \"\") is not an addition" \
	"$(fresh gitea "${V}" "$(arr "$(gt_add 61 2026-11-09T10:01:00Z)" "$(gt_add 62 2026-11-09T11:00:00Z '')")")" "false 61 stale"
check "B Gitea: only a removal is not evidence" \
	"$(fresh gitea "${V}" "$(arr "$(gt_add 62 2026-11-09T11:00:00Z '')")")" "false - undated"
check "B Gitea: a resume= leftover is consumed" \
	"$(fresh gitea "${CONSUMED}" "$(arr "$(gt_add 80 2026-11-09T05:30:00-05:00)")")" "false 80 consumed"
check "B Gitea: a GitHub-shaped labeled event is not a Gitea addition" \
	"$(fresh gitea "${V}" "$(arr "$(gh_add 61 2026-11-09T11:00:00Z)")")" "false - undated"
check "B GitHub: a Gitea-shaped label entry is not a GitHub addition" \
	"$(fresh github "${V}" "$(arr "$(gt_add 61 2026-11-09T11:00:00Z)")")" "false - undated"

# ---- C: the marker, the hist parser and the reconcile block -----------------
extract body_prog "${T}/post.txt" \
	$'--arg p "$PATCH_ID" --arg x "$HUNK_CTX" --arg r "$ROUND" --arg t "$stop" --arg o "$resume" \'\n' \
	$'\' \\\n' "the posting step's body program"
body() {
	jq -r --arg e REQUEST_CHANGES --arg s "${SHA}" --arg m m --arg f high --arg u https://example.invalid/run \
		--arg p "" --arg x "" --arg r 1 --arg t "" --arg o "$1" "${body_prog}" <<< '{"summary": "ok", "findings": []}'
}
b=$(body 4242)
check "C the marker carries resume= when the round started on the label" \
	"$(yn contains "${b}" "<!-- codex-review:verdict head=${SHA} round=1 resume=4242 -->")" yes
b0=$(body "")
check "C the marker has no resume= otherwise" \
	"$(yn contains "${b0}" "<!-- codex-review:verdict head=${SHA} round=1 -->")" yes
posted() { # id body
	jq -cn --argjson id "$1" --arg b "$2" --arg u "${REVIEWER}" --arg s "${SHA}" \
		'{id: $id, user: {login: $u}, state: "REQUEST_CHANGES", body: $b, commit_id: $s, submitted_at: "2026-11-09T12:00:00Z"}'
}
check "C the hist parser reads resume= back" \
	"$(hist_of "$(arr "$(posted 20 "${b}")")" | jq -r '.[0] | "\(.resume) \(.round)"')" "4242 1"
check "C the hist parser reads no resume= as \"\"" \
	"$(hist_of "$(arr "$(posted 20 "${b0}")")" | jq -c '.[0].resume')" '""'
check "C a resume= the post recorded is consumed on the next run, label still on" \
	"$(fresh github "$(arr "${R7}" "${R9}" "$(posted 30 "${b}")")" "$(arr "$(gh_add 4242 2026-11-09T11:00:00Z)")")" \
	"false 4242 consumed"
check "C the posting step reads the guard's owner_resume_id" \
	"$(yn contains "${POST}" 'OWNER_RESUME_ID: ${{ steps.guard.outputs.owner_resume_id }}')" yes
check "C the posting step's resume is OWNER_RESUME_ID only when it resumed on the label" \
	"$(yn contains "${POST}" $'if [ "$OWNER_RESUME" = label ]; then\n')$(yn contains "${POST}" 'resume=$OWNER_RESUME_ID')" yesyes
check "C the guard hands the fresh addition's id to the posting step" \
	"$(yn contains "${GUARD}" 'echo "owner_resume_id=$resume_id" >> "$GITHUB_OUTPUT"')" yes

# The reconcile block, run under bash with the forge stubbed.
extract block "${T}/guard.txt" $'\n          resume_id=""\n' '          # v5.10.7: THE OWNER RESUMES.' \
	"the owner-resume reconcile block"
check "C the reconcile block ends its if" "$(yn ends_with "${block}" $'\n          fi')" yes
rb=$(pos "${T}/guard.txt" $'\n          resume_id=""\n')
lb=$(pos "${T}/guard.txt" 'if [ "$done_rounds" -ge "$last_round" ]')
check "C the reconcile block is outside the round-limit branch (every run)" "$(yn before "${rb}" "${lb}")" yes
check "C the guard takes owner-resume off in one place only" "$(count_re "${T}/guard.txt" 'relabel "[^"]*" owner-resume')" 1
printf '%s\n' "${block}" > "${T}/block.txt"
extract case_txt "${T}/block.txt" $'case "$(jq -r \'.fresh\' <<<"$ores")" in\n' 'esac' "the reconcile case"
printf '%s\n' "${case_txt}" > "${T}/case.txt"
extract fresh_arm "${T}/case.txt" $'true)\n' ';;' "the fresh arm"
extract stale_arm "${T}/case.txt" $'false)\n' ';;' "the leftover arm"
check "C a fresh label is never taken off by the guard" "$(yn contains "${fresh_arm}" relabel)" no
check "C a leftover is taken off by the guard" "$(yn contains "${stale_arm}" 'relabel "" owner-resume')" yes

{
	printf '%s\n' 'set -euo pipefail' \
		'die() { echo "DIE: $*"; exit 7; }' \
		'api_all() { [ "$1" = "/issues/$PR_NUM/timeline?" ] || die "unexpected api_all $1"; : > "$WORK/timeline.read"; cat "$WORK/timeline.json"; }' \
		'relabel() { echo "RELABEL add=[$1] drop=[$2]"; }' \
		'WORK=$1; FORGE=$2; PR_NUM=12' \
		'labels=$(cat "$WORK/labels.json")' \
		'hist=$(cat "$WORK/hist.json")' \
		'resume_id=""'
	printf '%s\n' "${block}"
	printf '%s\n' '[ ! -e "$WORK/timeline.read" ] || echo "TIMELINE-READ"' \
		'echo "RESUME_ID=[$resume_id]"' \
		'echo "LABELS=$labels"'
} > "${T}/reconcile.sh"
mkdir -p "${T}/r"
RC=0 OUT=""
reconcile() { # forge labels reviews timeline
	printf '%s\n' "$2" > "${T}/r/labels.json"
	hist_of "$3" > "${T}/r/hist.json"
	printf '%s\n' "$4" > "${T}/r/timeline.json"
	rm -f "${T}/r/timeline.read"
	RC=0
	OUT=$(bash "${T}/reconcile.sh" "${T}/r" "$1" 2>&1) || RC=$?
}
reconcile github '["code-review","owner-resume"]' "${V}" "$(arr "$(gh_add 61 2026-11-09T10:05:00Z)")"
check "C reconcile: a leftover runs clean" "${RC}" 0
check "C reconcile: a leftover is taken off" "$(yn contains "${OUT}" 'RELABEL add=[] drop=[owner-resume]')" yes
check "C reconcile: ... the run counts it absent" \
	"$(yn contains "${OUT}" 'LABELS=["code-review"]')$(yn contains "${OUT}" 'RESUME_ID=[]')" yesyes
printf '%s\n' "${OUT}" > "${T}/r/out.txt"
check "C reconcile: ... and says so in one line" \
	"$(count_re "${T}/r/out.txt" '(?m)^Took a leftover owner-resume off PR 12 \(added before the latest verdict')" 1
reconcile gitea '["owner-resume"]' "${V}" "$(arr "$(gt_add 61 2026-11-09T06:00:00-05:00)")"
check "C reconcile: a fresh label stays on and gives its id" \
	"${RC} $(yn contains "${OUT}" RELABEL) $(yn contains "${OUT}" 'RESUME_ID=[61]') $(yn contains "${OUT}" 'LABELS=["owner-resume"]')" \
	"0 no yes yes"
reconcile github '["owner-resume"]' "${CONSUMED}" "$(arr "$(gh_add 80 2026-11-09T10:30:00Z)")"
check "C reconcile: a consumed addition is taken off, naming its round" \
	"${RC} $(yn contains "${OUT}" 'RELABEL add=[] drop=[owner-resume]') $(yn contains "${OUT}" 'consumed by the verdict of round 1')" \
	"0 yes yes"
reconcile gitea '["owner-resume"]' "${V}" "$(arr "$(gt_add 61 2026-11-09T05:09:00-05:00)")"
check "C reconcile: a same-second Gitea addition is taken off" \
	"${RC} $(yn contains "${OUT}" 'RELABEL add=[] drop=[owner-resume]') $(yn contains "${OUT}" 'RESUME_ID=[]')" "0 yes yes"
reconcile github '["owner-resume"]' "${V}" '[]'
check "C reconcile: an undatable label is taken off" \
	"${RC} $(yn contains "${OUT}" 'RELABEL add=[] drop=[owner-resume]')" "0 yes"
reconcile github '["code-review"]' "${V}" "$(arr "$(gh_add 61 2026-11-09T11:00:00Z)")"
check "C reconcile: no label, no timeline read, nothing taken off" \
	"${RC} $(yn contains "${OUT}" TIMELINE-READ) $(yn contains "${OUT}" RELABEL) $(yn contains "${OUT}" 'RESUME_ID=[]')" \
	"0 no no yes"

filed=$(pos "${T}/post.txt" 'echo "Posted $event on $EVENT_SHA as $REVIEWER."')
drop=$(pos "${T}/post.txt" 'relabel "" owner-resume')
check "C the posting step still takes owner-resume off only after the verdict is filed" \
	"$(yn before "${filed}" "${drop}")" yes

# ---- D: api_all reads every page, and fails closed --------------------------
A1_START=$'api_all() {\n            local page=1 all=\'[]\' got n size=limit=50\n'
A2_START=$'api_all() {\n            local page=1 all=\'[]\' got n\n'
extract a1 "${T}/guard.txt" "${A1_START}" $'\n          }\n' "the guard's api_all"
extract a2 "${T}/oguard.txt" "${A2_START}" $'\n          }\n' "the opencode guard's api_all"
mkpaging() { # file api_all-text
	{
		printf '%s\n' 'set -euo pipefail' 'shopt -s inherit_errexit' \
			'die() { echo "DIE: $*" >&2; exit 7; }' \
			'api() {' \
			'	[ "$1" = GET ] || die "unexpected method $1"' \
			'	printf "%s\n" "$2" >> "$WORK/urls"' \
			'	local p=${2##*&page=}' \
			'	[ ! -e "$WORK/fail-$p" ] || return 22' \
			'	if [ -e "$WORK/page-$p.json" ]; then cat "$WORK/page-$p.json"; else echo "[]"; fi' \
			'}' \
			'WORK=$1; FORGE=$2'
		printf '%s\n' "$2"
		printf '%s\n' 'api_all "/pulls/12/reviews?" > "$WORK/all.json"' 'echo DONE'
	} > "$1"
}
mkpaging "${T}/paging1.sh" "${A1_START}${a1}"$'\n          }'
mkpaging "${T}/paging2.sh" "${A2_START}${a2}"$'\n          }'
P="${T}/p"
# A page of 100 reviews of about 1 KiB each: two pages are past the 128 KiB
# that one argv argument may carry, which v5.10.10's --argjson join broke on.
bigpage() { jq -cn --argjson o "$1" '[range(0; 100) | {id: (. + $o), body: ("x" * 1000)}]'; }
paging() { # script forge [page-spec...]: page-spec N=big | N=small | N=html | N=object | N=fail
	local s=$1 f=$2 spec
	shift 2
	rm -rf "${P}"
	mkdir -p "${P}"
	for spec in "$@"; do
		case "${spec#*=}" in
		big) bigpage "$(((${spec%%=*} - 1) * 100))" > "${P}/page-${spec%%=*}.json" ;;
		small) echo '[{"id": 1}]' > "${P}/page-${spec%%=*}.json" ;;
		html) echo '<html>502 Bad Gateway</html>' > "${P}/page-${spec%%=*}.json" ;;
		object) echo '{"message": "Not Found"}' > "${P}/page-${spec%%=*}.json" ;;
		fail) : > "${P}/fail-${spec%%=*}" ;;
		esac
	done
	RC=0
	OUT=$(bash "${T}/${s}" "${P}" "${f}" 2>&1) || RC=$?
}
urls() { if [ -e "${P}/urls" ]; then jq -Rrs 'split("\n") | map(select(. != "")) | join(" ")' "${P}/urls"; fi; }
ids_ok() { jq -e '[.[].id] == [range(0; 300)]' "${P}/all.json" > /dev/null 2>&1; }
partial() { [ -s "${P}/all.json" ]; }

for c in "paging1.sh github per_page=100" "paging1.sh gitea limit=50" "paging2.sh gitea limit=50"; do
	read -r s f size <<< "${c}"
	w="D ${s%.sh} (${f})"
	paging "${s}" "${f}" 1=big 2=big 3=big
	check "${w}: three pages past 128 KiB are all read, in order" \
		"${RC} $(yn contains "${OUT}" DONE) $(yn ids_ok)" "0 yes yes"
	check "${w}: ... page by page until an empty page" "$(urls)" \
		"/pulls/12/reviews?&${size}&page=1 /pulls/12/reviews?&${size}&page=2 /pulls/12/reviews?&${size}&page=3 /pulls/12/reviews?&${size}&page=4"
	paging "${s}" "${f}" 1=small
	check "${w}: one page" "${RC} $(jq -c '[.[].id]' "${P}/all.json")" "0 [1]"
	paging "${s}" "${f}"
	check "${w}: no reviews is an empty list" "${RC} $(jq -c . "${P}/all.json")" "0 []"
	paging "${s}" "${f}" 1=big 2=big 3=fail 4=big
	check "${w}: a failed third page fails closed, no partial history" \
		"$(yn [ "${RC}" -ne 0 ]) $(yn contains "${OUT}" DONE) $(yn partial)" "yes no no"
	paging "${s}" "${f}" 1=fail
	check "${w}: a failed first page fails closed" \
		"$(yn [ "${RC}" -ne 0 ]) $(yn contains "${OUT}" DONE) $(yn partial)" "yes no no"
	paging "${s}" "${f}" 1=big 2=html 3=big
	check "${w}: an unreadable page (not JSON) fails closed" \
		"$(yn [ "${RC}" -ne 0 ]) $(yn contains "${OUT}" DONE) $(yn partial)" "yes no no"
	paging "${s}" "${f}" 1=small 2=object
	check "${w}: a page that is not a list fails closed" \
		"$(yn [ "${RC}" -ne 0 ]) $(yn contains "${OUT}" DONE) $(yn partial)" "yes no no"
done

check "nothing called curl" "$(yn [ ! -e "${T}/curl.log" ])" yes
echo "$((total - fails)) of ${total} passed"
[ "${fails}" -eq 0 ]
