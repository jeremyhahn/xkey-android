#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2154 # workflow text is matched literally; extract assigns by name
# code-review-test.sh -- regression fixtures for .github/workflows/code-review.yml
# (template v5.10.10, v5.10.11, v5.12.5 and v5.12.6).
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
#   E. lock_wait (v5.12.5) and both of its callers, the Codex login refresh
#      and the review: each flock waits for what the job's budget has left
#      past $WORK/job-start, less what the job needs after the lock (normal
#      and large reviews, a wait past 600 s), and dies when no time is left or
#      the start time is unreadable or not a number. The clock (date +%s) and
#      flock are stubbed.
#   F. The gate (v5.12.6) reads the twins once and never waits: an APPROVED
#      head passes with a twin queued; otherwise a twin whose `Codex review`
#      is queued or in progress fails it at once (exit 3), naming the run; no
#      twin and no approval fails as before; a failed or unreadable list of
#      runs or jobs fails closed. Its timeout is 10 minutes. The gate's own
#      get() runs against a stub curl that answers from fixtures.
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

# ---- E: each review-lock wait is what the job's budget has left ------------
# lib.sh's JOB_BUDGET and lock_wait are its last lines; each caller is read
# from its lock_wait call through its flock line, and runs to a stub flock.
extract lw "${WORKFLOW}" $'\n          JOB_BUDGET=' $'\n          LIB\n' "lib.sh's JOB_BUDGET and lock_wait"
extract refresh_call "${WORKFLOW}" $'\n            wait_s=$(lock_wait ' $'\n              timeout -k 10 120 \\\n' \
	"the Codex login refresh's lock wait"
extract review_limit "${WORKFLOW}" $'\n          limit=1500\n' $'\n          fi\n' "the review's time limit"
extract review_call "${WORKFLOW}" $'\n          wait_s=$(lock_wait ' $'\n            timeout -k 30 "$limit" \\\n' \
	"the review's lock wait"
mklock() { # file caller-text
	{
		printf '%s\n' 'set -euo pipefail' 'shopt -s inherit_errexit' \
			'die() { echo "DIE: $*" >&2; exit 7; }' \
			'date() { if [ "$*" = +%s ]; then cat "$WORK/now"; else command date "$@"; fi; }' \
			'flock() { printf "%s\n" "$*" > "$WORK/flock"; }' \
			'WORK=$1; nfiles=$2; large=100; EFFORT=medium; CODEX_MASTER=$WORK/codex'
		printf 'JOB_BUDGET=%s\n' "${lw}"
		printf '%s\n' "$2" '              true' 'echo "DONE wait_s=$wait_s"'
	} > "$1"
}
mklock "${T}/lock-refresh.sh" "wait_s=\$(lock_wait ${refresh_call}"
mklock "${T}/lock-review.sh" \
	"limit=1500"$'\n'"${review_limit}"$'\n          fi\n'"wait_s=\$(lock_wait ${review_call}"
L="${T}/l"
S=1000000
lockrun() { # script job-start now nfiles; job-start "-" writes no file
	rm -rf "${L}"
	mkdir -p "${L}"
	[ "$2" = - ] || printf '%s\n' "$2" > "${L}/job-start"
	printf '%s\n' "$3" > "${L}/now"
	RC=0
	OUT=$(bash "${T}/$1" "${L}" "$4" 2>&1) || RC=$?
}
flocked() { if [ -e "${L}/flock" ]; then jq -Rrs 'rtrimstr("\n")' "${L}/flock"; else echo none; fi; }
lock_ok() { # name script job-start now nfiles want-wait
	lockrun "$2" "$3" "$4" "$5"
	check "$1" "${RC} $(flocked) $(yn contains "${OUT}" "DONE wait_s=$6")" \
		"0 -w $6 -E 75 ${L}/codex/.review.lock true yes"
}
lock_dies() { # name script job-start now nfiles message
	lockrun "$2" "$3" "$4" "$5"
	check "$1" "${RC} $(yn contains "${OUT}" "DIE: $6") $(yn contains "${OUT}" DONE) $(flocked)" "7 yes no none"
}
# The refresh needs 130 + 360 + 2730 + 440 = 3660 s of the 4500 s after the lock.
lock_ok "E refresh: 10 s in the lock waits 830 s, past the old 600" \
	lock-refresh.sh "${S}" $((S + 10)) 5 830
lock_ok "E refresh: 300 s in, 540 s" lock-refresh.sh "${S}" $((S + 300)) 5 540
lock_ok "E refresh: 839 s in, the last second" lock-refresh.sh "${S}" $((S + 839)) 5 1
lock_dies "E refresh: 840 s in, no time is left: dies before flock" lock-refresh.sh "${S}" $((S + 840)) 5 \
	"no time is left in the job's 4500 s to wait for ${L}/codex/.review.lock (it needs 3660 s after the lock)"
# A normal review (limit 1500) needs 1500 + 30 + 440 = 1970 s after the lock.
lock_ok "E review: a normal review 10 s in waits 2520 s" lock-review.sh "${S}" $((S + 10)) 5 2520
lock_ok "E review: a normal review 1000 s in waits 1530 s, past the old 600" \
	lock-review.sh "${S}" $((S + 1000)) 5 1530
lock_ok "E review: a normal review 2529 s in, the last second" lock-review.sh "${S}" $((S + 2529)) 5 1
lock_dies "E review: a normal review 2530 s in, no time is left: dies before flock" \
	lock-review.sh "${S}" $((S + 2530)) 5 \
	"no time is left in the job's 4500 s to wait for ${L}/codex/.review.lock (it needs 1970 s after the lock)"
# A large review (limit 2700) needs 2700 + 30 + 440 = 3170 s after the lock.
lock_ok "E review: a large review 500 s in waits 830 s, past the old 600" \
	lock-review.sh "${S}" $((S + 500)) 150 830
lock_ok "E review: a large review 1329 s in, the last second" lock-review.sh "${S}" $((S + 1329)) 150 1
lock_dies "E review: a large review 1330 s in, no time is left: dies before flock" \
	lock-review.sh "${S}" $((S + 1330)) 150 \
	"no time is left in the job's 4500 s to wait for ${L}/codex/.review.lock (it needs 3170 s after the lock)"
for s in lock-refresh.sh lock-review.sh; do
	lock_dies "E ${s%.sh}: an unreadable job-start dies before flock" "${s}" - "${S}" 5 \
		"cannot read the job's start time (${L}/job-start)"
	lock_dies "E ${s%.sh}: a non-numeric job-start dies before flock" "${s}" "${S}x" "${S}" 5 \
		"the job's start time (${L}/job-start) is not a number"
	lock_dies "E ${s%.sh}: an empty job-start dies before flock" "${s}" "" "${S}" 5 \
		"the job's start time (${L}/job-start) is not a number"
done

# ---- F: the gate reads the twins once and never waits (v5.12.6) -----------
# The gate's whole run script runs under bash, its own get() talking to a
# stub curl (first on PATH for these runs only) that answers each API path
# from a fixture file, HTTP 404 for a path with none and HTTP 500 for a path
# marked to fail. sleep is a function that stops the run: the gate waits for
# nothing.
extract gjob "${WORKFLOW}" $'\n  gate:\n' $'\n    steps:\n' "the gate job"
check "F the gate's timeout is 10 minutes" "$(yn contains "${gjob}" $'\n    timeout-minutes: 10\n')" yes
GATE_START=$'\n      - name: Require a Codex approval of the head, or a no-review change\n        run: |\n'
GATE_END=$'(ruling 589)" ;;\n          esac\n'
extract gate "${WORKFLOW}" "${GATE_START}" "${GATE_END}" "the gate step"
G="${T}/g"
GAPI=https://api.example.invalid/repos/o/r
mkdir -p "${T}/gbin"
printf '%s\n' '#!/usr/bin/env bash' \
	'out="" url=""' \
	'while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2 ;; *) url=$1; shift ;; esac; done' \
	'p=${url#"$REPO_API"}' \
	'printf "%s\n" "$p" >> "$G/urls"' \
	'k=${p//[^A-Za-z0-9]/_}' \
	'if [ -e "$G/fail-$k" ]; then : > "$out"; printf 500; exit 0; fi' \
	'if [ -e "$G/$k.json" ]; then cp "$G/$k.json" "$out"; printf 200; else echo "{\"message\": \"Not Found\"}" > "$out"; printf 404; fi' \
	> "${T}/gbin/curl"
chmod +x "${T}/gbin/curl"
{
	printf '%s\n' 'set -euo pipefail' 'sleep() { echo "SLEPT $*"; exit 8; }'
	printf '%s' "${gate}${GATE_END}"
} > "${T}/gate.sh"
gkey() { printf '%s' "${1//[^A-Za-z0-9]/_}"; }
gput() { printf '%s\n' "$2" > "${G}/$(gkey "$1").json"; } # path body
gfail() { : > "${G}/fail-$(gkey "$1")"; }                  # path
RUNS_Q="/actions/workflows/3/runs?head_sha=${SHA}&status=queued&per_page=100"
RUNS_P="/actions/workflows/3/runs?head_sha=${SHA}&status=in_progress&per_page=100"
REVIEWS="/pulls/12/reviews?&per_page=100&page=1"
gate_setup() { # a code change, no twin, no verdict
	rm -rf "${G}"
	mkdir -p "${G}"
	gput "/compare/${OTHER_SHA}...${SHA}" '{"files": [{"filename": "app/src/main/kotlin/A.kt"}]}'
	gput /actions/runs/500 '{"id": 500, "workflow_id": 3}'
	gput "${RUNS_Q}" '{"workflow_runs": []}'
	gput "${RUNS_P}" '{"workflow_runs": []}'
	gput /pulls/12 '{"labels": [{"name": "code-review"}, {"name": "task:ready"}]}'
	gput "${REVIEWS}" '[]'
	gput "/pulls/12/reviews?&per_page=100&page=2" '[]'
}
grun() { gruns "$1" "$2:$3"; } # list-path run-id title
gruns() { # list-path id:title...
	local path=$1 spec
	shift
	gput "${path}" "$(for spec in "$@"; do jq -cn --argjson id "${spec%%:*}" --arg t "${spec#*:}" '{id: $id, display_title: $t}'; done | jq -cs '{workflow_runs: .}')"
}
gjobs() { gput "/actions/runs/$1/jobs?per_page=100" "$(jq -cn --arg s "$2" '{jobs: [{name: "scope", status: "completed"}, {name: "Codex review", status: $s}]}')"; }
gverdict() { gput "${REVIEWS}" "$(arr "$(review 7 2026-11-09T10:00:00Z 1 "" "$1")")"; }
gate_run() {
	RC=0
	OUT=$(cd "${G}" && PATH="${T}/gbin:${PATH}" G="${G}" GH_API_TOKEN=t FORGE=github REVIEWER="${REVIEWER}" \
		REPO_API="${GAPI}" PR_NUM=12 EVENT_SHA="${SHA}" BASE_SHA="${OTHER_SHA}" BASE_REF=main \
		NO_REVIEW_PATHS='^docs/.+$' DOCS_PATHS='^docs/.+$' SCOPE_SKIP=false SCOPE_RESULT=success \
		REVIEW_RESULT=skipped GITHUB_RUN_ID=500 bash "${T}/gate.sh" 2>&1) || RC=$?
}
reads() { jq -Rrs --arg p "$1" 'split("\n") | map(select(. == $p)) | length' "${G}/urls"; }
twin_msg() { echo "the Codex review of ${SHA} runs in run $1; that run's gate posts this head's check (verdict here: $2;"; }

# (a) An APPROVED head passes, a twin queued or not.
gate_setup
grun "${RUNS_Q}" 501 "${mine}"
gjobs 501 queued
gverdict APPROVED
gate_run
check "F an approved head passes with a twin's review queued" \
	"${RC} $(yn contains "${OUT}" "${REVIEWER} approved ${SHA}.") $(yn contains "${OUT}" SLEPT)" "0 yes no"

# (b) Not approved while a twin's review of the head is queued or in progress:
# the gate fails at once (exit 3, no sleep), naming the twin.
gate_setup
grun "${RUNS_Q}" 501 "${mine}"
gjobs 501 queued
gate_run
check "F a twin's queued review fails the gate at once, naming the twin" \
	"${RC} $(yn contains "${OUT}" "$(twin_msg 501 NONE)") $(yn contains "${OUT}" SLEPT)" "3 yes no"
check "F ... each twin list is read once" "$(reads "${RUNS_Q}") $(reads "${RUNS_P}")" "1 1"
gate_setup
gruns "${RUNS_P}" "500:${mine}" "504:Code Review: PR #120 into main at ${SHA}" "502:${mine}"
gjobs 504 in_progress
gjobs 502 in_progress
gverdict REQUEST_CHANGES
gate_run
check "F a twin's review in progress fails the gate at once, naming that twin (not self, not another PR)" \
	"${RC} $(yn contains "${OUT}" "$(twin_msg 502 REQUEST_CHANGES)") $(yn contains "${OUT}" SLEPT)" "3 yes no"
gate_setup
grun "${RUNS_Q}" 501 "${mine}"
gjobs 501 queued
grun "${RUNS_P}" 502 "${mine}"
gjobs 502 in_progress
gate_run
check "F two twins: the gate names the first" "${RC} $(yn contains "${OUT}" "$(twin_msg 501 NONE)")" "3 yes"
gate_setup
grun "${RUNS_P}" 502 "${mine}"
gjobs 502 completed
gate_run
check "F a twin whose review has ended is no twin: no approval fails as before" \
	"${RC} $(yn contains "${OUT}" "no ${REVIEWER} approval of ${SHA}.") $(yn contains "${OUT}" "runs in run")" "3 yes no"

# (c) No twin and no approval fails as before.
gate_setup
gate_run
check "F no twin, no approval: the gate fails as before" \
	"${RC} $(yn contains "${OUT}" "no ${REVIEWER} approval of ${SHA}.") $(yn contains "${OUT}" "runs in run") $(yn contains "${OUT}" SLEPT)" \
	"3 yes no no"
gate_setup
gverdict REQUEST_CHANGES
gate_run
check "F no twin, changes requested: the gate fails as before" \
	"${RC} $(yn contains "${OUT}" "${REVIEWER} requested changes on ${SHA}")" "3 yes"

# (d) An API error listing runs or jobs fails closed, an approval or not.
for st in queued in_progress; do
	gate_setup
	gverdict APPROVED
	if [ "${st}" = queued ]; then gfail "${RUNS_Q}"; else gfail "${RUNS_P}"; fi
	gate_run
	check "F a failed list of the ${st} runs fails closed over an approval" \
		"${RC} $(yn contains "${OUT}" "cannot list the ${st} runs on ${SHA}") $(yn contains "${OUT}" "approved ${SHA}.")" "3 yes no"
done
gate_setup
gverdict APPROVED
gput "${RUNS_Q}" '<html>502 Bad Gateway</html>'
gate_run
check "F an unreadable list of runs fails closed over an approval" \
	"${RC} $(yn contains "${OUT}" "cannot list the queued runs on ${SHA}") $(yn contains "${OUT}" "approved ${SHA}.")" "3 yes no"
gate_setup
gverdict APPROVED
grun "${RUNS_Q}" 501 "${mine}"
gfail "/actions/runs/501/jobs?per_page=100"
gate_run
check "F a failed read of a twin's jobs fails closed over an approval" \
	"${RC} $(yn contains "${OUT}" "cannot read the jobs of run 501") $(yn contains "${OUT}" "approved ${SHA}.")" "3 yes no"
gate_setup
gverdict APPROVED
grun "${RUNS_P}" 501 "${mine}"
gput "/actions/runs/501/jobs?per_page=100" '<html>502 Bad Gateway</html>'
gate_run
check "F an unreadable list of a twin's jobs fails closed over an approval" \
	"${RC} $(yn contains "${OUT}" "cannot read the jobs of run 501") $(yn contains "${OUT}" "approved ${SHA}.")" "3 yes no"
gate_setup
gverdict APPROVED
gfail /actions/runs/500
gate_run
check "F a failed read of its own run fails closed over an approval" \
	"${RC} $(yn contains "${OUT}" "GET /actions/runs/500 answered HTTP 500") $(yn contains "${OUT}" "approved ${SHA}.")" "3 yes no"
gate_setup
gverdict APPROVED
gput /actions/runs/500 '{"id": 500}'
gate_run
check "F an own run with no workflow fails closed over an approval" \
	"${RC} $(yn contains "${OUT}" "cannot read this run's workflow") $(yn contains "${OUT}" "approved ${SHA}.")" "3 yes no"

check "nothing called curl" "$(yn [ ! -e "${T}/curl.log" ])" yes
echo "$((total - fails)) of ${total} passed"
[ "${fails}" -eq 0 ]
