#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2154 # workflow text is matched literally; extract assigns by name
# Offline regression fixtures for .github/workflows/code-review.yml, extracted by marker; curl is stubbed. Needs bash and jq.
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

# extract VAR FILE START END WHAT: VAR is FILE's text between START (exactly once) and the next END.
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

# ---- F: the gate reads the twins once and never waits; curl and sleep are stubbed ----
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
live_pr() { # author head-repo: the live PR into main of o/r, labelled for review
	jq -cn --arg a "$1" --arg h "$2" '{base: {ref: "main", repo: {full_name: "o/r"}}, head: {repo: {full_name: $h}}, user: {login: $a}, labels: [{name: "code-review"}, {name: "task:ready"}]}'
}
TRUSTED_AUTHORS=$(sed -n "s/^  TRUSTED_AUTHORS: '\(.*\)'$/\1/p" "${WORKFLOW}")
TRUSTED_PR=$(sed -n "s/^  TRUSTED_PR: '\(.*\)'$/\1/p" "${WORKFLOW}")
gate_setup() { # a code change, no twin, no verdict
	rm -rf "${G}"
	mkdir -p "${G}"
	gput "/compare/${OTHER_SHA}...${SHA}" '{"files": [{"filename": "app/src/main/kotlin/A.kt"}]}'
	gput /actions/runs/500 '{"id": 500, "workflow_id": 3}'
	gput "${RUNS_Q}" '{"workflow_runs": []}'
	gput "${RUNS_P}" '{"workflow_runs": []}'
	gput /pulls/12 "$(live_pr xkey-android-agent[bot] o/r)"
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
		NON_CODE_PATHS='^docs/.+$' ROW_BRANCH='^row/[0-9]+-' HEAD_REF=row/1-x TRUSTED_AUTHORS="${TRUSTED_AUTHORS}" TRUSTED_PR="${TRUSTED_PR}" SCOPE_RESULT=success \
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

# (e) The live PR's base, read first and again with the holds.
gate_setup
gverdict APPROVED
gate_run
check "F an approved head reads the live PR four times (base, holds before the exemption, the row check, holds after the twins)" \
	"${RC} $(reads /pulls/12)" "0 4"
gate_setup
gverdict APPROVED
gput /pulls/12 '{"base": {"ref": "dev"}, "labels": [{"name": "code-review"}]}'
gate_run
check "F a PR retargeted off BASE_REF fails over an approval" \
	"${RC} $(yn contains "${OUT}" "PR 12 was retargeted from main to dev;") $(yn contains "${OUT}" "approved ${SHA}.")" "3 yes no"
gate_setup
gverdict APPROVED
gput /pulls/12 '{"labels": []}'
gate_run
check "F a live PR with no base fails over an approval" \
	"${RC} $(yn contains "${OUT}" "PR 12 was retargeted from main to no base;")" "3 yes"
gate_setup
gput "/compare/${OTHER_SHA}...${SHA}" '{"files": [{"filename": "docs/a.md"}]}'
gput /pulls/12 '{"base": {"ref": "dev"}, "labels": []}'
gate_run
check "F a PR retargeted off BASE_REF fails a docs-only change too" \
	"${RC} $(yn contains "${OUT}" "PR 12 was retargeted from main to dev;") $(yn contains "${OUT}" "no code changed")" "3 yes no"

# (f) The live hold fails closed and is read before the exemption.
gate_setup
gverdict APPROVED
gput /pulls/12 '{"base": {"ref": "main"}}'
gate_run
check "F a live PR with no label list fails closed over an approval" \
	"${RC} $(yn contains "${OUT}" "cannot read the labels of PR 12") $(yn contains "${OUT}" "approved ${SHA}.")" "3 yes no"
gate_setup
gverdict APPROVED
gput /pulls/12 '{"base": {"ref": "main"}, "labels": null}'
gate_run
check "F a live PR whose labels are null fails closed over an approval" \
	"${RC} $(yn contains "${OUT}" "cannot read the labels of PR 12")" "3 yes"
gate_setup
gput "/compare/${OTHER_SHA}...${SHA}" '{"files": [{"filename": "docs/a.md"}]}'
gate_run
check "F a docs-only change with no hold passes with no review" \
	"${RC} $(yn contains "${OUT}" "no code changed")" "0 yes"
for who in "outsider o/r" "xkey-android-agent[bot] x/r"; do
	gate_setup
	gput "/compare/${OTHER_SHA}...${SHA}" '{"files": [{"filename": "docs/a.md"}]}'
	gput /pulls/12 "$(live_pr ${who})"
	gate_run
	check "F a docs-only change from ${who} (an outside author or a fork) needs an approval" \
		"${RC} $(yn contains "${OUT}" "fork or an untrusted author") $(yn contains "${OUT}" "no code changed")" "3 yes no"
done
for hold in needs-owner needs-coordinator; do
	gate_setup
	gput "/compare/${OTHER_SHA}...${SHA}" '{"files": [{"filename": "docs/a.md"}]}'
	gput /pulls/12 "$(jq -cn --arg h "${hold}" '{base: {ref: "main"}, labels: [{name: "code-review"}, {name: $h}]}')"
	gate_run
	check "F a hold (${hold}) refuses an exempt change" \
		"${RC} $(yn contains "${OUT}" "PR 12 is on hold (${hold})") $(yn contains "${OUT}" "no code changed")" "3 yes no"
done
gate_setup
gverdict APPROVED
gput /pulls/12 '{"base": {"ref": "main"}, "labels": [{"name": "needs-owner"}]}'
gate_run
check "F a hold refuses an approval of the head" \
	"${RC} $(yn contains "${OUT}" "PR 12 is on hold (needs-owner)") $(yn contains "${OUT}" "approved ${SHA}.")" "3 yes no"
check "F the live hold is read before the exemption exit" \
	"$(yn before "$(pos <(printf '%s' "${gate}") $'\n          holds\n          n=$(jq \'length\' <<<"$files")\n')" \
		"$(pos <(printf '%s' "${gate}") 'no code changed')")" yes

# (g) get_all fails on a failed page, never a partial list.
gate_setup
gverdict APPROVED
gput "/pulls/12/reviews?&per_page=100&page=2" '[{"id": 99}]'
gfail "/pulls/12/reviews?&per_page=100&page=3"
gate_run
check "F a failed later page of reviews fails closed over an approval" \
	"${RC} $(yn contains "${OUT}" "GET /pulls/12/reviews?&per_page=100&page=3 answered HTTP 500") $(yn contains "${OUT}" "approved ${SHA}.")" "3 yes no"
gate_setup
gverdict APPROVED
gfail "/pulls/12/reviews?&per_page=100&page=2"
gate_run
check "F a failed second page of reviews fails closed over an approval" \
	"${RC} $(yn contains "${OUT}" "approved ${SHA}.")" "3 no"
check "F get_all returns 3 on a failed page" \
	"$(yn contains "${gate}" $'got=$(get "$1&$size&page=$page") || return 3\n')" yes
check "F get_all fails on a page count that is not a number" \
	"$(yn contains "${gate}" $'[[ $n =~ ^[0-9]+$ ]] || fail "GET $1 answered no page count"\n')" yes

# ---- G: a passing gate re-runs a newer twin's red gate (v5.12.7) ----------
# The gate's second step runs under bash against the same stub curl. A run
# list entry is "id:suite:status:title"; a run's gate is job <id>0 of it.
gjob_rr=$'\n      - name: Re-run a newer twin\'s failed gate on this head\n        if: success() && env.FORGE == \'github\'\n        run: |\n'
RR_END=$'done <<<"$newer"\n'
extract rerun "${WORKFLOW}" "${gjob_rr}" "${RR_END}" "the gate's handoff step"
check "G the gate's actions: is write, for the handoff" \
	"$(yn contains "${gjob}" $'\n    permissions:\n      contents: read\n      # v5.12.7: write, for the re-run of a newer twin\'s gate only.\n      actions: write\n      pull-requests: read\n    env:\n')" yes
check "G the handoff follows the gate step" \
	"$(yn before "$(pos "${WORKFLOW}" "${GATE_END}")" "$(pos "${WORKFLOW}" "${gjob_rr}")")" yes
# sleep advances SECONDS and, on its first call, swaps in the next fixtures.
{
	printf '%s\n' 'sleep() { echo "SLEPT $*"; SECONDS=$((SECONDS + $1)); if [ -d "$G/next" ]; then cp "$G"/next/* "$G"/; rm -rf "$G/next"; fi; }'
	printf '%s' "${rerun}${RR_END}"
} > "${T}/rerun.sh"
RR_LIST="/actions/workflows/3/runs?head_sha=${SHA}&per_page=100"
rr_setup() { # this run is 500 in suite 900; no other run
	rm -rf "${G}"
	mkdir -p "${G}"
	gput /actions/runs/500 '{"id": 500, "workflow_id": 3, "check_suite_id": 900}'
	gput "${RR_LIST}" '{"workflow_runs": []}'
}
rr_runs() { # id:suite:status:title...
	local spec
	gput "${RR_LIST}" "$(for spec in "$@"; do
		IFS=: read -r id suite status title <<<"${spec}"
		jq -cn --argjson id "${id}" --argjson s "${suite}" --arg st "${status}" --arg t "${title}" \
			'{id: $id, check_suite_id: $s, status: $st, display_title: $t}'
	done | jq -cs '{workflow_runs: .}')"
}
rr_gate() { # run-id status conclusion: that run's jobs, its gate job <id>0
	gput "/actions/runs/$1/jobs?per_page=100" "$(jq -cn --argjson id "$1" --arg s "$2" --arg c "$3" \
		'{jobs: [{id: ($id * 10 + 1), name: "Codex review", status: "completed", conclusion: "skipped"},
		         {id: ($id * 10), name: "Code Review (codex)", status: $s, conclusion: $c}]}')"
	gput "/actions/jobs/$1""0/rerun" '{}'
}
rr_run() {
	RC=0
	OUT=$(cd "${G}" && PATH="${T}/gbin:${PATH}" G="${G}" GH_API_TOKEN=t REPO_API="${GAPI}" \
		PR_NUM=12 EVENT_SHA="${SHA}" BASE_REF=main GITHUB_RUN_ID=500 HANDOFF_POLL_S=7 HANDOFF_WAIT_S="${RR_WAIT:-20}" \
		bash "${T}/rerun.sh" 2>&1) || RC=$?
}
rr_next() { mkdir -p "${G}/next"; printf '%s\n' "$2" > "${G}/next/$(gkey "$1").json"; } # path body, after the first sleep
rr_jobs() { # run-id review-status gate-status gate-conclusion
	gput "/actions/runs/$1/jobs?per_page=100" "$(jq -cn --argjson id "$1" --arg r "$2" --arg s "$3" --arg c "$4" \
		'{jobs: [{id: ($id * 10 + 1), name: "Codex review", status: $r, conclusion: null},
		         {id: ($id * 10), name: "Code Review (codex)", status: $s, conclusion: (if $c == "" then null else $c end)}]}')"
}
slept() { jq -Rn '[inputs | select(startswith("SLEPT "))] | length' <<<"${OUT}"; }
reruns() { jq -Rrs 'split("\n") | map(select(endswith("/rerun"))) | sort | join(" ")' "${G}/urls"; }
rr_other="Code Review: PR #12 into main at ${OTHER_SHA}"
rr_pr120="Code Review: PR #120 into main at ${SHA}"

# (a) A newer same-head run whose gate failed or was cancelled is re-run; an
# older run, another head's, another PR's and a newer green gate are not.
rr_setup
rr_runs "510:910:completed:${mine}" "511:911:completed:${mine}" "490:890:completed:${mine}" \
	"512:912:completed:${rr_other}" "513:913:completed:${rr_pr120}" "514:914:completed:${mine}"
rr_gate 510 completed failure
rr_gate 511 completed cancelled
rr_gate 490 completed failure
rr_gate 512 completed failure
rr_gate 513 completed failure
rr_gate 514 completed success
rr_run
check "G a pass re-runs only the newer same-head runs' red gates" \
	"${RC} $(reruns)" "0 /actions/jobs/5100/rerun /actions/jobs/5110/rerun"
check "G ... and says so" "$(yn contains "${OUT}" "Run 510 is newer on ${SHA} and its gate (job 5100) ended red: re-run")" yes
check "G ... a newer green gate is left alone" "$(yn contains "${OUT}" "Run 514: its gate did not end red; nothing to re-run.")" yes
# (b) A newer red gate still running is polled and re-run when it ends; past HANDOFF_WAIT_S the step fails (exit 5).
check "G the handoff's bound is 300 s and its poll 15 s by default" \
	"$(yn contains "${rerun}" $'HANDOFF_POLL_S=${HANDOFF_POLL_S:-15}\n          HANDOFF_WAIT_S=${HANDOFF_WAIT_S:-300}\n')" yes
rr_setup
rr_runs "510:910:in_progress:${mine}"
rr_gate 510 completed failure
rr_next /actions/runs/510 '{"id": 510, "status": "completed"}'
rr_run
check "G a newer red gate in a running run is re-run once the run ends" \
	"${RC} $(slept) [$(reruns)]" "0 1 [/actions/jobs/5100/rerun]"
check "G ... the wait says so and reads the run again" \
	"$(yn contains "${OUT}" "Run 510 is in_progress; reading it again in 7 s.") $(reads /actions/runs/510)" "yes 1"
rr_setup
rr_runs "510:910:in_progress:${mine}"
rr_gate 510 completed failure
gput /actions/runs/510 '{"id": 510, "status": "in_progress"}'
rr_run
check "G a newer red gate whose run never ends fails the step at the bound" \
	"${RC} $(slept) [$(reruns)] $(yn contains "${OUT}" "::error::Code Review (codex): run 510 on ${SHA} is still in_progress after the handoff's 20 s bound, so its gate (job 5100, red) is not re-run")" \
	"5 3 [] yes"
check "G ... and that is no warning" "$(yn contains "${OUT}" "::warning::")" no
rr_setup
rr_runs "510:910:in_progress:${mine}"
rr_gate 510 completed failure
gput /actions/runs/510 '{"id": 510, "status": "in_progress"}'
RR_WAIT=0 rr_run
check "G a zero bound fails at once on a red gate in a running run" "${RC} $(slept) [$(reruns)]" "5 0 []"
rr_setup
rr_runs "510:910:in_progress:${mine}"
rr_gate 510 completed failure
gfail /actions/runs/510
rr_run
check "G a failed read of the waited run is a warning, exit 0" \
	"${RC} $(yn contains "${OUT}" "::warning::Code Review (codex): GET /actions/runs/510 answered HTTP 500") [$(reruns)]" "0 yes []"
# A gate still running is read again until it ends; past the bound, a warning.
rr_setup
rr_runs "510:910:in_progress:${mine}"
rr_jobs 510 completed in_progress ""
rr_next /actions/runs/510 '{"id": 510, "status": "completed"}'
rr_next "/actions/runs/510/jobs?per_page=100" "$(jq -cn '{jobs: [{id: 5101, name: "Codex review", status: "completed", conclusion: "skipped"},
	{id: 5100, name: "Code Review (codex)", status: "completed", conclusion: "failure"}]}')"
rr_run
check "G a newer gate still running is waited for and re-run when it ends red" \
	"${RC} $(slept) [$(reruns)]" "0 1 [/actions/jobs/5100/rerun]"
rr_setup
rr_runs "510:910:in_progress:${mine}"
rr_jobs 510 completed in_progress ""
gput /actions/runs/510 '{"id": 510, "status": "in_progress"}'
rr_run
check "G a newer gate still running past the bound is a warning, exit 0" \
	"${RC} [$(reruns)] $(yn contains "${OUT}" "::warning::Code Review (codex): run 510's gate on ${SHA} is still running after the handoff's 20 s bound; it reads the verdict itself") $(yn contains "${OUT}" "::error::")" \
	"0 [] yes no"
# A newer run that reviews the head itself, or whose gate has not started, is
# left to its own gate at once: no wait, no re-run.
for rv in queued in_progress; do
	rr_setup
	rr_runs "510:910:in_progress:${mine}"
	rr_jobs 510 "${rv}" queued ""
	rr_run
	check "G a newer run whose Codex review is ${rv} is left to its own gate" \
		"${RC} $(slept) [$(reruns)] $(yn contains "${OUT}" "Run 510 reviews ${SHA} itself; its own gate reads that verdict.")" "0 0 [] yes"
done
for gs in queued waiting; do
	rr_setup
	rr_runs "510:910:in_progress:${mine}"
	rr_jobs 510 completed "${gs}" ""
	rr_run
	check "G a newer run whose gate is ${gs} is left to its own gate" \
		"${RC} $(slept) [$(reruns)] $(yn contains "${OUT}" "Run 510 has not run its gate yet; that gate reads this approval itself.")" "0 0 [] yes"
done
rr_setup
rr_runs "510:910:queued:${mine}"
gput "/actions/runs/510/jobs?per_page=100" '{"jobs": []}'
rr_run
check "G a queued newer run with no jobs yet is left to its own gate" \
	"${RC} $(slept) [$(reruns)] $(yn contains "${OUT}" "Run 510 has not run its gate yet;")" "0 0 [] yes"
rr_setup
rr_runs "510:910:completed:${mine}"
rr_gate 510 completed failure
rr_run
check "G a completed newer run is re-run with no wait" "${RC} $(slept) [$(reruns)]" "0 0 [/actions/jobs/5100/rerun]"
# (c) No newer run: nothing to do.
rr_setup
rr_runs "490:890:completed:${mine}"
rr_gate 490 completed failure
rr_run
check "G no newer run: the check stands" \
	"${RC} $(yn contains "${OUT}" "No newer run of PR 12 on ${SHA}; this gate's check stands.") [$(reruns)]" "0 yes []"
# (d) An API error is a warning and exits 0.
for broken in /actions/runs/500 "${RR_LIST}" "/actions/runs/510/jobs?per_page=100" /actions/jobs/5100/rerun; do
	rr_setup
	rr_runs "510:910:completed:${mine}"
	rr_gate 510 completed failure
	gfail "${broken}"
	rr_run
	check "G a failed ${broken%%\?*} is a warning, exit 0" \
		"${RC} $(yn contains "${OUT}" "::warning::Code Review (codex): GET ${broken} answered HTTP 500")$(yn contains "${OUT}" "::warning::Code Review (codex): POST ${broken} answered HTTP 500")" \
		"0 $(if [ "${broken}" = /actions/jobs/5100/rerun ]; then echo noyes; else echo yesno; fi)"
done
rr_setup
gput /actions/runs/500 '{"id": 500}'
rr_run
check "G an own run with no check suite is a warning, exit 0" \
	"${RC} $(yn contains "${OUT}" "::warning::Code Review (codex): cannot read this run's workflow and check suite")" "0 yes"

# ---- H: a new head cancels this PR's runs on an older head (v5.12.8) ------
# The supersede job's step runs under bash against the same stub curl. This
# run is 600 on ${SHA}; a run list entry is "id:head_sha:title".
extract sjob "${WORKFLOW}" $'\n  supersede:\n' $'\n    steps:\n' "the supersede job"
check "H supersede's token: actions: write and pull-requests: read only" \
	"$(yn contains "${sjob}" $'\n    permissions:\n      # The cancel only. No contents: nothing is checked out.\n      actions: write\n      pull-requests: read\n    env:\n')" yes
check "H supersede's timeout is 5 minutes" "$(yn contains "${sjob}" $'\n    timeout-minutes: 5\n')" yes
check "H supersede runs on GitHub for synchronize or reopened on an open PR" \
	"$(yn contains "${sjob}" $'\n    if: >-\n      github.server_url == \'https://github.com\' &&\n      github.event.pull_request.state == \'open\' &&\n      (github.event.action == \'synchronize\' || github.event.action == \'reopened\')\n')" yes
SUP_START=$'\n      - name: Cancel this PR\'s runs on an older head\n        run: |\n'
SUP_END=$'done <<<"$older"\n'
extract sup "${WORKFLOW}" "${SUP_START}" "${SUP_END}" "the supersede step"
printf '%s' "${sup}${SUP_END}" > "${T}/sup.sh"
sup_list() { printf '/actions/workflows/3/runs?event=pull_request_target&status=%s&per_page=100' "$1"; }
sup_setup() { # PR 12 open at ${SHA}; no run listed
	rm -rf "${G}"
	mkdir -p "${G}"
	gput /pulls/12 "$(jq -cn --arg s "${SHA}" '{state: "open", head: {sha: $s}}')"
	gput /actions/runs/600 '{"id": 600, "workflow_id": 3}'
	local st
	for st in queued in_progress waiting pending requested; do gput "$(sup_list "${st}")" '{"workflow_runs": []}'; done
}
sup_runs() { # status id:head_sha:title...
	local st=$1 spec
	shift
	gput "$(sup_list "${st}")" "$(for spec in "$@"; do
		IFS=: read -r id head title <<<"${spec}"
		jq -cn --argjson id "${id}" --arg h "${head}" --arg t "${title}" '{id: $id, head_sha: $h, display_title: $t}'
	done | jq -cs '{workflow_runs: .}')"
}
sup_jobs() { # run-id review-job-name status
	gput "/actions/runs/$1/jobs?per_page=100" "$(jq -cn --arg n "$2" --arg s "$3" \
		'{jobs: [{name: "Review scope", status: "completed"}, {name: $n, status: $s}]}')"
	gput "/actions/runs/$1/cancel" '{}'
}
sup_run() {
	RC=0
	OUT=$(cd "${G}" && PATH="${T}/gbin:${PATH}" G="${G}" GH_API_TOKEN=t REPO_API="${GAPI}" \
		PR_NUM=12 EVENT_SHA="${SHA}" GITHUB_RUN_ID=600 bash "${T}/sup.sh" 2>&1) || RC=$?
}
cancels() { [ -e "${G}/urls" ] || return 0; jq -Rrs 'split("\n") | map(select(endswith("/cancel"))) | join(" ")' "${G}/urls"; }
old="Code Review: PR #12 into main at ${OTHER_SHA}"

# (a) Queued or running runs of this PR on an older head are cancelled, each
# once; a same-head run (by head_sha or by run-name), another PR's run, this
# run, a newer run and a run whose review is in progress are not.
sup_setup
sup_runs queued "590:${OTHER_SHA}:${old}" "593:${SHA}:${old}" "595:${OTHER_SHA}:Code Review: PR #120 into main at ${OTHER_SHA}"
sup_runs in_progress "591:${OTHER_SHA}:${old}" "594:${OTHER_SHA}:${mine}" "596:${OTHER_SHA}:${old}" \
	"597:${OTHER_SHA}:${old}" "600:${OTHER_SHA}:${old}" "605:${OTHER_SHA}:${old}"
sup_runs waiting "590:${OTHER_SHA}:${old}" "598:${OTHER_SHA}:${old}"
sup_jobs 590 "Codex review" completed
sup_jobs 591 "Codex review" queued
sup_jobs 596 "Codex review" in_progress
sup_jobs 597 "Code Review (opencode)" in_progress
sup_jobs 598 "Code Review (opencode)" completed
for id in 593 594 595 600 605; do sup_jobs "${id}" "Codex review" queued; done
sup_run
check "H older-head runs of this PR are cancelled, each once" \
	"${RC} $(cancels)" "0 /actions/runs/590/cancel /actions/runs/591/cancel /actions/runs/598/cancel"
check "H ... a run whose review is in progress is left" \
	"$(yn contains "${OUT}" "Run 596: its review is in progress")$(yn contains "${OUT}" "Run 597: its review is in progress")" yesyes
check "H ... and each cancel is said" "$(yn contains "${OUT}" "Run 590 is on an older head of PR 12 than ${SHA}: cancelled.")" yes
# (b) Nothing to cancel.
sup_setup
sup_runs queued "593:${SHA}:${mine}"
sup_jobs 593 "Codex review" queued
sup_run
check "H a same-head run only: nothing is cancelled" \
	"${RC} [$(cancels)] $(yn contains "${OUT}" "No run of PR 12 on an older head is queued or running.")" "0 [] yes"
# (c) Not the live head, or the PR is closed: nothing is read or cancelled.
for pr in "{\"state\": \"open\", \"head\": {\"sha\": \"${OTHER_SHA}\"}}" "{\"state\": \"closed\", \"head\": {\"sha\": \"${SHA}\"}}"; do
	sup_setup
	sup_runs queued "590:${OTHER_SHA}:${old}"
	sup_jobs 590 "Codex review" queued
	gput /pulls/12 "${pr}"
	sup_run
	check "H $(jq -r '.state' <<<"${pr}") PR at $(jq -r '.head.sha[:4]' <<<"${pr}"): nothing to cancel" \
		"${RC} [$(cancels)] $(yn contains "${OUT}" "nothing to cancel.") $(reads "$(sup_list queued)")" "0 [] yes 0"
done
# (d) An API error is a warning and exits 0.
for broken in /pulls/12 /actions/runs/600 "$(sup_list pending)" "/actions/runs/590/jobs?per_page=100" /actions/runs/590/cancel; do
	sup_setup
	sup_runs queued "590:${OTHER_SHA}:${old}" "591:${OTHER_SHA}:${old}"
	sup_jobs 590 "Codex review" queued
	sup_jobs 591 "Codex review" queued
	gfail "${broken}"
	sup_run
	check "H a failed ${broken%%\?*} is a warning, exit 0, nothing cancelled past it" \
		"${RC} $(yn contains "${OUT}" "::warning::Cancel superseded runs: ") [$(cancels | jq -Rr --arg b "${broken}" 'split(" ") | map(select(. != $b and . != "")) | join(" ")')]" \
		"0 yes []"
done

# ---- I: which jobs take a runner, and the gate's name: `if:` expressions translated to jq ----
gh2jq() { # expression text on stdin -> jq program
	jq -Rrs '
		gsub("\\$\\{\\{|\\}\\}"; "")
		| gsub("(?<![\\w./])(?<p>(github|needs)\\.)"; ".\(.p)")
		| gsub("!contains\\((?<p>[a-z_.]+)\\.\\*\\.name, (?<v>\\x27[^\\x27]*\\x27)\\)"; "(any(\(.p)[]?; .name == \(.v)) | not)")
		| gsub("contains\\((?<p>[a-z_.]+)\\.\\*\\.name, (?<v>\\x27[^\\x27]*\\x27)\\)"; "any(\(.p)[]?; .name == \(.v))")
		| gsub("startsWith\\((?<p>[a-z_.]+), (?<v>\\x27[^\\x27]*\\x27)\\)"; "((\(.p) // \"\") | startswith(\(.v)))")
		| gsub("always\\(\\)"; "true") | gsub("&&"; " and ") | gsub("\\|\\|"; " or ")
		| gsub("\\x27"; "\"")'
}
# job_if JOB: the translated `if:` of JOB (folded or one line).
job_if() {
	jq -Rrs --arg j "$1" '
		split("\n  \($j):\n") | if length != 2 then error("job \($j) not found once") else .[1] end
		| capture("\n    if: (>-\n(?<f>(      [^\n]*\n)+)|(?<l>[^\n]*)\n)") | (.f // .l)' "${WORKFLOW}" | gh2jq
}
extract gname "${WORKFLOW}" $'\n    name: >-\n      ${{ ' $' }}\n    needs: [scope, review]\n' "the gate's name"
gname_jq=$(jq -nr --arg n "${gname}" '$n | gsub("\n *"; " ") | capture("^(?<c>.*) && \\x27(?<a>[^\\x27]*)\\x27 \\|\\| \\x27(?<b>[^\\x27]*)\\x27$")
	| "if \(.c) then \"\(.a)\" else \"\(.b)\" end"') || fatal "the gate's name is not C && 'A' || 'B'"
gname_jq=$(gh2jq <<<"${gname_jq}")
IF_SUP=$(job_if supersede) IF_SCOPE=$(job_if scope) IF_REVIEW=$(job_if review)
IF_OPEN=$(job_if review-opencode) IF_GATE=$(job_if gate)
check "I the gate's if: is the draft clause alone" \
	"$(jq -Rrs --arg s $'\n    if: >-\n      always() && github.event.pull_request.draft != true\n    # v5.12.2' 'split($s) | length - 1' "${WORKFLOW}")" 1
# ctx SERVER ACTION LABEL DRAFT: an event on PR 12 with its head in this repository.
ctx() {
	jq -cn --arg srv "$1" --arg a "$2" --arg l "$3" --argjson d "$4" '{
		github: {server_url: $srv, repository: "o/r", event: ({action: $a,
			pull_request: {draft: $d, state: "open", head: {repo: {full_name: "o/r"}},
				labels: ([{name: "code-review"}, {name: "task:ready"}] + (if $l == "" then [] else [{name: $l}] end) | unique)}}
			+ (if $a == "labeled" then {label: {name: $l}} else {} end))},
		needs: {scope: {outputs: {skip: "false", code: "true", row: "true"}}, review: {outputs: {agent: "opencode"}}}}'
}
b01() { if [ "$1" = true ]; then echo 1; else echo 0; fi; }
# jobs_for SERVER ACTION LABEL DRAFT: "scope review opencode supersede gate:name"
jobs_for() {
	local c
	c=$(ctx "$@")
	printf '%s %s %s %s %s:%s' \
		"$(b01 "$(jq -n --argjson x "$c" "\$x | (${IF_SCOPE})")")" \
		"$(b01 "$(jq -n --argjson x "$c" "\$x | (${IF_REVIEW})")")" \
		"$(b01 "$(jq -n --argjson x "$c" "\$x | (${IF_OPEN})")")" \
		"$(b01 "$(jq -n --argjson x "$c" "\$x | (${IF_SUP})")")" \
		"$(b01 "$(jq -n --argjson x "$c" "\$x | (${IF_GATE})")")" \
		"$(jq -nr --argjson x "$c" "\$x | (${gname_jq})")"
}
GH=https://github.com GT=https://gitea.example.org
CX="Code Review (codex)" NR="Code Review (not requested)"
dsfx() { if [ "$1" = true ]; then echo " (draft)"; fi; }
# event (action/label/draft) -> want on github.com
while IFS='|' read -r ev want; do
	IFS=/ read -r a l d <<<"${ev}"
	check "I github.com ${a}${l:+ ${l}}$(dsfx "${d}")" "$(jobs_for "${GH}" "${a}" "${l}" "${d}")" "${want}"
done <<EOF
opened//false|1 1 0 0 1:${CX}
opened//true|0 0 0 0 0:${NR}
ready_for_review//false|1 1 0 0 1:${CX}
synchronize//false|1 1 0 1 1:${CX}
synchronize//true|0 0 0 0 0:${NR}
reopened//false|1 1 0 1 1:${CX}
reopened//true|0 0 0 0 0:${NR}
labeled/code-review/false|1 1 0 0 1:${CX}
labeled/task:ready/false|1 1 0 0 1:${CX}
labeled/agent:opencode/false|1 1 0 0 1:${CX}
labeled/model:gpt-x/false|1 1 0 0 1:${CX}
labeled/effort:high/false|1 1 0 0 1:${CX}
labeled/dept:software/false|1 0 0 0 1:${CX}
labeled/ci:full/false|1 0 0 0 1:${CX}
labeled/task:in-progress/false|1 0 0 0 1:${CX}
labeled/needs-owner/false|1 0 0 0 1:${CX}
labeled/needs-coordinator/false|1 0 0 0 1:${CX}
labeled/code-review/true|0 0 0 0 0:${NR}
labeled/dept:software/true|0 0 0 0 0:${NR}
EOF
# The opencode job keeps the shared condition; supersede runs only on GitHub.
while IFS='|' read -r ev want; do
	IFS=/ read -r a l d <<<"${ev}"
	check "I gitea ${a}${l:+ ${l}}$(dsfx "${d}")" "$(jobs_for "${GT}" "${a}" "${l}" "${d}")" "${want}"
done <<EOF
opened//false|1 1 1 0 1:${CX}
synchronize//false|1 1 1 0 1:${CX}
labeled/agent:opencode/false|1 1 1 0 1:${CX}
labeled/dept:software/false|1 0 0 0 1:${CX}
opened//true|0 0 0 0 0:${NR}
EOF
# Invariants over every action, label and draft state: the gate posts the
# required name exactly when it runs, and every non-draft suite has it.
bad=""
for a in opened synchronize reopened ready_for_review edited labeled unlabeled; do
	for l in "" code-review task:ready agent:opencode dept:software ci:full needs-owner; do
		[ "${a}" = labeled ] || [ -z "${l}" ] || continue
		for d in false true; do
			got=$(jobs_for "${GH}" "${a}" "${l}" "${d}")
			gate_bit=${got:8:1} name=${got:10}
			if [ "${gate_bit}" = 1 ] && [ "${name}" != "${CX}" ]; then bad+=" ${a}/${l}/${d}:runs-as-${name}"; fi
			if [ "${gate_bit}" = 0 ] && [ "${name}" = "${CX}" ]; then bad+=" ${a}/${l}/${d}:skipped-as-required"; fi
			if [ "${d}" = false ] && [ "${gate_bit}${name}" != "1${CX}" ]; then bad+=" ${a}/${l}/${d}:no-required-context"; fi
			if [ "${d}" = true ] && [ "${got:0:7}" != "0 0 0 0" ]; then bad+=" ${a}/${l}/${d}:draft-takes-a-runner"; fi
			if [ "${d}" = false ] && [ "${got:0:1}" != 1 ]; then bad+=" ${a}/${l}/${d}:no-guard-for-the-gate"; fi
		done
	done
done
check "I a skipped gate never posts the required check; every non-draft suite carries it and its guard; a draft takes no runner" "[${bad}]" "[]"
# scope runs on every non-draft event of an open PR, never a closed one.
check "I scope's if: is the draft clause and the open state" \
	"$(jq -Rrs --arg s $'\n  scope:\n' 'split($s) | .[1] // ""' "${WORKFLOW}" | jq -Rrs --arg s $'\n    if: >-\n      github.event.pull_request.draft != true\n      && github.event.pull_request.state == \'open\'\n    # v5.12.3' 'split($s) | length - 1')" 1
closed_ctx=$(ctx "${GH}" labeled dept:software false | jq -c '.github.event.pull_request.state = "closed"')
check "I scope skips a closed PR" "$(b01 "$(jq -n --argjson x "${closed_ctx}" "\$x | (${IF_SCOPE})")")" 0
check "I review and review-opencode keep the shared condition (an unrelated label starts neither)" \
	"$(jobs_for "${GT}" labeled ci:full false | cut -c3-5)" "0 0"
# A fork's head never takes the codex runner.
fork_ctx=$(ctx "${GH}" opened "" false | jq -c '.github.event.pull_request.head.repo.full_name = "fork/r"')
check "I a fork's head starts no review" "$(b01 "$(jq -n --argjson x "${fork_ctx}" "\$x | (${IF_REVIEW})")")" 0

check "nothing called curl" "$(yn [ ! -e "${T}/curl.log" ])" yes
echo "$((total - fails)) of ${total} passed"
[ "${fails}" -eq 0 ]
