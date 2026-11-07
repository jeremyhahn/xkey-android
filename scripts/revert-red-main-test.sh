#!/usr/bin/env bash
# Tests that revert-red-main.yml resumes a partial run: its
# run script, read from the workflow itself, against a fake forge (a curl stub
# answering the API from files) and a bare repository standing in for the
# remote (real git, behind a wrapper that logs every push). Each case starts
# from a red merge of PR #7, which closes issue #3, and checks what the run
# wrote. Needs bash, git and jq only. `make revert-red-main-test`.
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
WORKFLOW="${ROOT}/.github/workflows/revert-red-main.yml"
T=$(mktemp -d)
trap 'rm -rf "${T}" /tmp/revert-repo' EXIT
REAL_GIT=$(command -v git)
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

# The run step's script and the env values it reads, as the runner sees them.
in_run=0
while IFS= read -r line; do
	if [ "${in_run}" = 1 ]; then
		printf '%s\n' "${line#          }" >> "${T}/run.sh"
		continue
	fi
	t=${line#"${line%%[![:space:]]*}"}
	case ${t} in
	"run: |") in_run=1 ;;
	"GATE_CONTEXT: '"*"'" | "REVERT_STEPS: '"*"'" | "CLOSING_LINK: '"*"'" | "INFRA_MARKERS: '"*"'")
		v=${t#*: \'} v=${v%\'}
		export "${t%%:*}=${v}"
		;;
	esac
done < "${WORKFLOW}"
[ -s "${T}/run.sh" ] || { echo "revert-red-main-test: no run script in ${WORKFLOW}"; exit 1; }
[ -n "${REVERT_STEPS:-}" ] || { echo "revert-red-main-test: no REVERT_STEPS in ${WORKFLOW}"; exit 1; }

mkdir -p "${T}/bin"
# git: the real one; a push that succeeds is logged as "push <refspec>".
cat > "${T}/bin/git" << EOF
#!/usr/bin/env bash
rc=0; "${REAL_GIT}" "\$@" || rc=\$?
if [ "\${rc}" = 0 ]; then
	for a in "\$@"; do [ "\${a}" = push ] && echo "push \${*: -1}" >> "\${FAKE}/writes.log"; done
fi
exit "\${rc}"
EOF
# curl: the forge API over files in FAKE; every write that succeeds is logged.
cat > "${T}/bin/curl" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
out=/dev/null fmt="" method=GET data="" url=""
while [ $# -gt 0 ]; do
	case $1 in
	-o) out=$2; shift 2 ;;
	-w) fmt=$2; shift 2 ;;
	-X) method=$2; shift 2 ;;
	-H) shift 2 ;;
	-d) data=$2; shift 2 ;;
	-*) shift ;;
	*) url=$1; shift ;;
	esac
done
path=${url#"${REPO_API}"} query=""
case ${path} in *\?*) query=${path#*\?} path=${path%%\?*} ;; esac
g() { git --git-dir="${BARE}" "$@"; }
log() { echo "$*" >> "${FAKE}/writes.log"; }
reply() { # code [file] -> the body to -o, the code to -w
	if [ -n "${2:-}" ]; then cp "$2" "${out}"; else echo '{}' > "${out}"; fi
	if [ -n "${fmt}" ]; then printf '%s' "$1"; fi
	exit 0
}
# fail-get names one path whose GET answers 503, a failed read.
[ "${method}" != GET ] || [ "$(cat "${FAKE}/fail-get" 2>/dev/null)" != "${path}" ] || reply 503
case "${method} ${path}" in
"GET /actions/runs/${RED_RUN}") reply 200 "${FAKE}/run.json" ;;
"GET /actions/runs/${RED_RUN}/jobs") reply 200 "${FAKE}/jobs.json" ;;
GET\ /actions/jobs/*/logs) reply 200 "${FAKE}/job.log" ;;
GET\ /git/commits/*)
	sha=${path##*/}
	read -r -a p <<< "$(g rev-list --parents -n 1 "${sha}")"
	jq -n --arg m "$(g log -1 --format=%B "${sha}")" '{parents: ($ARGS.positional | map({sha: .})), commit: {message: $m}}' \
		--args "${p[@]:1}" > "${FAKE}/r.json"
	reply 200 "${FAKE}/r.json" ;;
GET\ /commits/*/statuses) reply 200 "${FAKE}/statuses.json" ;;
GET\ /commits/*/pull)
	sha=${path#/commits/} sha=${sha%/pull}
	[ -f "${FAKE}/pull-of-${sha}" ] || reply 404
	reply 200 "${FAKE}/pulls/$(< "${FAKE}/pull-of-${sha}").json" ;;
"GET /pulls")
	case "&${query}&" in *"&page=1&"*) jq -s 'sort_by(.number)' "${FAKE}"/pulls/*.json > "${FAKE}/r.json" ;; *) echo '[]' > "${FAKE}/r.json" ;; esac
	reply 200 "${FAKE}/r.json" ;;
"POST /pulls")
	head=$(jq -r '.head' <<< "${data}")
	[ "$(cat "${FAKE}/fail-head" 2>/dev/null)" != "${head}" ] || reply 503
	hsha=$(g rev-parse -q --verify "refs/heads/${head}") || reply 422
	n=$(< "${FAKE}/next"); echo $((n + 1)) > "${FAKE}/next"
	jq --argjson n "${n}" --arg s "${hsha}" '{number: $n, state: "open", merged: false, title, body, head: {ref: .head, sha: $s}, user: {login: "agent-xkey-android"}}' \
		<<< "${data}" > "${FAKE}/pulls/${n}.json"
	log "POST /pulls ${head} #${n}"
	reply 201 "${FAKE}/pulls/${n}.json" ;;
PATCH\ /pulls/* | PATCH\ /issues/*)
	[ "$(cat "${FAKE}/fail-patch" 2>/dev/null)" != "${path}" ] || reply 503
	;;&
PATCH\ /pulls/*)
	f="${FAKE}/pulls/${path#/pulls/}.json"
	jq -s '.[0] + .[1]' "${f}" - <<< "${data}" > "${f}.next" && mv "${f}.next" "${f}"
	log "PATCH /pulls/${path#/pulls/}"
	reply 201 "${f}" ;;
GET\ /pulls/*)
	f="${FAKE}/pulls/${path#/pulls/}.json"
	[ -f "${f}" ] || reply 404
	reply 200 "${f}" ;;
GET\ /branches/*)
	id=$(g rev-parse -q --verify "refs/heads/${path#/branches/}") || reply 404
	jq -n --arg id "${id}" '{commit: {id: $id}}' > "${FAKE}/r.json"
	reply 200 "${FAKE}/r.json" ;;
GET\ /issues/*/comments)
	f="${FAKE}/comments/$(basename "$(dirname "${path}")").json"
	[ -f "${f}" ] || echo '[]' > "${f}"
	reply 200 "${f}" ;;
POST\ /issues/*/comments)
	i=$(basename "$(dirname "${path}")") f="${FAKE}/comments/${i}.json"
	[ -f "${f}" ] || echo '[]' > "${f}"
	jq --argjson c "${data}" '. + [$c]' "${f}" > "${f}.next" && mv "${f}.next" "${f}"
	log "POST comment #${i}"
	reply 201 ;;
GET\ /issues/*)
	f="${FAKE}/issues/${path#/issues/}.json"
	[ -f "${f}" ] || reply 404
	reply 200 "${f}" ;;
PATCH\ /issues/*)
	f="${FAKE}/issues/${path#/issues/}.json"
	jq -s '.[0] + .[1]' "${f}" - <<< "${data}" > "${f}.next" && mv "${f}.next" "${f}"
	log "PATCH /issues/${path#/issues/}"
	reply 201 "${f}" ;;
esac
echo "curl stub: no route for ${method} ${path}" >&2
reply 404
EOF
chmod +x "${T}/bin/git" "${T}/bin/curl"

# setup case -> FAKE and BARE for a fresh case: main green at A, then PR #7
# (head F, closes #3) merged as M; main's CI red at M in a lint step.
setup() {
	export FAKE="${T}/$1/fake" BARE="${T}/$1/bare.git"
	local w="${T}/$1/work"
	mkdir -p "${FAKE}/pulls" "${FAKE}/issues" "${FAKE}/comments"
	: > "${FAKE}/writes.log"
	echo 100 > "${FAKE}/next"
	gw() { "${REAL_GIT}" -C "${w}" -c user.name=t -c user.email=t@t -c commit.gpgSign=false "$@"; }
	"${REAL_GIT}" init -q -b main "${w}"
	echo a > "${w}/a.txt"; gw add a.txt; gw commit -qm "A"
	gw checkout -qb feat
	echo b > "${w}/b.txt"; gw add b.txt; gw commit -qm "feature"
	F=$(gw rev-parse HEAD)
	gw checkout -q main
	echo c > "${w}/c.txt"; gw add c.txt; gw commit -qm "other"
	gw merge -q --no-ff feat -m "Merge feature (#7)"
	M=$(gw rev-parse HEAD) SHORT=${M:0:12}
	"${REAL_GIT}" init -q --bare "${BARE}"
	gw push -q "${BARE}" main "${F}:refs/pull/7/head"
	jq -n --arg s "${M}" '{event: "push", head_branch: "main", conclusion: "failure", head_sha: $s, html_url: "https://ci/run/1"}' > "${FAKE}/run.json"
	jq -n '{jobs: [{id: 11, name: "Lint", conclusion: "failure", steps: [{name: "make lint", conclusion: "failure"}]}]}' > "${FAKE}/jobs.json"
	echo "lint: 1 error" > "${FAKE}/job.log"
	jq -n --arg c "${GATE_CONTEXT}" '[{id: 1, context: $c, status: "success"}]' > "${FAKE}/statuses.json"
	echo 7 > "${FAKE}/pull-of-${M}"
	jq -n --arg s "${F}" '{number: 7, state: "closed", merged: true, title: "feature", body: "Adds b.\n\nCloses #3", head: {ref: "feat", sha: $s}}' > "${FAKE}/pulls/7.json"
	jq -n '{number: 3, state: "closed"}' > "${FAKE}/issues/3.json"
}

# run -> the run script against the case; rc in RC, output in OUT.
run() {
	RC=0
	OUT=$(cd "${T}" && PATH="${T}/bin:${PATH}" BOT=token REPO_API=https://forge.example.com/api/v1/repos/o/xkey-android \
		GIT_URL="${BARE}" SERVER=https://forge.example.com REPOSITORY=o/xkey-android RED_RUN=1 \
		AGENT_DOMAIN=example.com bash "${T}/run.sh" 2>&1) || RC=$?
}

runs=0 fails=0
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
writes() { grep -c -- "$1" "${FAKE}/writes.log" || true; } # pattern -> how many logged writes match
expect() { # case what got want
	runs=$((runs + 1))
	[ "$3" = "$4" ] || fail "$1: $2: want '$4', got '$3'${OUT:+ -- output: ${OUT}}"
}
expect_fresh() { # case: one of every write a full run makes
	expect "$1" "revert pushed" "$(writes "^push HEAD:refs/heads/revert/${SHORT}$")" 1
	expect "$1" "revert PR" "$(writes "^POST /pulls revert/${SHORT} ")" 1
	expect "$1" "reland pushed" "$(writes "^push ${F}:refs/heads/reland/7$")" 1
	expect "$1" "reland PR" "$(writes "^POST /pulls reland/7 ")" 1
	expect "$1" "issue reopened" "$(writes "^PATCH /issues/3$")" 1
	expect "$1" "issue comments" "$(writes "^POST comment #3$")" 1
}

# 1. A fresh run reverts, relands, reopens, and comments once each.
setup fresh; run
expect fresh "exit" "${RC}" 0
expect_fresh fresh
expect fresh "PR #7 comments (relanded, summary)" "$(writes "^POST comment #7$")" 2

# 4. A rerun after everything finished writes nothing.
before=$(wc -l < "${FAKE}/writes.log")
run
expect finished "exit" "${RC}" 0
expect finished "new writes" "$(($(wc -l < "${FAKE}/writes.log") - before))" 0
expect finished "summary" "$([[ ${OUT} == *"did: nothing; found done:"* ]] && echo yes)" yes

# 2. The revert PR POST failed after the push: the rerun opens the PR on the
# branch it finds, and finishes the rest.
setup pr-post; echo "revert/${SHORT}" > "${FAKE}/fail-head"; run
expect pr-post "first exit" "${RC}" 1
expect pr-post "first run's PR" "$(writes "^POST /pulls revert/")" 0
rm "${FAKE}/fail-head"; run
expect pr-post "rerun exit" "${RC}" 0
expect_fresh pr-post

# 3. The reland POST failed: the first run finishes the rest and fails naming
# it; the rerun opens it once and comments on the issue
# once.
setup reland; echo "reland/7" > "${FAKE}/fail-head"; run
expect reland "first exit" "${RC}" 1
expect reland "first run's error" "$([[ ${OUT} == *"::error::recovery incomplete: reland-pr#7"* ]] && echo yes)" yes
expect reland "first run's reland PR" "$(writes "^POST /pulls reland/7 ")" 0
expect reland "first run's issue reopened" "$(writes "^PATCH /issues/3$")" 1
rm "${FAKE}/fail-head"; run
expect reland "rerun exit" "${RC}" 0
expect_fresh reland
before=$(wc -l < "${FAKE}/writes.log"); run
expect reland "third run's writes" "$(($(wc -l < "${FAKE}/writes.log") - before))" 0

# 5. A foreign branch named revert/<short> is not overwritten.
setup foreign
"${REAL_GIT}" --git-dir="${BARE}" update-ref "refs/heads/revert/${SHORT}" "${F}"
run
expect foreign "exit" "${RC}" 1
expect foreign "message" "$([[ ${OUT} == *"is not the revert of ${SHORT}"* ]] && echo yes)" yes
expect foreign "writes" "$(wc -l < "${FAKE}/writes.log")" 0
expect foreign "branch" "$("${REAL_GIT}" --git-dir="${BARE}" rev-parse "refs/heads/revert/${SHORT}")" "${F}"

# 6. The revert PR merged (squashed, its branch deleted) before the rerun: the
# rerun leaves the revert alone and opens the reland the first run could not.
setup merged; echo "reland/7" > "${FAKE}/fail-head"; run
rpr=$(jq -r 'select(.head.ref | startswith("revert/")) | .number' "${FAKE}"/pulls/*.json)
"${REAL_GIT}" --git-dir="${BARE}" update-ref main "refs/heads/revert/${SHORT}"
"${REAL_GIT}" --git-dir="${BARE}" update-ref -d "refs/heads/revert/${SHORT}"
jq '.state = "closed" | .merged = true' "${FAKE}/pulls/${rpr}.json" > "${FAKE}/m.json" && mv "${FAKE}/m.json" "${FAKE}/pulls/${rpr}.json"
rm "${FAKE}/fail-head"; run
expect merged "rerun exit" "${RC}" 0
expect_fresh merged
expect merged "summary" "$([[ ${OUT} == *"found done: revert PR #${rpr} merged"* ]] && echo yes)" yes

# train_setup case -> setup, then the red merge is train PR #9, which carried
# #7; the train closed #7 unmerged.
train_setup() {
	setup "$1"
	local w="${T}/$1/work"
	"${REAL_GIT}" -C "${w}" -c user.name=t -c user.email=t@t -c commit.gpgSign=false commit -q --allow-empty -m $'train\n\npr 7 '"${F}"
	"${REAL_GIT}" -C "${w}" push -q "${BARE}" "HEAD:refs/pull/9/head"
	jq -n '{number: 9, state: "closed", merged: true, title: "train", body: "", head: {ref: "merge-train/1", sha: "x"}}' > "${FAKE}/pulls/9.json"
	jq '.merged = false | .head.ref = "feat"' "${FAKE}/pulls/7.json" > "${FAKE}/m.json" && mv "${FAKE}/m.json" "${FAKE}/pulls/7.json"
	echo 9 > "${FAKE}/pull-of-${M}"
}

# 7. A train carried #7, closed unmerged: it is reopened as a draft once.
train_setup train
run; run
expect train "exit" "${RC}" 0
expect train "reopened" "$(writes "^PATCH /pulls/7$")" 1
expect train "branch restored" "$(writes "^push ${F}:refs/heads/feat$")" 1
expect train "reland PRs" "$(writes "^POST /pulls reland/")" 0
expect train "PR #7 comments" "$(writes "^POST comment #7$")" 1
expect train "title" "$(jq -r '.title' "${FAKE}/pulls/7.json")" "WIP: feature"

# 8. Main already carries a revert of the merge, with no revert PR: nothing is
# written (the check reads git log itself; a `| grep -q` died of SIGPIPE).
setup carried
gt() { "${REAL_GIT}" -C "${T}/carried/work" -c user.name=t -c user.email=t@t -c commit.gpgSign=false "$@"; }
gt revert --no-edit -m 1 "${M}" > /dev/null
gt commit -q --allow-empty -m "later"
gt push -q "${BARE}" main
run
expect carried "exit" "${RC}" 0
expect carried "message" "$([[ ${OUT} == *"main already carries a revert of ${SHORT}"* ]] && echo yes)" yes
expect carried "writes" "$(wc -l < "${FAKE}/writes.log")" 0

# 9. Automerge merged main into the open revert PR's branch: the rerun keeps
# the PR and its branch, and writes nothing.
setup updated; run
gt() { "${REAL_GIT}" -C "${T}/updated/work" -c user.name=t -c user.email=t@t -c commit.gpgSign=false "$@"; }
gt commit -q --allow-empty -m "main moves"
gt push -q "${BARE}" main
gt fetch -q "${BARE}" "refs/heads/revert/${SHORT}:refs/heads/rv"
gt checkout -q rv
gt merge -q --no-ff main -m "Merge main into revert/${SHORT}"
gt push -q "${BARE}" "rv:refs/heads/revert/${SHORT}"
before=$(wc -l < "${FAKE}/writes.log"); run
expect updated "exit" "${RC}" 0
expect updated "new writes" "$(($(wc -l < "${FAKE}/writes.log") - before))" 0

# 10. The reopen PATCH of a train-closed PR failed: the first run fails naming
# it, and the rerun reopens it once without pushing its
# branch again.
train_setup reopen; echo /pulls/7 > "${FAKE}/fail-patch"; run
expect reopen "first exit" "${RC}" 1
expect reopen "first run's error" "$([[ ${OUT} == *"::error::recovery incomplete: reopen-pr#7"* ]] && echo yes)" yes
expect reopen "first run's reopen" "$(writes "^PATCH /pulls/7$")" 0
rm "${FAKE}/fail-patch"; run
expect reopen "rerun exit" "${RC}" 0
expect reopen "reopened" "$(writes "^PATCH /pulls/7$")" 1
expect reopen "branch restored" "$(writes "^push ${F}:refs/heads/feat$")" 1
expect reopen "title" "$(jq -r '.title' "${FAKE}/pulls/7.json")" "WIP: feature"
before=$(wc -l < "${FAKE}/writes.log"); run
expect reopen "third run's writes" "$(($(wc -l < "${FAKE}/writes.log") - before))" 0

# 11. The issue reopen PATCH failed: the first run fails naming it, and the
# rerun reopens the issue and comments on it once, and writes nothing else.
setup issue; echo /issues/3 > "${FAKE}/fail-patch"; run
expect issue "first exit" "${RC}" 1
expect issue "first run's error" "$([[ ${OUT} == *"::error::recovery incomplete: reopen-issue#3"* ]] && echo yes)" yes
expect issue "first run's issue comments" "$(writes "^POST comment #3$")" 0
rm "${FAKE}/fail-patch"; before=$(wc -l < "${FAKE}/writes.log"); run
expect issue "rerun exit" "${RC}" 0
expect_fresh issue
expect issue "rerun's writes" "$(($(wc -l < "${FAKE}/writes.log") - before))" 2
expect issue "issue state" "$(jq -r '.state' "${FAKE}/issues/3.json")" open

# 12. The PR read of a number the body closes failed: it is
# not taken for an issue, so no issue PATCH or comment; the run fails naming
# it, and the rerun reopens the issue and comments on it once.
setup pr-read; echo /pulls/3 > "${FAKE}/fail-get"; run
expect pr-read "first exit" "${RC}" 1
expect pr-read "first run's error" "$([[ ${OUT} == *"::error::recovery incomplete: read-pr#3"* ]] && echo yes)" yes
expect pr-read "first run's issue reopen" "$(writes "^PATCH /issues/3$")" 0
expect pr-read "first run's issue comments" "$(writes "^POST comment #3$")" 0
rm "${FAKE}/fail-get"; run
expect pr-read "rerun exit" "${RC}" 0
expect_fresh pr-read

# 13. The merge's PR lookup failed: the run fails before any write, and does
# not fall back to the commit message, which only a 404 selects.
setup pull-read; echo "/commits/${M}/pull" > "${FAKE}/fail-get"; run
expect pull-read "exit" "${RC}" 1
expect pull-read "message" "$([[ ${OUT} == *"::error::cannot read the PR of ${SHORT} (HTTP 503)"* ]] && echo yes)" yes
expect pull-read "writes" "$(wc -l < "${FAKE}/writes.log")" 0

# 14. The parent's statuses could not be read: the run fails, not leaves.
setup status-read
echo "/commits/$("${REAL_GIT}" --git-dir="${BARE}" rev-parse "${M}^1")/statuses" > "${FAKE}/fail-get"; run
expect status-read "exit" "${RC}" 1
expect status-read "message" "$([[ ${OUT} == *"::error::cannot read the statuses of "* ]] && echo yes)" yes
expect status-read "writes" "$(wc -l < "${FAKE}/writes.log")" 0

# 15. The read of reland/7 failed: it is not pushed, the item is recorded, and
# the rerun relands it once.
setup reland-read; echo /branches/reland/7 > "${FAKE}/fail-get"; run
expect reland-read "first exit" "${RC}" 1
expect reland-read "first run's error" "$([[ ${OUT} == *"::error::recovery incomplete: read-branch#7"* ]] && echo yes)" yes
expect reland-read "first run's reland push" "$(writes "^push ${F}:refs/heads/reland/7$")" 0
expect reland-read "first run's reland PR" "$(writes "^POST /pulls reland/7 ")" 0
rm "${FAKE}/fail-get"; run
expect reland-read "rerun exit" "${RC}" 0
expect_fresh reland-read

# 16. The read of a train-closed PR's branch failed: it is neither restored
# nor reopened, and the rerun does both once.
train_setup branch-read; echo /branches/feat > "${FAKE}/fail-get"; run
expect branch-read "first exit" "${RC}" 1
expect branch-read "first run's error" "$([[ ${OUT} == *"::error::recovery incomplete: read-branch#7"* ]] && echo yes)" yes
expect branch-read "first run's restore" "$(writes "^push ${F}:refs/heads/feat$")" 0
expect branch-read "first run's reopen" "$(writes "^PATCH /pulls/7$")" 0
rm "${FAKE}/fail-get"; run
expect branch-read "rerun exit" "${RC}" 0
expect branch-read "reopened" "$(writes "^PATCH /pulls/7$")" 1
expect branch-read "branch restored" "$(writes "^push ${F}:refs/heads/feat$")" 1

# 17. The comments of #3 could not be read: no comment is posted on the guess
# that none exists; the rerun posts it once.
setup comment-read; echo /issues/3/comments > "${FAKE}/fail-get"; run
expect comment-read "first exit" "${RC}" 1
expect comment-read "first run's error" "$([[ ${OUT} == *"::error::recovery incomplete: comment#3"* ]] && echo yes)" yes
expect comment-read "first run's issue comments" "$(writes "^POST comment #3$")" 0
rm "${FAKE}/fail-get"; run
expect comment-read "rerun exit" "${RC}" 0
expect_fresh comment-read

# 18. Only `make lint-gates` failed: it is a
# deterministic stage, so the merge is reverted and relanded like any other.
setup lint-gates
jq -n '{jobs: [{id: 11, name: "Lint gates", conclusion: "failure", steps: [{name: "make lint-gates", conclusion: "failure"}]}]}' > "${FAKE}/jobs.json"
run
expect lint-gates "exit" "${RC}" 0
expect_fresh lint-gates

# 19. A failed step that is no deterministic stage (a name that only starts like
# one, or a setup step) never reverts, and writes nothing.
setup not-a-stage
jq -n '{jobs: [{id: 11, name: "Lint gates", conclusion: "failure", steps: [{name: "make lint-gates-extra", conclusion: "failure"}, {name: "Set up job", conclusion: "failure"}]}]}' > "${FAKE}/jobs.json"
run
expect not-a-stage "exit" "${RC}" 0
expect not-a-stage "writes" "$(wc -l < "${FAKE}/writes.log")" 0
expect not-a-stage "reason" "$([[ ${OUT} == *"no failed step in run 1 is a deterministic stage"* ]] && echo yes)" yes

[ "${fails}" -eq 0 ] || { echo "revert-red-main-test: ${fails} of ${runs} failed"; exit 1; }
echo "revert-red-main-test: all ${runs} passed"
