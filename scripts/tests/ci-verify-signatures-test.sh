#!/usr/bin/env bash
# Tests scripts/ci-verify-signatures.sh against offline git fixtures; no head file may run. SCRIPT=<path> tests another copy.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPT=${SCRIPT:-$ROOT/scripts/ci-verify-signatures.sh}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
export HOME="$T/home" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
mkdir -p "$HOME" "$T/tmp"

EMAIL=dev@example.com
ssh-keygen -q -t ed25519 -N '' -C reg -f "$T/key_reg"
ssh-keygen -q -t ed25519 -N '' -C head -f "$T/key_head"
signer_line() { local kt kb; read -r kt kb _ < "$1.pub"; printf '%s %s %s\n' "$EMAIL" "$kt" "$kb"; }
REG_LINE=$(signer_line "$T/key_reg")
HEAD_LINE=$(signer_line "$T/key_head")
MARKER="$T/head-code-ran"
HEAD_CODE="#!/bin/sh
touch '$MARKER'"

FAILED=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; FAILED=1; }

# commit <key|-> <file> <content> <message>: commit in the work repo, signed
# with <key> (or unsigned for -); prints the new SHA.
commit() {
  local key=$1 f=$2
  mkdir -p "$T/w/$(dirname "$f")"
  printf '%s\n' "$3" > "$T/w/$f"
  case "$f" in *.sh) chmod +x "$T/w/$f" ;; esac
  git -C "$T/w" add -A
  if [ "$key" = - ]; then
    git -C "$T/w" -c commit.gpgsign=false commit -q -m "$4"
  else
    git -C "$T/w" -c gpg.format=ssh -c user.signingkey="$key" commit -q -S -m "$4"
  fi
  git -C "$T/w" rev-parse HEAD
}

# unpushed: a commit object that exists only in the work repo.
unpushed() { git -C "$T/w" commit-tree -m "never pushed" "$(git -C "$T/w" write-tree)"; }

# setup <with-registry|no-registry>: a fresh origin whose main is the base; sets BASE.
setup() {
  rm -rf "$T/o" "$T/w" "$T/ck" "$MARKER"
  git init -q --bare -b main "$T/o"
  git -C "$T/o" config uploadpack.allowAnySHA1InWant true
  git init -q -b main "$T/w"
  git -C "$T/w" config user.name Dev
  git -C "$T/w" config user.email "$EMAIL"
  git -C "$T/w" remote add origin "$T/o"
  if [ "$1" = with-registry ]; then
    BASE=$(commit "$T/key_reg" .github/allowed_signers "$REG_LINE" "base")
  else
    BASE=$(commit "$T/key_reg" README "base" "base")
  fi
  git -C "$T/w" push -q origin main
  git -C "$T/w" checkout -q -b feat
}

# push_pr <sha>: publish <sha> as refs/pull/7/head only, never as a branch.
push_pr() { git -C "$T/w" push -q -f origin "$1:refs/pull/7/head"; }

# check <pass|fail> <name> <VAR=value>...: clone origin (the base checkout,
# branches only), run the script in it with only the given environment,
# and assert the outcome, that no head file ran and that the checkout did
# not move. OUT holds the script's output.
check() {
  local want=$1 name=$2 rc=0 before after
  shift 2
  rm -rf "$T/ck" "$MARKER"
  git clone -q "$T/o" "$T/ck"
  before=$(git -C "$T/ck" rev-parse HEAD)
  (cd "$T/ck" && env -i PATH="$PATH" HOME="$HOME" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
      GIT_TERMINAL_PROMPT=0 RUNNER_TEMP="$T/tmp" REPO=example/repo API=http://127.0.0.1:9 GH_TOKEN=unused \
      "$@" "$SCRIPT") > "$T/out" 2>&1 || rc=$?
  OUT=$(<"$T/out")
  after=$(git -C "$T/ck" rev-parse HEAD)
  if [ -e "$MARKER" ]; then bad "$name: a file from the pull request head ran"; return; fi
  if [ "$before" != "$after" ]; then bad "$name: the base checkout moved to $after"; return; fi
  if { [ "$want" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$want" = fail ] && [ "$rc" -ne 0 ]; }; then
    ok "$name ($want)"
  else
    bad "$name: want $want, got rc=$rc"
    printf '%s\n' "$OUT" | tail -n 5 | cut -c1-200
  fi
}

prt() { echo EVENT=pull_request_target PR=7 BASE_SHA="$1" HEAD_SHA="$2"; }

# 1. A fork head: signed with the base's registered key, reachable only via
# refs/pull/7/head, and carrying a script of its own that must not run.
setup with-registry
H=$(commit "$T/key_reg" scripts/ci-verify-signatures.sh "$HEAD_CODE" "head ships its own checker")
push_pr "$H"
# shellcheck disable=SC2046 # prt prints separate VAR=value words
check pass "fork head signed with a base-registered key" $(prt "$BASE" "$H")
case "$OUT" in *"OK   ${H:0:12}"*) ok "fork head commit listed as OK" ;; *) bad "fork head commit not listed as OK" ;; esac

# 2. The head moved after the event: an unsigned commit lands on top of the
# event's head. The run checks the event's head, not the moved ref.
setup with-registry
H1=$(commit "$T/key_reg" scripts/ci-verify-signatures.sh "$HEAD_CODE" "event head")
push_pr "$H1"
H2=$(commit - scripts/later.sh "$HEAD_CODE" "pushed after the event, unsigned")
push_pr "$H2"
# shellcheck disable=SC2046
check pass "head moved after the event: the event head is checked" $(prt "$BASE" "$H1")
case "$OUT" in *"${H2:0:12}"*) bad "moved head ${H2:0:12} was checked" ;; *) ok "moved head not checked" ;; esac
# shellcheck disable=SC2046
check fail "the moved head itself (unsigned) fails" $(prt "$BASE" "$H2")

# 3. A missing base object: the base SHA is in no remote.
setup with-registry
H=$(commit "$T/key_reg" scripts/ci-verify-signatures.sh "$HEAD_CODE" "head")
push_pr "$H"
# shellcheck disable=SC2046
check fail "missing base object" $(prt "$(unpushed)" "$H")

# 4. A missing head object: the head SHA is in no remote, while
# refs/pull/7/head holds another commit.
setup with-registry
H=$(commit "$T/key_reg" scripts/ci-verify-signatures.sh "$HEAD_CODE" "head")
push_pr "$H"
# shellcheck disable=SC2046
check fail "missing head object" $(prt "$BASE" "$(unpushed)")

# 5. A signer registry only on the head: the base has none, and the head
# adds one registering the key that signs it.
setup no-registry
commit "$T/key_head" .github/allowed_signers "$HEAD_LINE" "head adds a registry" > /dev/null
H=$(commit "$T/key_head" scripts/ci-verify-signatures.sh "$HEAD_CODE" "head signed by its own key")
push_pr "$H"
# shellcheck disable=SC2046
check fail "registry present only on the head" $(prt "$BASE" "$H")

# 6. The head replaces the base's registry with its own key.
setup with-registry
commit "$T/key_head" .github/allowed_signers "$HEAD_LINE" "head swaps the registry" > /dev/null
H=$(commit "$T/key_head" scripts/ci-verify-signatures.sh "$HEAD_CODE" "head signed by its own key")
push_pr "$H"
# shellcheck disable=SC2046
check fail "head-swapped registry" $(prt "$BASE" "$H")

# 7. An unsigned pull request commit.
setup with-registry
H=$(commit - scripts/ci-verify-signatures.sh "$HEAD_CODE" "unsigned")
push_pr "$H"
# shellcheck disable=SC2046
check fail "unsigned pull request commit" $(prt "$BASE" "$H")

# 8. A push to main with a before: the registry comes from the before.
setup with-registry
H=$(commit "$T/key_reg" scripts/ci-verify-signatures.sh "$HEAD_CODE" "pushed to main")
git -C "$T/w" push -q origin "$H:refs/heads/main"
check pass "push to main, signed" EVENT=push BEFORE="$BASE" HEAD_SHA="$H"

if [ "$FAILED" -ne 0 ]; then echo "ci-verify-signatures-test: FAILED"; exit 1; fi
echo "ci-verify-signatures-test: all cases pass"
