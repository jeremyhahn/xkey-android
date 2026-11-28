#!/usr/bin/env bash
# Test that scripts/in-toolchain-image.sh starts every container under CI_CGROUP_PARENT (default ci.slice;
# empty passes no --cgroup-parent, a bad name is refused) and asks for at most IN_IMAGE_MAX_CPUS (default 8)
# CPUs. A fake docker first on PATH records its arguments; no real docker, network or image is needed.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
launcher="$root/scripts/in-toolchain-image.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin" "$tmp/src"
echo hello >"$tmp/src/file"
# One line per docker call: the arguments, each followed by a space, between leading and trailing spaces.
cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
line=" "
for a in "$@"; do line+="$a "; done
echo "$line" >>"$FAKE_DOCKER_LOG"
case "${1:-}" in
  info) echo "$FAKE_DOCKER_NCPU" ;;
  cp) cat >/dev/null ;;
esac
exit 0
EOF
chmod +x "$tmp/bin/docker"

# The CPUs the launcher finds before any cap: the cgroup quota, else nproc.
host_cpus() {
  local quota=max period=100000
  if [ -r /sys/fs/cgroup/cpu.max ]; then read -r quota period </sys/fs/cgroup/cpu.max; fi
  case $quota in
    max | "" | *[!0-9]*) nproc ;;
    *) echo $(((quota + period - 1) / period)) ;;
  esac
}
min() {
  local m=$1 v
  for v in "$@"; do if [ "$v" -lt "$m" ]; then m=$v; fi; done
  echo "$m"
}

fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

# run <ncpu> [VAR=value...]: run the launcher with a fresh log; sets rc.
run() {
  local ncpu=$1
  shift
  : >"$tmp/log"
  rc=0
  (cd "$tmp/src" && env -u CI_CGROUP_PARENT -u IN_IMAGE_CPUS -u IN_IMAGE_MAX_CPUS \
    PATH="$tmp/bin:$PATH" FAKE_DOCKER_LOG="$tmp/log" FAKE_DOCKER_NCPU="$ncpu" \
    CI_STACK_PREFIX=t-ci- CI_CACHE=on "$@" "$launcher" dummy-image true) >/dev/null 2>"$tmp/err" || rc=$?
}
# call <verb>: the recorded line of the first docker call with that verb.
call() {
  local line
  while IFS= read -r line; do
    if [[ $line == " $1 "* ]]; then
      echo "$line"
      return
    fi
  done <"$tmp/log"
}
has() { [[ $2 == *" $1 "* ]]; }

# Default: both containers under ci.slice; the job at most 8 CPUs.
run 112
want=$(min "$(host_cpus)" 112 8)
create=$(call create)
chown=$(call run)
[ "$rc" = 0 ] || fail "default: rc $rc: $(cat "$tmp/err")"
has "--cgroup-parent ci.slice" "$create" || fail "default: main container has no --cgroup-parent ci.slice: $create"
has "--cpus $want" "$create" || fail "default: main container wants --cpus $want: $create"
has "GOMAXPROCS=$want" "$create" || fail "default: main container wants GOMAXPROCS=$want: $create"
has "--cgroup-parent ci.slice" "$chown" || fail "default: chown helper has no --cgroup-parent ci.slice: $chown"
has "--cpus 1" "$chown" || fail "default: chown helper wants --cpus 1: $chown"

# Empty CI_CGROUP_PARENT: no --cgroup-parent anywhere.
run 112 CI_CGROUP_PARENT=
[ "$rc" = 0 ] || fail "empty parent: rc $rc: $(cat "$tmp/err")"
while IFS= read -r line; do
  if has --cgroup-parent "$line"; then fail "empty parent: --cgroup-parent passed: $line"; fi
done <"$tmp/log"

# A bad name: exit 2 before any container starts.
run 112 "CI_CGROUP_PARENT=bad;name"
[ "$rc" = 2 ] || fail "bad parent: want rc 2, got $rc"
[ -z "$(call run)$(call create)" ] || fail "bad parent: a container was started: $(cat "$tmp/log")"

# The CPU cap.
check_cpus() {
  local want=$1
  shift
  run "$@"
  [ "$rc" = 0 ] || fail "$*: rc $rc: $(cat "$tmp/err")"
  has "--cpus $want" "$(call create)" || fail "$*: want --cpus $want: $(call create)"
  has "GOMAXPROCS=$want" "$(call create)" || fail "$*: want GOMAXPROCS=$want: $(call create)"
}
check_cpus 4 112 IN_IMAGE_CPUS=4
check_cpus 8 112 IN_IMAGE_CPUS=64
check_cpus 16 112 IN_IMAGE_MAX_CPUS=16 IN_IMAGE_CPUS=64
check_cpus "$(min "$(host_cpus)" 2)" 2

for bad in 0 x; do
  run 112 IN_IMAGE_MAX_CPUS=$bad
  [ "$rc" = 2 ] || fail "IN_IMAGE_MAX_CPUS=$bad: want rc 2, got $rc"
done

if [ "$fails" -gt 0 ]; then
  echo "in-toolchain-image-test: $fails failure(s)" >&2
  exit 1
fi
echo "in-toolchain-image-test: ok"
