#!/usr/bin/env bash
# Tests reap-stale-ci-stacks.sh's image and lease rules (Codex review 6544 on
# PR #40) against a stubbed docker: the image families (<prefix>it and
# REAP_IMAGE_REPOS) and their untagged images, the in-use check, the last-use
# age and the lease expiry. Needs bash and GNU date only, no Docker.
# `make reaper-test`.
#
# The stub serves two fixture files and logs every removal:
#   containers: id name state finished created expires image
#   images:     id ref created last-tag-unix label   (ref <none>: untagged)
# A dash is an empty field. An image with two tags is two lines, one id.
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
REAPER="${ROOT}/scripts/reap-stale-ci-stacks.sh"
PREFIX=xkey-android-ci-
TC=xkey-android-toolchain

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT
mkdir "${tmp}/bin"
cat > "${tmp}/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -u
fix=${STUB_FIXTURE:?}
arg() { local a; for a in "$@"; do case $a in "$want"*) echo "${a#"$want"}"; return 0 ;; esac; done; return 1; }
field() { [ "$1" = - ] && echo "" || echo "$1"; }
drop() { # drop <file> <column> <value>: remove the lines whose column is value
  local f=$1 col=$2 val=$3 line out=""
  while IFS= read -r line; do
    read -r -a w <<< "${line}"
    [ "${w[$col]}" = "${val}" ] || out+="${line}"$'\n'
  done < "${fix}/${f}"
  printf '%s' "${out}" > "${fix}/${f}"
}
cmd=$1
shift
case ${cmd} in
  ps)
    want=label=com.docker.compose.project; arg "$@" > /dev/null && exit 0
    if want=name=^; p=$(arg "$@"); then
      while read -r id name _; do
        case ${name} in "${p}"*) echo "${id} ${name} " ;; esac
      done < "${fix}/containers"
      exit 0
    fi
    while read -r id _; do echo "${id}"; done < "${fix}/containers" ;;
  inspect)
    fmt=$2
    shift 2
    for c in "$@"; do
      while read -r id name state finished created expires image; do
        [ "${id}" = "${c}" ] || continue
        case ${fmt} in
          *State.Status*) echo "${state} ${finished} ${created} $(field "${expires}")" ;;
          *) echo "${image}" ;;
        esac
      done < "${fix}/containers"
    done ;;
  images)
    if want=reference=; r=$(arg "$@"); then
      while read -r id ref _; do
        case ${ref} in "${r}:"*) echo "${ref}" ;; esac
      done < "${fix}/images"
    else
      want=label=ci.image.repository=; l=$(arg "$@")
      while read -r id ref _ _ label; do
        [ "${ref}" = "<none>" ] && [ "${label}" = "${l}" ] && echo "${id}"
      done < "${fix}/images"
    fi ;;
  image)
    sub=$1
    shift
    case ${sub} in
      inspect)
        while read -r id ref created tagged _; do
          [ "${ref}" = "$3" ] || [ "${id}" = "$3" ] || continue
          echo "${id} ${created} ${tagged}"
          exit 0
        done < "${fix}/images"
        exit 1 ;;
      rm)
        echo "image rm $1" >> "${fix}/log"
        case $1 in sha256:*) drop images 0 "$1" ;; *) drop images 1 "$1" ;; esac ;;
    esac ;;
  rm)
    [ "$1" = -v ] && shift
    echo "rm $1" >> "${fix}/log"
    drop containers 0 "$1" ;;
  network | volume) ;;
esac
STUB
chmod +x "${tmp}/bin/docker"

now=$(date +%s)
# ago <seconds>: the RFC 3339 time that long ago.
ago() { date -u -d "@$((now - $1))" +%Y-%m-%dT%H:%M:%SZ; }
NEVER=0001-01-01T00:00:00Z
H=3600

runs=0 fails=0
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }

# reap <case> <want> [env...]: run the reaper on the fixture as it stands,
# with env, and compare the sorted removal log with want (one per line).
reap() {
	local name=$1 want=$2 got
	shift 2
	runs=$((runs + 1))
	: > "${tmp}/fix/log"
	env PATH="${tmp}/bin:${PATH}" STUB_FIXTURE="${tmp}/fix" "$@" "${REAPER}" "${PREFIX}" > "${tmp}/out" 2>&1 \
		|| fail "${name}: reaper exit $?: $(cat "${tmp}/out")"
	got=$(sort "${tmp}/fix/log")
	want=$(printf '%s' "${want}" | sort)
	[ "${got}" = "${want}" ] || fail "${name}: want removed [${want//$'\n'/, }], got [${got//$'\n'/, }]"
}
fixture() { mkdir -p "${tmp}/fix"; printf '%s\n' "$1" > "${tmp}/fix/containers"; printf '%s\n' "$2" > "${tmp}/fix/images"; }

sha() { printf 'sha256:%064d' "$1"; }

# The image rules, one daemon. REAP_IMAGE_MIN_AGE is the default 2 h,
# <min-age-seconds> the default 11100.
fixture "\
c1 ${PREFIX}lease-1-1-aa created ${NEVER} $(ago $((1 * H))) $((now + H)) $(sha 3)
c2 ${PREFIX}lease-2-1-bb created ${NEVER} $(ago $((1 * H))) $((now - 60)) $(sha 4)
c3 ${PREFIX}lease-3-1-cc created ${NEVER} $(ago $((4 * H))) $((now + 7 * 24 * H)) $(sha 5)
c4 ${PREFIX}lease-4-1-dd created ${NEVER} $(ago $((1 * H))) - $(sha 6)
c5 ${PREFIX}tc-99-1 running ${NEVER} $(ago 600) - $(sha 7)
c6 other-ci-tc-1 created ${NEVER} $(ago $((9 * H))) - $(sha 8)" "\
$(sha 1) ${TC}:aaaa $(ago $((5 * H))) $((now - 5 * H)) ${TC}
$(sha 2) ${TC}:pr-bbbb $(ago $((5 * H))) $((now - 600)) ${TC}
$(sha 3) ${TC}:cccc $(ago $((5 * H))) $((now - 5 * H)) ${TC}
$(sha 3) ${TC}:pr-cccc $(ago $((5 * H))) $((now - 5 * H)) ${TC}
$(sha 4) ${TC}:pr-dddd $(ago $((5 * H))) $((now - 5 * H)) ${TC}
$(sha 5) ${TC}:eeee $(ago $((5 * H))) $((now - 5 * H)) ${TC}
$(sha 6) ${TC}:ffff $(ago $((5 * H))) $((now - 5 * H)) ${TC}
$(sha 7) ${TC}:gggg $(ago $((5 * H))) $((now - 5 * H)) ${TC}
$(sha 8) other-toolchain:hhhh $(ago $((5 * H))) $((now - 5 * H)) other-toolchain
$(sha 9) <none> $(ago $((5 * H))) $((now - 5 * H)) ${TC}
$(sha 10) <none> $(ago 600) $((now - 600)) ${TC}
$(sha 11) <none> $(ago $((5 * H))) $((now - 5 * H)) other-toolchain
$(sha 12) <none> $(ago $((5 * H))) -62135596800 ${PREFIX}it
$(sha 13) ${PREFIX}it:iiii $(ago $((5 * H))) $((now - 5 * H)) ${PREFIX}it
$(sha 14) ${PREFIX}it:jjjj $(ago $((3 * H))) $((now - 60)) ${PREFIX}it"
# Removed: the expired lease (c2) and the one past <min-age-seconds> despite
# its far expiry (c3), then their images; the idle tag (1); the untagged
# images of both families older than 2 h (9, 12); the idle it image (13).
# Kept: an image re-tagged 10 min ago (2, 14), both tags of an image an
# unexpired lease holds (3), an image a lease without expiry holds within
# <min-age-seconds> (6), an image a running stage uses (7), another repo's
# images and containers (8, 11, c6), a young untagged image (10).
reap "image rules" "\
rm c2
rm c3
image rm ${TC}:aaaa
image rm ${TC}:pr-dddd
image rm ${TC}:eeee
image rm $(sha 9)
image rm $(sha 12)
image rm ${PREFIX}it:iiii" REAP_IMAGE_REPOS="${TC}"

# Without REAP_IMAGE_REPOS only the <prefix>it family is reaped (v3).
fixture "" "\
$(sha 1) ${TC}:aaaa $(ago $((5 * H))) $((now - 5 * H)) ${TC}
$(sha 13) ${PREFIX}it:iiii $(ago $((5 * H))) $((now - 5 * H)) ${PREFIX}it"
reap "it family only" "image rm ${PREFIX}it:iiii"

# REAP_IMAGE_MIN_AGE moves the age line.
fixture "" "$(sha 1) ${TC}:aaaa $(ago $((5 * H))) $((now - 5 * H)) ${TC}"
reap "image min age" "" REAP_IMAGE_REPOS="${TC}" REAP_IMAGE_MIN_AGE=$((6 * H))

# A repository name that is not one is refused before anything is removed.
runs=$((runs + 1))
fixture "" "$(sha 1) ${TC}:aaaa $(ago $((5 * H))) $((now - 5 * H)) ${TC}"
rc=0
env PATH="${tmp}/bin:${PATH}" STUB_FIXTURE="${tmp}/fix" REAP_IMAGE_REPOS='Bad;rm' "${REAPER}" "${PREFIX}" > /dev/null 2>&1 || rc=$?
[ "${rc}" = 2 ] || fail "bad REAP_IMAGE_REPOS: want exit 2, got ${rc}"

[ "${fails}" -eq 0 ] || { echo "reaper-test: ${fails} of ${runs} failed"; exit 1; }
echo "reaper-test: all ${runs} passed"
