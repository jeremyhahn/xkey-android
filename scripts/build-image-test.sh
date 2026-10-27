#!/usr/bin/env bash
# Tests concurrent cold builds of one image tag (main run 68429, job 319235):
# the real `make docker-build-toolchain` and `make docker-build-it`, two at
# once, against a stub docker whose build names its image the way BuildKit's
# exporter does, an update and, when the name is missing, a create, with both
# builds held between the two (so the race is certain, not timing). Asserted:
# the stub reproduces the failure for two builds tagged alike; both makes
# succeed; with IMAGE_FRESH=true each job's `make -s <kind>-image-id` is the
# sha256: ID its own build wrote, still on the daemon, and the tag names one of
# them; without it no build's own name stays behind; a failed build leaves the
# tag alone; a final re-tag that collides with another job's (main run 69069)
# is retried, a bounded number of times, and no other error is. Needs bash and
# make only. `make build-image-test`.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
T=$(mktemp -d)
trap 'rm -rf "${T}"' EXIT
FAILED=0

mkdir -p "${T}/bin"
# docker: state under $S. names/<ref, / as %> = the ID that name points at;
# ids = every image ID built; log = builds and tags, one line each.
cat > "${T}/bin/docker" << 'EOF'
#!/usr/bin/env bash
S=${STUB_STATE:?}
f() { printf '%s/names/%s' "${S}" "${1//\//%}"; }
cmd=$1; shift
case ${cmd} in
build)
	name= iid= target= bargs=
	while [ $# -gt 0 ]; do
		case $1 in
		-t) name=$2; shift 2 ;;
		--iidfile) iid=$2; shift 2 ;;
		--target) target=$2; shift 2 ;;
		--build-arg) bargs+=" $2"; shift 2 ;;
		-f | --label) shift 2 ;;
		*) shift ;;
		esac
	done
	echo "${target}:${bargs}" >> "${S}/buildargs"
	[ -z "${STUB_BUILD_FAIL:-}" ] || { echo "ERROR: failed to solve: stub" >&2; exit 1; }
	if [ -n "${STUB_SAME_ID:-}" ]; then
		id=sha256:$(printf '%s' "${target}" | sha256sum | cut -c1-64)
	else
		id=sha256:$(printf '%s %s %s' "${target}" "$$" "${RANDOM}" | sha256sum | cut -c1-64)
	fi
	echo "${id}" >> "${S}/ids"
	# BuildKit's exporter: update the name; when that finds none, create it.
	if [ -n "${name}" ] && [ ! -e "$(f "${name}")" ]; then
		# Hold every build of this round here, between the miss and the create.
		: > "${S}/arrived.$$"
		for _ in $(seq 100); do
			[ "$(ls "${S}" | grep -c '^arrived\.')" -ge "${STUB_BUILDERS:-1}" ] && break
			sleep 0.1
		done
		if ! (set -C; echo "${id}" > "$(f "${name}")") 2> /dev/null; then
			echo "ERROR: failed to build: failed to solve: image \"docker.io/library/${name}\": already exists" >&2
			exit 1
		fi
	elif [ -n "${name}" ]; then
		echo "${id}" > "$(f "${name}")"
	fi
	echo "build ${name} ${id}" >> "${S}/log"
	[ -z "${iid}" ] || printf '%s' "${id}" > "${iid}"
	;;
tag)
	src=$1 dst=$2
	case ${src} in
	sha256:*) grep -qxF "${src}" "${S}/ids" || exit 1; id=${src} ;;
	*) [ -e "$(f "${src}")" ] || exit 1; id=$(cat "$(f "${src}")") ;;
	esac
	# The first STUB_TAG_FAILS tries fail: STUB_TAG_ERR=exists as a concurrent
	# re-tag's create does (run 69069), else as some other error.
	echo "${dst}" >> "${S}/tagtries"
	if [ "$(wc -l < "${S}/tagtries")" -le "${STUB_TAG_FAILS:-0}" ]; then
		if [ "${STUB_TAG_ERR:-}" = exists ]; then
			echo "Error response from daemon: failed to create an image docker.io/library/${dst} with target ${id} after deleting the existing one: AlreadyExists: image \"docker.io/library/${dst}\": already exists" >&2
		else
			echo "Error response from daemon: stub: no space left on device" >&2
		fi
		exit 1
	fi
	# docker tag replaces the name, whoever wrote it.
	echo "${id}" > "$(f "${dst}").$$" && mv "$(f "${dst}").$$" "$(f "${dst}")"
	echo "tag ${dst} ${id}" >> "${S}/log"
	;;
image)
	sub=$1; shift
	case ${sub} in
	inspect)
		fmt=
		[ "$1" != -f ] || { fmt=$2; shift 2; }
		ref=$1
		case ${ref} in
		sha256:*) grep -qxF "${ref}" "${S}/ids" || exit 1; id=${ref} ;;
		*) [ -e "$(f "${ref}")" ] || exit 1; id=$(cat "$(f "${ref}")") ;;
		esac
		[ -z "${fmt}" ] || echo "${id}"
		;;
	rm) rm "$(f "$1")" ;;
	*) echo "stub docker: unexpected image ${sub}" >&2; exit 99 ;;
	esac
	;;
*) echo "stub docker: unexpected ${cmd}" >&2; exit 99 ;;
esac
EOF
chmod +x "${T}/bin/docker"

S="${T}/state"
reset() {
	rm -rf "${S}" "${T}"/ids-* "${T}"/out-*
	mkdir -p "${S}/names"
	: > "${S}/ids"
	: > "${S}/log"
	: > "${S}/tagtries"
}

# stub <command...>: the command against the stub docker.
stub() { env PATH="${T}/bin:${PATH}" STUB_STATE="${S}" "$@"; }

# pair <make args...>: two `make` at once, jobs a and b, each with its own
# IMAGE_ID_DIR (runner.temp); sets RC_A and RC_B.
pair() {
	local pa pb
	stub STUB_BUILDERS=2 make -s -C "${ROOT}" "$@" IMAGE_ID_DIR="${T}/ids-a" > "${T}/out-a" 2>&1 & pa=$!
	stub STUB_BUILDERS=2 make -s -C "${ROOT}" "$@" IMAGE_ID_DIR="${T}/ids-b" > "${T}/out-b" 2>&1 & pb=$!
	RC_A=0 RC_B=0
	wait "${pa}" || RC_A=$?
	wait "${pb}" || RC_B=$?
}

check() {
	local what=$1
	shift
	if "$@"; then
		echo "ok   ${what}"
	else
		echo "FAIL ${what}"
		FAILED=1
	fi
}
eq() { [ "$1" = "$2" ]; }
ne() { [ "$1" != "$2" ]; }
is_id() { [[ $1 =~ ^sha256:[0-9a-f]{64}$ ]]; }
built() { grep -qxF "$1" "${S}/ids"; }
names_of() { ls "${S}/names" | tr '%' '/' | sort | tr '\n' ' '; }
present() { grep -rqxF "$1" "${S}/names"; }
tag_id() { cat "${S}/names/${1//\//%}" 2> /dev/null || true; }

TC=$(make -s -C "${ROOT}" toolchain-image)
IT=xkey-android-ci-it:test

# The stub reproduces the race: two builds tagged alike, at once, and the
# second create fails as job 319235 did.
reset
stub STUB_BUILDERS=2 docker build -t "${TC}" . > "${T}/out-a" 2>&1 & pa=$!
stub STUB_BUILDERS=2 docker build -t "${TC}" . > "${T}/out-b" 2>&1 & pb=$!
ra=0 rb=0
wait "${pa}" || ra=$?
wait "${pb}" || rb=$?
check "stub: two builds tagged alike: exactly one succeeds" eq "$(((ra == 0) + (rb == 0)))" 1
check "stub: the failure is 'already exists'" grep -qh "already exists" "${T}/out-a" "${T}/out-b"

for kind in toolchain it; do
	args=("docker-build-${kind}") idt=${kind}-image-id tag=${TC}
	if [ "${kind}" = it ]; then args+=(IT_IMAGE="${IT}"); tag=${IT}; fi

	# IMAGE_FRESH=true (a trusted run): each job runs on the ID its own build wrote.
	reset
	pair "${args[@]}" IMAGE_FRESH=true
	check "${kind}: fresh: both builds succeed" eq "${RC_A}${RC_B}" 00
	ida=$(stub make -s -C "${ROOT}" "${idt}" "${args[@]:1}" IMAGE_FRESH=true IMAGE_ID_DIR="${T}/ids-a" 2>&1 || true)
	idb=$(stub make -s -C "${ROOT}" "${idt}" "${args[@]:1}" IMAGE_FRESH=true IMAGE_ID_DIR="${T}/ids-b" 2>&1 || true)
	check "${kind}: fresh: job a's ID is a sha256: ID" is_id "${ida}"
	check "${kind}: fresh: job b's ID is a sha256: ID" is_id "${idb}"
	check "${kind}: fresh: job a's ID is one a build wrote" built "${ida}"
	check "${kind}: fresh: each job has its own build's ID" ne "${ida}" "${idb}"
	check "${kind}: fresh: job a's image is still on the daemon" present "${ida}"
	check "${kind}: fresh: job b's image is still on the daemon" present "${idb}"
	check "${kind}: fresh: the tag names one of the two" grep -qxF "$(tag_id "${tag}")" <(printf '%s\n' "${ida}" "${idb}")
	check "${kind}: fresh: the builds kept their own names (stages lease by ID)" eq "$(ls "${S}/names" | wc -l)" 3

	# The same, when BuildKit merges the two builds into one image.
	reset
	pair "${args[@]}" IMAGE_FRESH=true STUB_SAME_ID=1
	check "${kind}: fresh, one image: both builds succeed" eq "${RC_A}${RC_B}" 00
	ida=$(cat "${T}/ids-a/${kind}.iid" 2> /dev/null || true)
	check "${kind}: fresh, one image: job a's ID is the built one" eq "${ida}" "$(tag_id "${tag}")"

	# IMAGE_FRESH=false (a developer, a pull request): both succeed, the tag
	# names a built image, and no build's own name stays behind.
	reset
	pair "${args[@]}"
	check "${kind}: reuse mode: both builds succeed" eq "${RC_A}${RC_B}" 00
	id=$(stub make -s -C "${ROOT}" "${idt}" "${args[@]:1}" 2>&1 || true)
	check "${kind}: reuse mode: the tag's ID is a built one" built "${id}"
	check "${kind}: reuse mode: only the tag is left" eq "$(names_of)" "${tag} "

	# A failed build fails the make and leaves the tag where it was.
	reset
	echo sha256:old > "${S}/names/${tag//\//%}"
	rc=0
	stub STUB_BUILD_FAIL=1 make -s -C "${ROOT}" "${args[@]}" IMAGE_FRESH=true IMAGE_ID_DIR="${T}/ids-a" > "${T}/out-a" 2>&1 || rc=$?
	check "${kind}: failed build: make fails" ne "${rc}" 0
	check "${kind}: failed build: no ID written" test ! -s "${T}/ids-a/${kind}.iid"
	check "${kind}: failed build: the tag is untouched" eq "$(tag_id "${tag}")" sha256:old
done

# ci-template v1.29: the Alpine index sum reaches the integration build alone,
# and so does its CUSTOMIZE (xkey-android) Debian mirror, APT_INDEX_SUM.
reset
stub make -s -C "${ROOT}" docker-build-it IT_IMAGE="${IT}" APK_INDEX_SUM=sum1 APT_INDEX_SUM=aptsum1 > "${T}/out-a" 2>&1 || true
stub make -s -C "${ROOT}" docker-build-toolchain APK_INDEX_SUM=sum1 APT_INDEX_SUM=aptsum1 > "${T}/out-b" 2>&1 || true
check "apk: the integration build takes APK_INDEX_SUM" grep -q '^integration:.* APK_INDEX_SUM=sum1' "${S}/buildargs"
check "apk: the toolchain build does not" eq "$(grep -c '^toolchain:.*APK_INDEX_SUM' "${S}/buildargs" || true)" 0
check "apk: the toolchain build ran" grep -q '^toolchain:' "${S}/buildargs"
check "apt: the integration build takes APT_INDEX_SUM" grep -q '^integration:.* APT_INDEX_SUM=aptsum1' "${S}/buildargs"
check "apt: the toolchain build does not" eq "$(grep -c '^toolchain:.*APT_INDEX_SUM' "${S}/buildargs" || true)" 0

# The final re-tag against a concurrent re-tag of the same name (main run
# 69069, job 323125): `already exists` is retried up to 5 tries, each pointing
# the tag at the job's own build; any other error fails at once. With and
# without --keep-name, which alone decides whether the build's own name stays.
# retag <fails> <exists|other> [--keep-name]: build-image.sh with the stub's
# first <fails> tags failing; sets RC, ID (the build's) and TRIES.
retag() {
	reset
	rc=0
	stub STUB_TAG_FAILS="$1" STUB_TAG_ERR="$2" BUILD_IMAGE_TAG_BACKOFF_MS=1 \
		"${ROOT}/scripts/build-image.sh" "${@:3}" "${TC}" - docker build > "${T}/out-a" 2>&1 || rc=$?
	RC=${rc} ID=$(tail -n 1 "${S}/ids") TRIES=$(wc -l < "${S}/tagtries")
}
for keep in "" --keep-name; do
	# kept: the names a build leaves besides the tag, its own with --keep-name.
	k=${keep:+keep-name: } kept=0
	[ -z "${keep}" ] || kept=1

	retag 1 exists ${keep:+"${keep}"}
	check "retag: ${k}one collision, then a free name: exits 0" eq "${RC}" 0
	check "retag: ${k}one collision, then a free name: the tag names the job's own build" eq "$(tag_id "${TC}")" "${ID}"
	check "retag: ${k}one collision, then a free name: two tries" eq "${TRIES}" 2
	check "retag: ${k}one collision, then a free name: the build's own name stays only with --keep-name" eq "$(ls "${S}/names" | wc -l)" "$((1 + kept))"

	retag 99 exists ${keep:+"${keep}"}
	check "retag: ${k}always colliding: exits 1" eq "${RC}" 1
	check "retag: ${k}always colliding: the bound, 5 tries" eq "${TRIES}" 5
	check "retag: ${k}always colliding: one line names the tag" grep -q "could not point ${TC} at " "${T}/out-a"
	check "retag: ${k}always colliding: the tag is not set" eq "$(tag_id "${TC}")" ""
	check "retag: ${k}always colliding: the build's own name stays only with --keep-name" eq "$(ls "${S}/names" | wc -l)" "${kept}"

	retag 99 other ${keep:+"${keep}"}
	check "retag: ${k}another error: exits 1" eq "${RC}" 1
	check "retag: ${k}another error: one try" eq "${TRIES}" 1
	check "retag: ${k}another error: the build's own name stays only with --keep-name" eq "$(ls "${S}/names" | wc -l)" "${kept}"
done

if [ "${FAILED}" != 0 ]; then
	echo "build-image-test: FAILED"
	exit 1
fi
echo "build-image-test: ok"
