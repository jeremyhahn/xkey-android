#!/usr/bin/env bash
# Tests the image lease steps of ci.yml (Codex review 7520): the real `run:`
# blocks of "Lease the images", "Lease the toolchain image" and "Lease the
# integration image" (the integration and soak jobs) are extracted at test time
# and run unchanged against a stub docker, make and sleep. Asserted: no rebuild
# when the image is there; one rebuild and the replacement ID exported when it
# is gone; a partial lease removed before the rebuild; a stale lock cleaned; a
# failure, without a loop, once the one rebuild did not bring the image back;
# a lock held by someone else failing the step; the lock released on success
# and on failure. Needs bash only. `make image-lease-test`.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORKFLOW="${ROOT}/.github/workflows/ci.yml"
T=$(mktemp -d)
trap 'rm -rf "${T}"' EXIT
PREFIX=repo-ci-
LOCK="${PREFIX}image-lock"
FAILED=0

# extract <step name> <nth step of that name> <out>: the step's run script, as the runner sees it.
extract() {
	local want=$1 nth=$2 out=$3 seen=0 state=0 line
	: > "${out}"
	while IFS= read -r line; do
		case ${state} in
		0)
			if [ "${line}" = "      - name: ${want}" ]; then
				seen=$((seen + 1))
				if [ "${seen}" -eq "${nth}" ]; then state=1; fi
			fi
			;;
		1) if [ "${line}" = "        run: |" ]; then state=2; fi ;;
		2)
			case ${line} in
			"          "*) printf '%s\n' "${line#          }" >> "${out}" ;;
			"") echo >> "${out}" ;;
			*) state=3 ;;
			esac
			;;
		esac
	done < "${WORKFLOW}"
	if ! [ -s "${out}" ] || ! { [ "${state}" = 3 ] || [ "${state}" = 2 ]; }; then
		echo "image-lease-test: no run script for step '${want}' (#${nth}) in ${WORKFLOW}"
		exit 1
	fi
}

mkdir -p "${T}/bin"
# docker: state under $S. images = the IDs the daemon holds; c/<name> = a created container (its Created time).
cat > "${T}/bin/docker" << 'EOF'
#!/usr/bin/env bash
S=${STUB_STATE:?}
cmd=$1; shift
case ${cmd} in
image)
	[ "$1" = inspect ] && [ -e "${S}/lockbase" ]
	;;
import)
	cat > /dev/null
	: > "${S}/lockbase"
	;;
create)
	name= img=
	while [ $# -gt 0 ]; do
		case $1 in
		--name) name=$2; shift 2 ;;
		--label) shift 2 ;;
		--pull) shift 2 ;;
		true) shift ;;
		*) img=$1; shift ;;
		esac
	done
	[ ! -e "${S}/c/${name}" ] || exit 1
	case ${img} in
	*:base) ;;
	*) grep -qxF "${img}" "${S}/images" || { echo "create ${name} ${img}: missing" >> "${S}/log"; exit 1; } ;;
	esac
	date -u +%Y-%m-%dT%H:%M:%SZ > "${S}/c/${name}"
	echo "create ${name} ${img}" >> "${S}/log"
	echo "id-${name}"
	;;
inspect)
	name=${3:-}
	[ -e "${S}/c/${name}" ] || exit 1
	echo "id-${name} $(cat "${S}/c/${name}")"
	;;
rm)
	for id in "$@"; do
		rm -f "${S}/c/${id#id-}"
		echo "rm ${id}" >> "${S}/log"
	done
	;;
*) echo "stub docker: unexpected ${cmd}" >&2; exit 99 ;;
esac
EOF
# make: the build targets add the IDs in $S/build_adds to the daemon (none: the build brings nothing back).
cat > "${T}/bin/make" << 'EOF'
#!/usr/bin/env bash
S=${STUB_STATE:?}
case " $* " in
*" it-image-id "*) echo it-new ;;
*" toolchain-image-id "*) echo tc-new ;;
*" it-image "*) echo it-tag ;;
*docker-build*)
	echo build >> "${S}/log"
	cat "${S}/build_adds" >> "${S}/images"
	;;
*) echo "stub make: unexpected $*" >&2; exit 99 ;;
esac
EOF
printf '#!/usr/bin/env bash\nexit 0\n' > "${T}/bin/sleep"
chmod +x "${T}/bin/docker" "${T}/bin/make" "${T}/bin/sleep"

# reset: a fresh daemon state; images and build_adds are space-separated IDs.
reset() {
	S="${T}/state"
	rm -rf "${S}" "${T}/env" "${T}/ids"
	mkdir -p "${S}/c"
	: > "${S}/log"
	: > "${T}/env"
	printf '%s\n' ${1:-} > "${S}/images"
	printf '%s\n' ${2:-} > "${S}/build_adds"
	OLD_IT=it-old OLD_TC=tc-old
}

# run <script>: sets RC and OUT; the daemon's state is in $S.
run() {
	RC=0
	OUT=$(env PATH="${T}/bin:${PATH}" STUB_STATE="${S}" CI_STACK_PREFIX="${PREFIX}" GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1 \
		LEASE_SECONDS=100 GITHUB_ENV="${T}/env" IMAGE_ID_DIR="${T}/ids" IT_IMAGE="${OLD_IT}" TOOLCHAIN_IMAGE="${OLD_TC}" \
		bash -eo pipefail "$1" 2>&1) || RC=$?
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
builds() { grep -c '^build$' "${S}/log" || true; }
leases() { ls "${S}/c" | grep -c "^${PREFIX}lease-1-1-" || true; }
env_has() { grep -qxF "$1" "${T}/env"; }
env_lacks() { ! grep -q "^$1=" "${T}/env"; }
lock_free() { [ ! -e "${S}/c/${LOCK}" ]; }
eq() { [ "$1" = "$2" ]; }
out_has() { grep -qF -- "$1" <<< "${OUT}"; }
log_has() { grep -qE -- "$1" "${S}/log"; }

# Step table: <step> <nth> <images to hold> <var the rebuild exports> <lease vars exported> <leases taken>
steps=(
	"Lease the images|1|IT_IMAGE TOOLCHAIN_IMAGE|IT_LEASE TC_LEASE|2"
	"Lease the toolchain image|1|TOOLCHAIN_IMAGE|TC_LEASE|1"
	"Lease the integration image|1|IT_IMAGE|-|1"
	"Lease the integration image|2|IT_IMAGE|-|1"
)

for row in "${steps[@]}"; do
	IFS='|' read -r step nth vars lvars nleases <<< "${row}"
	label="${step} #${nth}"
	extract "${step}" "${nth}" "${T}/run.sh"
	have_old="" new_ids=""
	case ${vars} in *IT_IMAGE*) have_old+=" ${OLD_IT:-it-old}"; new_ids+=" it-new" ;; esac
	case ${vars} in *TOOLCHAIN_IMAGE*) have_old+=" tc-old"; new_ids+=" tc-new" ;; esac

	# The images are there: no rebuild, and nothing replacement is exported.
	reset "${have_old}" "${new_ids}"
	run "${T}/run.sh"
	check "${label}: present: succeeds" eq "${RC}" 0
	check "${label}: present: no rebuild" eq "$(builds)" 0
	check "${label}: present: leases taken" eq "$(leases)" "${nleases}"
	check "${label}: present: no replacement ID exported" env_lacks "IT_IMAGE"
	check "${label}: present: no replacement toolchain ID exported" env_lacks "TOOLCHAIN_IMAGE"
	check "${label}: present: lock released" lock_free
	if [ "${lvars}" != "-" ]; then
		for v in ${lvars}; do check "${label}: present: ${v} exported" grep -q "^${v}=${PREFIX}lease-1-1-" "${T}/env"; done
	fi

	# The images are gone: one rebuild, the replacement IDs exported, then leased.
	reset "" "${new_ids}"
	run "${T}/run.sh"
	check "${label}: gone: succeeds" eq "${RC}" 0
	check "${label}: gone: one rebuild" eq "$(builds)" 1
	check "${label}: gone: leases taken on the rebuilt images" eq "$(leases)" "${nleases}"
	case ${vars} in *IT_IMAGE*) check "${label}: gone: new IT_IMAGE exported" env_has "IT_IMAGE=it-new" ;; esac
	case ${vars} in *TOOLCHAIN_IMAGE*) check "${label}: gone: new TOOLCHAIN_IMAGE exported" env_has "TOOLCHAIN_IMAGE=tc-new" ;; esac
	check "${label}: gone: lease leased the new ID" log_has "^create ${PREFIX}lease-1-1-[0-9a-f]+ (it|tc)-new$"
	check "${label}: gone: lock released" lock_free

	# The images are gone and the rebuild brings nothing back: fails after the one retry, lock released.
	reset "" ""
	run "${T}/run.sh"
	check "${label}: exhausted: fails" test "${RC}" -ne 0
	check "${label}: exhausted: one rebuild, no loop" eq "$(builds)" 1
	check "${label}: exhausted: error names the missing image" out_has "is missing after one rebuild"
	check "${label}: exhausted: no lease held" eq "$(leases)" 0
	check "${label}: exhausted: lock released on failure" lock_free

	# A stale lock (a failed run's, created long ago) is cleaned and the step goes on.
	reset "${have_old}" "${new_ids}"
	echo 2000-01-01T00:00:00Z > "${S}/c/${LOCK}"
	: > "${S}/lockbase"
	run "${T}/run.sh"
	check "${label}: stale lock: succeeds" eq "${RC}" 0
	check "${label}: stale lock: removed" out_has "removing the stale image lock ${LOCK}"
	check "${label}: stale lock: removed by its id" log_has "^rm id-${LOCK}$"
	check "${label}: stale lock: leases taken" eq "$(leases)" "${nleases}"
	check "${label}: stale lock: lock released" lock_free

	# A fresh lock held by another run is waited for, then the step fails; the other run's lock stays.
	reset "${have_old}" "${new_ids}"
	date -u +%Y-%m-%dT%H:%M:%SZ > "${S}/c/${LOCK}"
	: > "${S}/lockbase"
	run "${T}/run.sh"
	check "${label}: held lock: fails" test "${RC}" -ne 0
	check "${label}: held lock: says it was not free" out_has "was not free within 660 s"
	check "${label}: held lock: no rebuild, no lease" eq "$(builds)$(leases)" 00
	check "${label}: held lock: the other run's lock is not removed" test -e "${S}/c/${LOCK}"
done

# Partial lease cleanup (the image job): the first image is leased, the second is
# gone, so the first lease is removed before the rebuild and only two stay after it.
extract "Lease the images" 1 "${T}/run.sh"
reset "it-old" "it-new tc-new"
run "${T}/run.sh"
check "partial: succeeds" eq "${RC}" 0
check "partial: the first lease was removed before the rebuild" log_has "^rm ${PREFIX}lease-1-1-"
check "partial: one rebuild" eq "$(builds)" 1
check "partial: exactly the two new leases remain" eq "$(leases)" 2
check "partial: both replacement IDs exported" env_has "IT_IMAGE=it-new"
check "partial: both replacement IDs exported (toolchain)" env_has "TOOLCHAIN_IMAGE=tc-new"
check "partial: lock released" lock_free

# Partial and exhausted: the rebuild brings back only one image; no lease stays, lock released.
reset "it-old" "it-new"
run "${T}/run.sh"
check "partial exhausted: fails" test "${RC}" -ne 0
check "partial exhausted: one rebuild, no loop" eq "$(builds)" 1
check "partial exhausted: no lease stays" eq "$(leases)" 0
check "partial exhausted: lock released on failure" lock_free

if [ "${FAILED}" != 0 ]; then
	echo "image-lease-test: FAILED"
	exit 1
fi
echo "image-lease-test: ok"
