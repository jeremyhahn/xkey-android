#!/usr/bin/env bash
# Tests build/docker/devcontainer/fetch.sh, the image build's download helper,
# offline: it runs under sh with a stub curl first on PATH, which serves the
# fixtures below, logs every call, and refuses one without the retry flags.
# The cases: the primary download with a good and a bad checksum; a failed
# GitHub release download recovered through the API asset endpoint, the asset
# picked among several, with a good and a bad checksum; release JSON without
# the asset, malformed, truncated or with a bad id; the release lookup and the
# asset download failing; a URL that is not a GitHub release, with no
# redirect, a redirect elsewhere, and a redirect to a GitHub release.
#
#   usage: scripts/fetch-test.sh    (make fetch-test, part of make lint-gates)
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FETCH="${ROOT}/build/docker/devcontainer/fetch.sh"
T=$(mktemp -d)
trap 'rm -rf "${T}"' EXIT
S="${T}/stub"
FAILED=0

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
has() { [[ $1 == *"$2"* ]]; }
lacks() { [[ $1 != *"$2"* ]]; }

# The stub curl. Each URL's fixtures live under STUB_DIR, named by the URL
# with every character outside [A-Za-z0-9._-] made `_`: <key>.body is served
# (to -o, or stdout), <key>.redirect is what -w '%{redirect_url}' prints, and
# <key>.rc makes the call fail with that exit code. A download with no body
# fails as curl -f does on an HTTP error (22); a redirect lookup with no
# redirect prints nothing. Each call appends "<get|redirect> <url> <Accept>"
# to STUB_DIR/log.
mkdir -p "${T}/bin"
cat > "${T}/bin/curl" << 'EOF'
#!/usr/bin/env bash
set -eu
dir=${STUB_DIR:?}
all=" $* "
out='' write='' accept=- url=''
while [ $# -gt 0 ]; do
	case $1 in
	-o) out=$2; shift 2 ;;
	-w) write=$2; shift 2 ;;
	-H) case $2 in Accept:*) accept=${2#Accept: } ;; esac; shift 2 ;;
	--proto | --retry | --retry-delay | --connect-timeout) shift 2 ;;
	-*) shift ;;
	*) url=$1; shift ;;
	esac
done
mode=get
[ -z "${write}" ] || mode=redirect
echo "${mode} ${url} ${accept}" >> "${dir}/log"
case ${all} in
*" --proto =https --tlsv1.2 --retry 5 --retry-delay 10 --retry-all-errors --connect-timeout 30 "*) ;;
*) echo "noretry ${url}" >> "${dir}/log"; exit 99 ;;
esac
key=$(printf '%s' "${url}" | tr -c 'A-Za-z0-9._-' '_')
[ ! -e "${dir}/${key}.rc" ] || exit "$(< "${dir}/${key}.rc")"
if [ "${mode}" = redirect ]; then
	[ "${write}" = '%{redirect_url}' ] || exit 99
	[ "${out}" = /dev/null ] || exit 99
	[ ! -e "${dir}/${key}.redirect" ] || printf '%s' "$(< "${dir}/${key}.redirect")"
	exit 0
fi
[ -e "${dir}/${key}.body" ] || exit 22
if [ -n "${out}" ]; then
	cp "${dir}/${key}.body" "${out}"
else
	cat "${dir}/${key}.body"
fi
EOF
chmod +x "${T}/bin/curl"

key() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }
# reset: no fixtures, an empty log, no download.
reset() {
	rm -rf "${S}" "${T}/dl"
	mkdir -p "${S}"
	: > "${S}/log"
}
serve() { printf '%s' "$2" > "${S}/$(key "$1").body"; }
redirect() { printf '%s' "$2" > "${S}/$(key "$1").redirect"; }
refuse() { printf '%s' "$2" > "${S}/$(key "$1").rc"; }

# run <url> <sha256>: fetch.sh under sh against the stub; sets RC, LOG (the
# stub's calls), ERR, and GOT (the downloaded file, or `<none>`).
run() {
	RC=0
	PATH="${T}/bin:${PATH}" STUB_DIR="${S}" sh "${FETCH}" "$1" "${T}/dl" "$2" > "${T}/stdout" 2> "${T}/err" || RC=$?
	LOG=$(< "${S}/log")
	ERR=$(< "${T}/err")
	GOT='<none>'
	[ ! -e "${T}/dl" ] || GOT=$(< "${T}/dl")
}
calls() { printf '%s\n' "$@"; }

BODY='the asset bytes'
SUM=$(printf '%s' "${BODY}" | sha256sum | cut -c1-64)
BAD=$(printf '%s' 'other bytes' | sha256sum | cut -c1-64)
NAME=tool_1.0_Linux-64bit.tar.gz
REL="https://github.com/example/tool/releases/download/v1.0/${NAME}"
API=https://api.github.com/repos/example/tool/releases
LOOKUP="${API}/tags/v1.0"
ASSET="${API}/assets/202"
JSON=application/vnd.github+json
OCTET=application/octet-stream

# asset <id> <name>: one asset object, laid out as the releases API does
# (the uploader object after the name).
asset() {
	cat << EOF
    {
      "url": "${API}/assets/$1",
      "id": $1,
      "node_id": "RA_x$1",
      "name": "$2",
      "label": "",
      "uploader": { "login": "example", "id": 7, "url": "https://api.github.com/users/example" },
      "content_type": "application/gzip",
      "browser_download_url": "https://github.com/example/tool/releases/download/v1.0/$2"
    }
EOF
}
# release <asset objects>: a release with those assets, pretty-printed.
release() {
	local IFS=,
	printf '{\n  "url": "%s/1",\n  "tag_name": "v1.0",\n  "assets": [\n%s\n  ]\n}\n' "${API}" "$*"
}
SEVERAL=$(release "$(asset 101 "${NAME}.sig")" "$(asset 202 "${NAME}")" "$(asset 303 tool_1.0_checksums.txt)")

# ---- the primary download ----
reset
serve "${REL}" "${BODY}"
run "${REL}" "${SUM}"
check "primary: served, checksum ok" eq "${RC}/${GOT}" "0/${BODY}"
check "primary: one call, no fallback" eq "${LOG}" "get ${REL} -"

reset
serve "${REL}" "${BODY}"
run "${REL}" "${BAD}"
check "primary: a wrong checksum fails" ne "${RC}" 0
check "primary: a wrong checksum takes no fallback" eq "${LOG}" "get ${REL} -"

# ---- a failed GitHub release download, recovered through the API ----
reset
serve "${LOOKUP}" "${SEVERAL}"
serve "${ASSET}" "${BODY}"
run "${REL}" "${SUM}"
check "fallback: served, checksum ok" eq "${RC}/${GOT}" "0/${BODY}"
check "fallback: the middle asset of three, not the .sig before it" \
	eq "${LOG}" "$(calls "get ${REL} -" "get ${LOOKUP} ${JSON}" "get ${ASSET} ${OCTET}")"
check "fallback: says so" has "${ERR}" "trying the GitHub API asset endpoint"
check "fallback: no redirect lookup for a release URL" lacks "${LOG}" redirect

reset
serve "${LOOKUP}" "$(release "$(asset 101 a.txt)" "$(asset 202 "${NAME}")")"
serve "${ASSET}" "${BODY}"
run "${REL}" "${SUM}"
check "fallback: the last asset of two" eq "${RC}/${GOT}" "0/${BODY}"

reset
serve "${LOOKUP}" "${SEVERAL}"
serve "${ASSET}" 'tampered bytes'
run "${REL}" "${SUM}"
check "fallback: a checksum mismatch fails" ne "${RC}" 0
check "fallback: the mismatch is the asset endpoint's" \
	eq "${LOG}" "$(calls "get ${REL} -" "get ${LOOKUP} ${JSON}" "get ${ASSET} ${OCTET}")"
check "fallback: sha256sum reports it" has "$(< "${T}/stdout")" FAILED

# ---- release JSON the fallback refuses; none reaches an asset endpoint ----
# json_case <what> <json> <message>: the lookup serves <json>; fetch fails
# with <message> after the lookup and downloads nothing more.
json_case() {
	reset
	serve "${LOOKUP}" "$2"
	serve "${ASSET}" "${BODY}"
	run "${REL}" "${SUM}"
	check "json: $1 fails" ne "${RC}" 0
	check "json: $1, no asset download" eq "${LOG}" "$(calls "get ${REL} -" "get ${LOOKUP} ${JSON}")"
	check "json: $1, says '$3'" has "${ERR}" "$3"
}
json_case "the asset missing" "$(release "$(asset 101 "${NAME}.sig")" "$(asset 303 b.txt)")" "no asset ${NAME}"
json_case "no assets" '{"tag_name":"v1.0","assets":[]}' "no asset ${NAME}"
json_case "an HTML error page" '<html><body>504 Gateway Time-out</body></html>' "no asset ${NAME}"
json_case "truncated before the asset" "${SEVERAL:0:200}" "no asset ${NAME}"
json_case "truncated inside the asset's url" "${SEVERAL%%/assets/202*}/assets/20" "no asset ${NAME}"
json_case "the name before the url" \
	"{\"assets\":[{\"name\":\"${NAME}\"},{\"url\":\"${API}/assets/202\"}]}" "no asset id for ${NAME}"
json_case "the asset without a url" \
	"$(release "$(asset 101 a.txt)" "{\"id\":202,\"name\":\"${NAME}\"}")" "no asset id for ${NAME}"
json_case "a non-numeric id" \
	"{\"assets\":[{\"url\":\"${API}/assets/abc\",\"name\":\"${NAME}\"}]}" "bad asset id for ${NAME}"
json_case "a path in the id" \
	"{\"assets\":[{\"url\":\"${API}/assets/../202\",\"name\":\"${NAME}\"}]}" "bad asset id for ${NAME}"
json_case "an empty id" \
	"{\"assets\":[{\"url\":\"${API}/assets/\",\"name\":\"${NAME}\"}]}" "bad asset id for ${NAME}"

# ---- API failures ----
reset
refuse "${LOOKUP}" 22
serve "${ASSET}" "${BODY}"
run "${REL}" "${SUM}"
check "api: a failed release lookup fails" ne "${RC}" 0
check "api: a failed release lookup, no asset download" \
	eq "${LOG}" "$(calls "get ${REL} -" "get ${LOOKUP} ${JSON}")"

reset
serve "${LOOKUP}" "${SEVERAL}"
refuse "${ASSET}" 56
run "${REL}" "${SUM}"
check "api: a failed asset download fails" ne "${RC}" 0
check "api: a failed asset download, after the lookup" \
	eq "${LOG}" "$(calls "get ${REL} -" "get ${LOOKUP} ${JSON}" "get ${ASSET} ${OCTET}")"

reset
NESTED=https://github.com/example/tool/extra/releases/download/v1.0/${NAME}
run "${NESTED}" "${SUM}"
check "api: a release URL with a nested repo path fails, no lookup" \
	eq "${RC}/${LOG}" "1/get ${NESTED} -"

# ---- a URL that is not a GitHub release ----
OTHER=https://downloads.example.com/dist/tool-1.0-bin.zip
reset
run "${OTHER}" "${SUM}"
check "other: no redirect fails" ne "${RC}" 0
check "other: no redirect, no fallback" \
	eq "${LOG}" "$(calls "get ${OTHER} -" "redirect ${OTHER} -")"

reset
refuse "${OTHER}" 6
run "${OTHER}" "${SUM}"
check "other: a failed redirect lookup fails, no fallback" \
	eq "${RC}/${LOG}" "1/$(calls "get ${OTHER} -" "redirect ${OTHER} -")"

reset
redirect "${OTHER}" https://mirror.example.net/tool-1.0-bin.zip
run "${OTHER}" "${SUM}"
check "other: a redirect elsewhere fails, no fallback" \
	eq "${RC}/${LOG}" "1/$(calls "get ${OTHER} -" "redirect ${OTHER} -")"

TARGET=https://github.com/example/tool-distributions/releases/download/v1.0/tool-1.0-bin.zip
DLOOKUP=https://api.github.com/repos/example/tool-distributions/releases/tags/v1.0
DASSET=https://api.github.com/repos/example/tool-distributions/releases/assets/202
DJSON=$(release "$(asset 101 tool-1.0-all.zip)" "$(asset 202 tool-1.0-bin.zip)" "$(asset 303 tool-1.0-src.zip)")
DJSON=${DJSON//\/repos\/example\/tool\//\/repos\/example\/tool-distributions\/}
reset
redirect "${OTHER}" "${TARGET}"
serve "${DLOOKUP}" "${DJSON}"
serve "${DASSET}" "${BODY}"
run "${OTHER}" "${SUM}"
check "redirect: to a GitHub release, served by the fallback" eq "${RC}/${GOT}" "0/${BODY}"
check "redirect: the API of the redirect target" \
	eq "${LOG}" "$(calls "get ${OTHER} -" "redirect ${OTHER} -" "get ${DLOOKUP} ${JSON}" "get ${DASSET} ${OCTET}")"
check "redirect: says so" has "${ERR}" "redirects to ${TARGET}"

reset
redirect "${OTHER}" "${TARGET}"
serve "${DLOOKUP}" "${DJSON}"
serve "${DASSET}" 'tampered bytes'
run "${OTHER}" "${SUM}"
check "redirect: a checksum mismatch after the fallback fails" ne "${RC}" 0

# A call without the retry flags logs `noretry <url>` and fails, so each exact
# LOG check above also checks the flags on every call.

if [ "${FAILED}" != 0 ]; then
	echo "fetch-test: FAILED"
	exit 1
fi
echo "fetch-test: ok"
