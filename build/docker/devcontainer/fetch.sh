#!/bin/sh
# fetch <url> <file> <sha256>: download over https, retrying transient errors
# (5 retries, 10 s apart, 30 s connect timeout), and refuse a mismatch. When a
# GitHub release download (https://github.com/<owner>/<repo>/releases/download/
# <tag>/<file>) still fails, it asks the public releases API for the asset's id
# and downloads the same asset from the API asset endpoint, with the same
# retries. The id is cut from the JSON with shell parameter expansion (the
# image's fetch stage has no jq or python): the last .../releases/assets/<id>
# URL before "name":"<file>", inside the same asset object. Any other URL fails
# as before, unless it redirects to a GitHub release URL: then the fallback
# runs on that redirect target (services.gradle.org answers 307 with one). The
# target is read without following it, and only one hop. The SHA-256 check is
# the same for every path and is the only trust anchor.
#
# The Dockerfile installs this as /usr/local/bin/fetch; image-tag.sh hashes it
# into the toolchain tag. scripts/fetch-test.sh (make lint-gates) tests it
# offline against a stub curl.
set -eu
retry() { curl --proto '=https' --tlsv1.2 --retry 5 --retry-delay 10 --retry-all-errors --connect-timeout 30 "$@"; }
get() { retry -fsSL "$@"; }
if ! get -o "$2" "$1"; then
  url=$1
  case "$url" in
    https://github.com/*/*/releases/download/*/*) ;;
    *)
      url=$(retry -sS -o /dev/null -w '%{redirect_url}' "$1") || exit 1
      case "$url" in
        https://github.com/*/*/releases/download/*/*) echo "fetch: $1 redirects to $url" >&2 ;;
        *) exit 1 ;;
      esac
      ;;
  esac
  path=${url#https://github.com/}
  repo=${path%%/releases/download/*}
  tag=${path#*/releases/download/}
  name=${tag##*/}
  tag=${tag%/*}
  case "$repo" in */*/*) exit 1 ;; esac
  echo "fetch: $1 failed; trying the GitHub API asset endpoint" >&2
  json=$(get -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/$repo/releases/tags/$tag" | tr -d ' \t\r\n')
  head=${json%%"\"name\":\"$name\""*}
  [ "$head" != "$json" ] || { echo "fetch: no asset $name in $repo $tag" >&2; exit 1; }
  id=${head##*/releases/assets/}
  case "$id" in *[{}]*) echo "fetch: no asset id for $name" >&2; exit 1 ;; esac
  id=${id%%\"*}
  case "$id" in ''|*[!0-9]*) echo "fetch: bad asset id for $name" >&2; exit 1 ;; esac
  get -H 'Accept: application/octet-stream' -o "$2" "https://api.github.com/repos/$repo/releases/assets/$id"
fi
echo "$3  $2" | sha256sum -c -
