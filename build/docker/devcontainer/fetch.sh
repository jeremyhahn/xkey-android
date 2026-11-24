#!/bin/sh
# fetch <url> <file> <sha256>: download with retries, falling back to the GitHub release API asset; the SHA-256 is the only trust anchor (tested by scripts/fetch-test.sh).
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
