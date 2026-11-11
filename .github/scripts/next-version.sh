#!/usr/bin/env bash
# Prints the next release version (vX.Y.Z) computed from the conventional
# commits since the latest release tag, or nothing if no commit warrants a
# release. Usage: next-version.sh [ref]   (default HEAD)
#
#   BREAKING CHANGE / type!:  major (minor while < v1)
#   feat:                     minor
#   fix: perf:                patch
#   anything else             no release
#
# The first release is v0.1.0. Going to v1.0.0, or to a new major version
# (which needs a /vN module path in Go), is never automatic: the script
# fails and the release must be cut by hand.
set -euo pipefail

ref="${1:-HEAD}"
last=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' "$ref" 2>/dev/null || true)
range="$ref"
[ -n "$last" ] && range="$last..$ref"

bump=0 # 0 none, 1 patch, 2 minor, 3 major
while IFS= read -r -d $'\x1e' commit; do
  commit="${commit#$'\n'}"
  subject="${commit%%$'\x1f'*}"
  body="${commit#*$'\x1f'}"
  if [[ "$subject" =~ ^[a-z]+(\([^\)]*\))?!: ]] || grep -qE '^BREAKING[ -]CHANGE:' <<<"$body"; then
    b=3
  elif [[ "$subject" =~ ^feat(\([^\)]*\))?: ]]; then
    b=2
  elif [[ "$subject" =~ ^(fix|perf)(\([^\)]*\))?: ]]; then
    b=1
  else
    b=0
  fi
  (( b > bump )) && bump=$b
done < <(git log --no-merges --format='%s%x1f%b%x1e' "$range")

(( bump == 0 )) && exit 0

if [ -z "$last" ]; then
  echo "v0.1.0"
  exit 0
fi

IFS=. read -r major minor patch <<<"${last#v}"
patch="${patch%%-*}"
if (( major == 0 )); then
  case $bump in
    3|2) minor=$((minor + 1)); patch=0 ;;
    1) patch=$((patch + 1)) ;;
  esac
else
  case $bump in
    3)
      echo "Breaking changes since $last need a new major version and a /v$((major + 1)) module path; release it by hand." >&2
      exit 1
      ;;
    2) minor=$((minor + 1)); patch=0 ;;
    1) patch=$((patch + 1)) ;;
  esac
fi
echo "v$major.$minor.$patch"
