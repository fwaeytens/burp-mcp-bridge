#!/usr/bin/env bash
# Set the project version in both places that hold it:
#   extension/pom.xml     the extension (Version.java reads it at build time)
#   bridge/package.json   the Node bridge (+ bridge/package-lock.json, via npm)
#
# Usage: scripts/set-version.sh <version>      e.g. scripts/set-version.sh 2.10.0-abbbe.2
#
# A release is then: commit "Release <version>", tag v<version>, push the tag.
# .github/workflows/release.yml refuses a tag that does not match both files.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <version>   (e.g. 2.10.0-abbbe.2, no leading v)" >&2
  exit 2
fi
version=$1
case $version in
  v*) echo "error: give the version without the leading v ($version)" >&2; exit 2 ;;
esac
# Strict semver, checked BEFORE anything is written: Maven takes any string,
# while npm refuses some (1.2.3-a..b) and silently rewrites others (1.2.3-01
# becomes 1.2.3-1), either of which would leave the two halves disagreeing.
# Numbers have no leading zeros; pre-release identifiers are non-empty.
num='(0|[1-9][0-9]*)'
ident="($num|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
if ! [[ $version =~ ^$num\.$num\.$num(-$ident(\.$ident)*)?$ ]]; then
  echo "error: not a strict semver version: $version" >&2
  exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)

# npm first, and Maven only once npm has written exactly this version.
(cd "$root/bridge" && npm version "$version" --no-git-tag-version --allow-same-version >/dev/null)
written=$(node -p "require('$root/bridge/package.json').version")
if [ "$written" != "$version" ]; then
  echo "error: npm wrote $written, not $version; extension/pom.xml left unchanged" >&2
  exit 1
fi
mvn -B -q -f "$root/extension/pom.xml" versions:set \
  -DnewVersion="$version" -DgenerateBackupPoms=false

pom_version=$(mvn -B -q -f "$root/extension/pom.xml" help:evaluate \
  -Dexpression=project.version -DforceStdout)
pkg_version=$(node -p "require('$root/bridge/package.json').version")
lock_version=$(node -p "require('$root/bridge/package-lock.json').version")
echo "extension/pom.xml:        $pom_version"
echo "bridge/package.json:      $pkg_version"
echo "bridge/package-lock.json: $lock_version"
for v in "$pom_version" "$pkg_version" "$lock_version"; do
  [ "$v" = "$version" ] || { echo "error: version not applied everywhere" >&2; exit 1; }
done
