#!/usr/bin/env bash
# Build Procyon's release binaries into dist/.
#
#   scripts/release.sh v0.1.0
#
# Produces one binary per system and architecture, with the version and
# commit embedded (procyon --version prints them), and a SHA256SUMS file.
# The same script runs locally and in .github/workflows/release.yml, so a
# release can be checked on your machine before it is published.
set -euo pipefail

version=${1:-}
if [[ ! $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "usage: scripts/release.sh vMAJOR.MINOR.PATCH (got '${version}')" >&2
  exit 2
fi
if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
  echo "the working tree has uncommitted changes; commit or stash them first" >&2
  exit 2
fi

commit=$(git rev-parse --short=12 HEAD)
cd "$(git rev-parse --show-toplevel)"
rm -rf dist
mkdir -p dist

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  out="dist/procyon_${version#v}_${os}_${arch}"
  [[ $os == windows ]] && out+=".exe"
  echo "building $out"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X main.version=${version} -X main.commit=${commit}" \
    -o "$out" ./cmd/procyon
done

(cd dist && sha256sum procyon_* > SHA256SUMS)
echo "done: $(ls dist | wc -l) files in dist/"
