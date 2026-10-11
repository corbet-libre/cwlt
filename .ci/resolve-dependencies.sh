#!/usr/bin/env bash
# Resolve the changed integration graph; this is not a validation verdict.
set -euo pipefail
exec 2>&1
ARTIFACT_ROOT=${ARTIFACT_ROOT:-$(mktemp -d)}
# Add only the missing packages; keep every locked revision.
cargo metadata --all-features --format-version 1 > /dev/null
echo "---LOCK-BEGIN---"; cat Cargo.lock; echo "---LOCK-END---"
cargo metadata --locked --all-features --format-version 1 > dependency-metadata.json
cp Cargo.lock "$ARTIFACT_ROOT/resolve-dependencies-Cargo.lock"
cp dependency-metadata.json "$ARTIFACT_ROOT/resolve-dependencies-metadata.json"
sha256sum Cargo.lock
sha256sum dependency-metadata.json
echo 'Resolved dependency locks only; retain them in a commit and run verify.'
