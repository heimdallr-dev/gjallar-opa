#!/bin/sh
# CI gate without a Gjallar server: scan, then decide with plain Rego.
# Needs: gjallar (CLI), syft, grype, conftest.
set -eu
IMAGE=${1:?usage: ci.sh <image>}
gjallar scan "$IMAGE" --json > scan.json
conftest test scan.json -p policy/scan --namespace gjallar.scan --data examples/gate.yaml
# Manifests before they reach the cluster (same checks Gjallar runs live):
conftest test deploy/*.yaml -p policy/posture --namespace gjallar.posture
