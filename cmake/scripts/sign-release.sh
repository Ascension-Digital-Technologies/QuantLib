#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
ARTIFACT="${1:?artifact path required}"
KEY_HINT="${2:-operator-held-key}"
echo "Signing scaffold for $ARTIFACT"
echo "Use your release system with $KEY_HINT. Do not store private signing keys in this repository."
echo "Example: gpg --detach-sign --armor ${ARTIFACT}"
