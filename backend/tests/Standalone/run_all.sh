#!/usr/bin/env sh
# Runs the standalone (dependency-free) security tests. Requires only php.
set -eu
cd "$(dirname "$0")/../.."
status=0
for f in tests/Standalone/*_test.php; do
  echo "== $f"
  php "$f" || status=1
done
exit "$status"
