#!/bin/sh
set -e

if [ -f .env ]; then
  php artisan config:clear 2>/dev/null || true
  php artisan route:clear 2>/dev/null || true
  php artisan view:clear 2>/dev/null || true

  echo "Running migrations..."
  php artisan migrate --force 2>/dev/null || echo "Migration skipped or already up to date"
fi

exec "$@"
