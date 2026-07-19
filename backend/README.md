# HowToHack - Backend

Enterprise-grade security scanning platform backend.

## Requirements

- PHP 8.2+
- Composer
- Redis (for queues and caching)
- MySQL or SQLite

## Installation

```bash
composer install
cp .env.example .env
php artisan key:generate
php artisan migrate
```

## Running

```bash
# Start API server
php artisan serve

# Start queue worker (separate terminal)
php artisan queue:work --tries=3 --timeout=120

# Development mode (server + queue + logs + Vite)
composer run dev
```

## Running Tests

```bash
composer run test
```

## API Endpoints

See `docs/api.md` for full API documentation.

## Architecture

See `docs/architecture.md` for architecture overview.

## Adding Scanners

See `docs/scanner-plugin.md` for scanner plugin development guide.
