<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Security configuration
|--------------------------------------------------------------------------
|
| The target policy is deny-by-default. Nothing is scannable until an operator
| lists it here (or in the database-backed override, see ACTIVE_ALLOWLIST_SOURCE).
|
| IMPORTANT: local lab exceptions are narrow by construction:
|   - one exact host each (hostname or IP literal, no CIDRs)
|   - explicit ports
|   - mandatory expiry
|
*/

return [

    /*
    | Anonymous self-registration. Off by default: this application scans
    | networks, so account creation is an operator action.
    */
    'allow_registration' => (bool) env('ALLOW_REGISTRATION', false),

    /*
    | Operator-managed allowlist.
    |
    | Each entry: host (required), ports (null = any), include_subdomains,
    | cidrs (optional address constraint).
    */
    'allowlist' => array_values(array_filter(array_map(
        static fn (string $entry) => ['host' => trim($entry)],
        array_filter(array_map('trim', explode(',', (string) env('SCAN_ALLOWLIST', '')))),
    ), static fn (array $rule) => $rule['host'] !== '')),

    /*
    | Local lab exceptions. JSON in the environment, for example:
    |
    | SCAN_LAB_EXCEPTIONS='[{"host":"127.0.0.1","ports":[8080],"expires_at":"2026-12-31T00:00:00Z","note":"local lab"}]'
    |
    | Invalid entries cause the application to fail closed (the exception is
    | ignored and reported) rather than silently widening access.
    */
    'lab_exceptions' => json_decode((string) env('SCAN_LAB_EXCEPTIONS', '[]'), true) ?: [],

    'max_resolved_addresses' => (int) env('SCAN_MAX_RESOLVED_ADDRESSES', 8),

    /*
    | Active-scan approvals.
    */
    'approvals' => [
        // How long an approval stays valid once granted.
        'ttl_minutes' => (int) env('SCAN_APPROVAL_TTL_MINUTES', 120),
        // How long an un-actioned approval request may sit before it expires.
        'request_ttl_minutes' => (int) env('SCAN_APPROVAL_REQUEST_TTL_MINUTES', 1440),
        // Free-form note length bound recorded in the audit trail.
        'note_max_length' => 500,
    ],

    /*
    | Scan execution bounds. These are enforced by the orchestrator and are the
    | numbers the queue/job timeouts are derived from.
    */
    'execution' => [
        'max_scanners_per_scan' => (int) env('SCAN_MAX_SCANNERS', 20),
        'max_duration_seconds' => (int) env('SCAN_MAX_DURATION', 900),
        'heartbeat_stale_seconds' => (int) env('SCAN_HEARTBEAT_STALE_SECONDS', 300),
        'per_scanner_timeout_seconds' => (int) env('SCANNER_TIMEOUT', 120),
    ],

    /*
    | Runner service (isolated scanner execution).
    */
    'runner' => [
        'enabled' => (bool) env('RUNNER_ENABLED', true),
        'url' => rtrim((string) env('RUNNER_URL', 'http://runner:8080'), '/'),
        'secret' => (string) env('RUNNER_SECRET', ''),
        'timeout_seconds' => (int) env('RUNNER_HTTP_TIMEOUT', 330),
        'connect_timeout_seconds' => (int) env('RUNNER_CONNECT_TIMEOUT', 10),
    ],

    /*
    | Audit trail retention (days). Null keeps events indefinitely.
    */
    'audit' => [
        'retention_days' => env('AUDIT_RETENTION_DAYS') !== null ? (int) env('AUDIT_RETENTION_DAYS') : null,
    ],
];
