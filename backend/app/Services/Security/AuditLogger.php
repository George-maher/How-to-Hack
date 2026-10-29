<?php

declare(strict_types=1);

namespace App\Services\Security;

use App\Models\AuditEvent;
use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Append-only security audit trail.
 *
 * Rules enforced here rather than at every call site:
 *  - values are redacted by key name (tokens, secrets, passwords, cookies);
 *  - strings are truncated so a scanner payload cannot bloat the table;
 *  - logging failures never break the request they describe (but they are
 *    reported to the application log, because a silent audit gap is itself a
 *    security problem).
 */
final class AuditLogger
{
    private const REDACTED_KEYS = [
        'password',
        'password_confirmation',
        'token',
        'api_token',
        'access_token',
        'refresh_token',
        'authorization',
        'secret',
        'runner_secret',
        'ai_api_key',
        'api_key',
        'cookie',
        'set-cookie',
        'private_key',
    ];

    private const MAX_STRING = 500;
    private const MAX_CONTEXT_BYTES = 4000;

    /** Auth and authorisation. */
    public const AUTH_LOGIN_FAILED = 'auth.login_failed';

    public const AUTH_LOGIN_SUCCEEDED = 'auth.login_succeeded';

    public const AUTH_LOGOUT = 'auth.logout';

    public const AUTH_TOKEN_INVALID = 'auth.token_invalid';

    public const AUTHZ_DENIED = 'authz.denied';

    /** Policy. */
    public const SCOPE_ALLOWED = 'scope.allowed';

    public const SCOPE_DENIED = 'scope.denied';

    public const SCOPE_CONFIG_INVALID = 'scope.config_invalid';

    public const LAB_EXCEPTION_ADDED = 'scope.lab_exception_added';

    public const LAB_EXCEPTION_REVOKED = 'scope.lab_exception_revoked';

    /** Approvals. */
    public const APPROVAL_REQUESTED = 'approval.requested';

    public const APPROVAL_GRANTED = 'approval.granted';

    public const APPROVAL_REJECTED = 'approval.rejected';

    public const APPROVAL_EXPIRED = 'approval.expired';

    public const APPROVAL_MISMATCH = 'approval.mismatch';

    public const APPROVAL_CONSUMED = 'approval.consumed';

    /** Scan lifecycle. */
    public const SCAN_CREATED = 'scan.created';

    public const SCAN_STARTED = 'scan.started';

    public const SCAN_CANCEL_REQUESTED = 'scan.cancel_requested';

    public const SCAN_CANCELLED = 'scan.cancelled';

    public const SCAN_COMPLETED = 'scan.completed';

    public const SCAN_FAILED = 'scan.failed';

    public const SCAN_REAPED = 'scan.reaped';

    /** Runner / scanners. */
    public const RUNNER_REJECTED = 'runner.rejected';

    public const RUNNER_ERROR = 'runner.error';

    public const SCANNER_ERROR = 'scanner.error';

    public const SCANNER_UNAVAILABLE = 'scanner.unavailable';

    /** Reports. */
    public const REPORT_GENERATED = 'report.generated';

    public const REPORT_DOWNLOADED = 'report.downloaded';

    public const REPORT_DELETED = 'report.deleted';

    /**
     * @param  array<string, mixed>  $context
     */
    public function record(
        string $event,
        string $decision = 'recorded',
        array $context = [],
        ?Model $subject = null,
        ?User $actor = null,
        ?Request $request = null,
    ): void {
        try {
            $request ??= request();

            AuditEvent::create([
                'event' => mb_substr($event, 0, 64),
                'actor_type' => $actor !== null ? 'user' : 'system',
                'actor_id' => $actor?->getKey(),
                'subject_type' => $subject !== null ? class_basename($subject) : null,
                'subject_id' => $subject !== null ? (string) $subject->getKey() : null,
                'decision' => mb_substr($decision, 0, 16),
                'target' => $this->targetOf($context),
                'context' => $this->sanitise($context),
                'ip' => $request?->ip(),
                'created_at' => now(),
            ]);
        } catch (Throwable $e) {
            // Never let audit failure take down the request, but make it visible.
            Log::error('audit.write_failed', [
                'event' => $event,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public function denied(string $event, string $reason, array $context = [], ?Request $request = null): void
    {
        $this->record($event, 'denied', array_merge($context, ['reason' => $reason]), null, null, $request);
    }

    /**
     * @param  array<string, mixed>  $context
     * @return array<string, mixed>
     */
    private function sanitise(array $context): array
    {
        $clean = [];

        foreach ($context as $key => $value) {
            $lower = is_string($key) ? strtolower($key) : null;

            if ($lower !== null && in_array($lower, self::REDACTED_KEYS, true)) {
                $clean[$key] = '[redacted]';
                continue;
            }

            $clean[$key] = $this->sanitiseValue($value);
        }

        $encoded = json_encode($clean, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($encoded !== false && strlen($encoded) > self::MAX_CONTEXT_BYTES) {
            $clean = ['truncated' => true, 'keys' => array_keys($clean)];
        }

        return $clean;
    }

    private function sanitiseValue(mixed $value): mixed
    {
        if (is_string($value)) {
            return mb_substr($value, 0, self::MAX_STRING);
        }

        if (is_array($value)) {
            $out = [];
            foreach (array_slice($value, 0, 50, true) as $k => $v) {
                $lower = is_string($k) ? strtolower($k) : null;
                $out[$k] = ($lower !== null && in_array($lower, self::REDACTED_KEYS, true))
                    ? '[redacted]'
                    : $this->sanitiseValue($v);
            }

            return $out;
        }

        if (is_object($value) && ! $value instanceof \JsonSerializable) {
            return class_basename($value);
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function targetOf(array $context): ?string
    {
        foreach (['target', 'target_url', 'host', 'url'] as $key) {
            if (isset($context[$key]) && is_string($context[$key]) && $context[$key] !== '') {
                return mb_substr($context[$key], 0, 255);
            }
        }

        return null;
    }
}
