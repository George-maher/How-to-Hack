<?php

declare(strict_types=1);

namespace App\Services\Security;

use App\Security\Target\AllowlistRule;
use App\Security\Target\ScopeReason;
use Illuminate\Support\Facades\Cache;

/**
 * Operator-managed local lab exceptions, persisted in the cache store so they
 * survive restarts without adding a new operator UI or table.
 *
 * Deliberately narrow: one exact host per exception, explicit ports, mandatory
 * expiry, and no CIDR ranges. Every change is audited, because adding an
 * exception is the one operation that can make a private address reachable.
 */
final class LabExceptionStore
{
    private const KEY = 'security.lab_exceptions';

    public function __construct(private readonly AuditLogger $audit)
    {
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function all(): array
    {
        $stored = Cache::get(self::KEY, []);
        $stored = is_array($stored) ? $stored : [];

        // Configured exceptions (env) plus operator additions, with expired
        // entries dropped rather than silently retained.
        $configured = config('security.lab_exceptions', []);
        $merged = array_merge(is_array($configured) ? $configured : [], $stored);

        $live = [];
        foreach ($merged as $rule) {
            if (! is_array($rule)) {
                continue;
            }
            $expires = isset($rule['expires_at']) ? strtotime((string) $rule['expires_at']) : false;
            if ($expires === false || $expires < time()) {
                continue;
            }
            $live[] = $rule;
        }

        return $live;
    }

    /**
     * @param  list<int>  $ports
     *
     * @throws \InvalidArgumentException
     */
    public function add(string $host, array $ports, string $expiresAt, ?string $note = null, ?string $actor = null): array
    {
        $host = strtolower(trim($host));
        if ($host === '' || str_contains($host, '/') || str_contains($host, '*')) {
            throw new \InvalidArgumentException('A lab exception must name exactly one host, not a range or wildcard.');
        }

        // A hostname is allowed; the policy still pins it to whatever it
        // resolves to, and the exception only covers the listed ports.
        $ports = array_values(array_unique(array_filter(array_map('intval', $ports), static fn ($p) => $p >= 1 && $p <= 65535)));
        if ($ports === []) {
            throw new \InvalidArgumentException('A lab exception must list at least one port.');
        }

        $expires = strtotime($expiresAt);
        if ($expires === false || $expires <= time()) {
            throw new \InvalidArgumentException('A lab exception must expire in the future.');
        }

        $rule = [
            'id' => 'lab-'.substr(hash('sha256', $host.'|'.$expires), 0, 8),
            'host' => $host,
            'ports' => $ports,
            'expires_at' => gmdate('c', $expires),
            'note' => $note !== null ? mb_substr($note, 0, 200) : null,
            'lab' => true,
        ];

        $stored = Cache::get(self::KEY, []);
        $stored = is_array($stored) ? $stored : [];
        $stored[] = $rule;
        Cache::forever(self::KEY, $stored);

        $this->audit->record(AuditLogger::LAB_EXCEPTION_ADDED, 'allowed', [
            'host' => $host,
            'ports' => $ports,
            'expires_at' => $rule['expires_at'],
            'actor' => $actor,
        ]);

        return $rule;
    }

    public function revoke(string $id, ?string $actor = null): bool
    {
        $stored = Cache::get(self::KEY, []);
        $stored = is_array($stored) ? $stored : [];

        $remaining = array_values(array_filter(
            $stored,
            static fn ($rule) => is_array($rule) && ($rule['id'] ?? null) !== $id,
        ));

        if (count($remaining) === count($stored)) {
            return false;
        }

        Cache::forever(self::KEY, $remaining);

        $this->audit->record(AuditLogger::LAB_EXCEPTION_REVOKED, 'allowed', [
            'id' => $id,
            'actor' => $actor,
        ]);

        return true;
    }
}
