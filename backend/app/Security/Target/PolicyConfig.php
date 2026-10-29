<?php

declare(strict_types=1);

namespace App\Security\Target;

use InvalidArgumentException;

/**
 * Immutable, validated operator policy.
 *
 * Construction throws on a malformed configuration so a typo fails at boot
 * rather than at scan time — and, more importantly, so a half-parsed rule can
 * never silently widen scope.
 */
final class PolicyConfig
{
    /**
     * @param  list<AllowlistRule>  $allowlist
     * @param  list<AllowlistRule>  $labExceptions
     */
    public function __construct(
        public readonly array $allowlist = [],
        public readonly array $labExceptions = [],
        public readonly bool $allowPrivateByDefault = false,
        public readonly int $maxResolvedAddresses = 8,
    ) {
        if ($this->allowPrivateByDefault) {
            // Deliberately not supported: "allow all private networks" is the
            // exact switch that turns a scanner into an internal-port-scan
            // service. Operators use scoped lab exceptions instead.
            throw new InvalidArgumentException(
                'allow_private_by_default is not supported; use narrowly scoped lab exceptions.',
            );
        }

        if ($this->maxResolvedAddresses < 1 || $this->maxResolvedAddresses > 64) {
            throw new InvalidArgumentException('max_resolved_addresses must be between 1 and 64.');
        }
    }

    /**
     * @param  array<string, mixed>  $config  the `security` config array
     */
    public static function fromArray(array $config): self
    {
        $allowlist = [];
        foreach (array_values($config['allowlist'] ?? []) as $index => $entry) {
            $allowlist[] = AllowlistRule::fromConfig($entry, (int) $index, false);
        }

        $exceptions = [];
        foreach (array_values($config['lab_exceptions'] ?? []) as $index => $entry) {
            $exceptions[] = AllowlistRule::fromConfig($entry, (int) $index, true);
        }

        return new self(
            allowlist: $allowlist,
            labExceptions: $exceptions,
            allowPrivateByDefault: (bool) ($config['allow_private_by_default'] ?? false),
            maxResolvedAddresses: (int) ($config['max_resolved_addresses'] ?? 8),
        );
    }

    /**
     * The operator-facing summary of what this instance may scan. Contains no
     * secrets; safe to expose to the authenticated UI.
     *
     * @return array<string, mixed>
     */
    public function describe(): array
    {
        return [
            'allowlist' => array_map(static fn (AllowlistRule $r) => $r->toArray(), $this->allowlist),
            'lab_exceptions' => array_map(static fn (AllowlistRule $r) => $r->toArray(), $this->labExceptions),
            'private_by_default' => false,
            'max_resolved_addresses' => $this->maxResolvedAddresses,
        ];
    }
}
