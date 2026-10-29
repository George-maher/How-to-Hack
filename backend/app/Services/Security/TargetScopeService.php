<?php

declare(strict_types=1);

namespace App\Services\Security;

use App\Security\Target\PolicyConfig;
use App\Security\Target\ScopeDecision;
use App\Security\Target\TargetPolicy;
use Closure;

/**
 * Single source of truth for "may this application talk to this destination?".
 *
 * Every API path that accepts a target goes through here, and the Runner
 * re-evaluates the same policy independently before it executes anything. The
 * two must agree; the API-side check is a UX/permission filter, not the
 * security boundary.
 *
 * Policy changes (allowlist / lab exceptions) are audited by
 * LabExceptionStore; this class only reads them.
 */
final class TargetScopeService
{
    /** @var (Closure(string): list<string>)|null */
    private ?Closure $resolverOverride = null;

    public function __construct(
        private readonly AuditLogger $audit,
        private readonly LabExceptionStore $labExceptions,
    ) {
    }

    /**
     * Test seam: inject a deterministic resolver (no real DNS in tests).
     *
     * @param  (Closure(string): list<string>)|null  $resolver
     */
    public function useResolver(?Closure $resolver): void
    {
        $this->resolverOverride = $resolver;
    }

    public function policy(): TargetPolicy
    {
        return new TargetPolicy($this->config(), $this->resolverOverride);
    }

    public function config(): PolicyConfig
    {
        $raw = [
            'allowlist' => config('security.allowlist', []),
            // Env-configured plus operator-added exceptions, expired ones dropped.
            'lab_exceptions' => $this->labExceptions->all(),
            'max_resolved_addresses' => config('security.max_resolved_addresses', 8),
        ];

        return PolicyConfig::fromArray($raw);
    }

    /**
     * Evaluate a URL for the ports a scan intends to touch.
     *
     * @param  list<int>        $ports
     * @param  list<string>|null $pinnedIps
     */
    public function evaluate(string $url, array $ports = [], ?array $pinnedIps = null): ScopeDecision
    {
        return $this->policy()->evaluate($url, $ports, $pinnedIps);
    }

    /**
     * Convenience guard for controllers: throws a 403-mapped exception.
     *
     * @throws TargetNotAuthorised
     */
    public function assertAllowed(string $url, array $ports = []): ScopeDecision
    {
        $decision = $this->evaluate($url, $ports);

        if (! $decision->allowed) {
            $this->audit->denied(
                AuditLogger::SCOPE_DENIED,
                $decision->code(),
                ['target_url' => $url, 'ports' => $ports, 'host' => $decision->host],
            );

            throw TargetNotAuthorised::fromDecision($decision);
        }

        return $decision;
    }

    /**
     * The scope document handed to the Runner, which re-evaluates it
     * independently. Contains operator policy only.
     *
     * @return array{allowlist: list<array<string, mixed>>, lab_exceptions: list<array<string, mixed>>}
     */
    public function runnerScopeDocument(): array
    {
        $config = $this->config();

        return [
            'allowlist' => array_map(static fn ($rule) => $rule->toArray(), array_values($config->allowlist)),
            'lab_exceptions' => array_map(static fn ($rule) => $rule->toArray(), array_values($config->labExceptions)),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function describe(): array
    {
        $config = $this->config();

        return [
            'allowlist' => array_map(static fn ($rule) => $rule->toArray(), $config->allowlist),
            'lab_exceptions' => array_map(static fn ($rule) => $rule->toArray(), $config->labExceptions),
        ];
    }
}
