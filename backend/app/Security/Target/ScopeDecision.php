<?php

declare(strict_types=1);

namespace App\Security\Target;

/**
 * The result of evaluating one target.
 *
 * A decision is always explicit: either `allowed` is true and `reason` is a
 * success reason, or it is false and `reason` explains the refusal. There is no
 * "unknown" state — an unexpected condition produces `policy_error`, which is a
 * denial.
 */
final class ScopeDecision
{
    /**
     * @param  list<string>  $resolvedIps  canonical IP literals, in resolution order
     * @param  list<int>  $ports  the ports this decision covers
     */
    public function __construct(
        public readonly bool $allowed,
        public readonly ScopeReason $reason,
        public readonly string $host,
        public readonly array $resolvedIps = [],
        public readonly array $ports = [],
        public readonly ?string $matchedRule = null,
        public readonly string $detail = '',
    ) {
    }

    /**
     * @param  list<string>  $resolvedIps
     * @param  list<int>  $ports
     */
    public static function allow(
        string $host,
        array $resolvedIps,
        array $ports,
        ScopeReason $reason = ScopeReason::Allowed,
        ?string $matchedRule = null,
    ): self {
        return new self(true, $reason, $host, $resolvedIps, $ports, $matchedRule, $reason->message());
    }

    /**
     * @param  list<string>  $resolvedIps
     * @param  list<int>  $ports
     */
    public static function deny(
        ScopeReason $reason,
        string $host = '',
        array $resolvedIps = [],
        array $ports = [],
        ?string $detail = null,
    ): self {
        return new self(false, $reason, $host, $resolvedIps, $ports, null, $detail ?? $reason->message());
    }

    public function code(): string
    {
        return $this->reason->value;
    }

    /**
     * The operator-facing sentence for this decision.
     *
     * Same value as `detail`; the alias exists because call sites read better
     * as `$decision->message()`.
     */
    public function message(): string
    {
        return $this->detail;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'reason' => $this->reason->value,
            'host' => $this->host,
            'resolved_ips' => $this->resolvedIps,
            'ports' => $this->ports,
            'matched_rule' => $this->matchedRule,
            'detail' => $this->detail,
        ];
    }
}
