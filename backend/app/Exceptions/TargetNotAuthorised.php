<?php

declare(strict_types=1);

namespace App\Exceptions;

use App\Security\Target\ScopeDecision;
use RuntimeException;

/**
 * Thrown when a destination fails the target policy.
 *
 * Carries the decision so the API can return a precise, client-safe code and
 * the UI can explain *why* a target was blocked. Never 500 — a blocked target
 * is an expected, correctly-handled outcome.
 */
class TargetNotAuthorised extends RuntimeException
{
    private function __construct(
        public readonly ScopeDecision $decision,
        string $message,
    ) {
        parent::__construct($message);
    }

    public static function fromDecision(ScopeDecision $decision): self
    {
        return new self($decision, $decision->message());
    }

    public function httpStatus(): int
    {
        // 403: the caller is authenticated but not permitted to reach this destination.
        return 403;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'message' => $this->decision->message(),
            'code' => $this->decision->code(),
            'reason' => $this->decision->reason->value,
            'host' => $this->decision->host,
        ];
    }
}
