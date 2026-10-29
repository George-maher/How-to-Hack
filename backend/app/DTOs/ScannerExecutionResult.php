<?php

declare(strict_types=1);

namespace App\DTOs;

/**
 * The complete, honest record of one scanner execution.
 *
 * `outcome` answers "what happened", `findings` answers "what was found".
 * Keeping them apart is what stops a broken scanner from being reported as a
 * clean scan with zero findings.
 */
final class ScannerExecutionResult
{
    public function __construct(
        public readonly string $scanner,
        public readonly ScannerOutcome $outcome,
        public readonly ScanResultCollection $findings,
        public readonly ?int $exitCode = null,
        public readonly int $durationMs = 0,
        public readonly ?string $error = null,
        public readonly ?string $stderr = null,
        public readonly ?string $runnerJobId = null,
    ) {
    }

    public static function success(
        string $scanner,
        ScanResultCollection $findings,
        int $durationMs = 0,
        ?int $exitCode = null,
        ?string $stderr = null,
        ?string $runnerJobId = null,
    ): self {
        return new self(
            scanner: $scanner,
            outcome: ScannerOutcome::Completed,
            findings: $findings,
            exitCode: $exitCode,
            durationMs: $durationMs,
            stderr: $stderr,
            runnerJobId: $runnerJobId,
        );
    }

    public static function failure(
        string $scanner,
        string $outcome,
        ?string $error = null,
        int $durationMs = 0,
        ?int $exitCode = null,
        ?string $stderr = null,
        ?string $runnerJobId = null,
    ): self {
        return new self(
            scanner: $scanner,
            outcome: $outcome,
            findings: new ScanResultCollection(),
            exitCode: $exitCode,
            durationMs: $durationMs,
            error: $error,
            stderr: $stderr,
            runnerJobId: $runnerJobId,
        );
    }

    public function isSuccessful(): bool
    {
        return $this->outcome === ScannerOutcome::Completed;
    }

    /**
     * True when the scanner's silence proves nothing about the target.
     */
    public function isInconclusive(): bool
    {
        return ! $this->isSuccessful();
    }
}
