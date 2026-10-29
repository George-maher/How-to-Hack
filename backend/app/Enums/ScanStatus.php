<?php

declare(strict_types=1);

namespace App\Enums;

/**
 * Explicit scan lifecycle.
 *
 * Transitions are validated in application code (Scan::transitionTo) and are
 * the only supported way to change state. Terminal states cannot be left.
 */
enum ScanStatus: string
{
    /** Created and queued for orchestration. */
    case Queued = 'queued';

    /** Contains at least one active scanner and is waiting for operator approval. */
    case AwaitingApproval = 'awaiting_approval';

    /** A worker is orchestrating/running scanners. */
    case Running = 'running';

    /** Cancellation was accepted; scanners are being stopped. */
    case CancelRequested = 'cancel_requested';

    case Completed = 'completed';
    case Failed = 'failed';
    case Cancelled = 'cancelled';
    case TimedOut = 'timed_out';

    public function isTerminal(): bool
    {
        return in_array($this, [self::Completed, self::Failed, self::Cancelled, self::TimedOut], true);
    }

    /**
     * States in which a scan is still "in flight" from the user's perspective.
     */
    public function isInFlight(): bool
    {
        return in_array($this, [self::AwaitingApproval, self::Queued, self::Running, self::CancelRequested], true);
    }

    public function isActiveExecution(): bool
    {
        return $this === self::Running;
    }

    public function canTransitionTo(self $target): bool
    {
        if ($target === $this) {
            return false;
        }

        return in_array($target, $this->allowedTransitions(), true);
    }

    /**
     * @return list<self>
     */
    public function allowedTransitions(): array
    {
        return match ($this) {
            self::AwaitingApproval => [self::Queued, self::Cancelled, self::Failed, self::TimedOut],
            self::Queued => [self::Running, self::AwaitingApproval, self::Cancelled, self::Failed, self::TimedOut],
            self::Running => [self::CancelRequested, self::Completed, self::Failed, self::TimedOut],
            self::CancelRequested => [self::Cancelled, self::Completed, self::Failed, self::TimedOut],
            self::Completed, self::Failed, self::Cancelled, self::TimedOut => [],
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Queued => 'Queued',
            self::AwaitingApproval => 'Awaiting approval',
            self::Running => 'Running',
            self::CancelRequested => 'Cancellation requested',
            self::Completed => 'Completed',
            self::Failed => 'Failed',
            self::Cancelled => 'Cancelled',
            self::TimedOut => 'Timed out',
        };
    }

    /**
     * Legacy value used by the pre-existing schema (`pending`).
     * Only used by the data migration; new code must not emit it.
     */
    public static function fromLegacy(string $value): self
    {
        return match ($value) {
            'pending' => self::Queued,
            default => self::from($value),
        };
    }
}
