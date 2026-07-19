<?php

namespace App\Enums;

enum ScanStatus: string
{
    case Pending = 'pending';
    case Running = 'running';
    case Completed = 'completed';
    case Failed = 'failed';
    case Cancelled = 'cancelled';

    public function isTerminal(): bool
    {
        return in_array($this, [self::Completed, self::Failed, self::Cancelled]);
    }

    public function canTransitionTo(self $target): bool
    {
        return match ($this) {
            self::Pending => in_array($target, [self::Running, self::Cancelled]),
            self::Running => in_array($target, [self::Completed, self::Failed, self::Cancelled]),
            default => false,
        };
    }
}
