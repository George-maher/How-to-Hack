<?php

declare(strict_types=1);

namespace App\DTOs;

/**
 * The outcome vocabulary shared by the Runner response and the API.
 *
 * These strings are written to `scan_scanner_runs.outcome`; changing them is a
 * data migration, not a rename.
 */
enum ScannerOutcome: string
{
    /** The tool ran and its output was parsed. */
    case Completed = 'completed';

    /** The tool ran but its output could not be parsed. */
    case InvalidOutput = 'invalid_output';

    /** The tool exited non-zero. */
    case Failed = 'failed';

    /** The tool exceeded its time budget. */
    case TimedOut = 'timed_out';

    /** The tool was missing from the image, or the Runner was unreachable. */
    case Unavailable = 'unavailable';

    /** A policy check refused the target. */
    case Blocked = 'blocked';

    /** Cancellation stopped the tool. */
    case Cancelled = 'cancelled';

    /** The plan was exhausted before this scanner ran. */
    case Skipped = 'skipped';

    public function isSuccessful(): bool
    {
        return $this === self::Completed;
    }

    public function label(): string
    {
        return match ($this) {
            self::Completed => 'Ran',
            self::InvalidOutput => 'Output could not be parsed',
            self::Failed => 'Tool failed',
            self::TimedOut => 'Timed out',
            self::Unavailable => 'Tool unavailable',
            self::Blocked => 'Blocked by policy',
            self::Cancelled => 'Cancelled',
            self::Skipped => 'Skipped',
        };
    }
}
