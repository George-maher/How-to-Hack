<?php

declare(strict_types=1);

namespace App\Services\Runner;

use RuntimeException;

/**
 * The Runner refused the job, or could not be reached.
 *
 * Always mapped to an explicit `unavailable`/`failed` scanner outcome — never to
 * "the scan finished with no findings".
 */
final class RunnerRejected extends RuntimeException
{
    public function __construct(
        public readonly string $reason,
        string $message,
    ) {
        parent::__construct($message);
    }
}
