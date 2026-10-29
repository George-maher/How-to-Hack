<?php

declare(strict_types=1);

namespace App\Exceptions;

use App\Enums\ScanStatus;
use RuntimeException;

class InvalidScanTransition extends RuntimeException
{
    public static function between(string $scanId, ScanStatus $from, ScanStatus $to): self
    {
        return new self(sprintf(
            'Scan %s cannot move from "%s" to "%s".',
            $scanId,
            $from->value,
            $to->value,
        ));
    }

    public static function concurrent(string $scanId, ScanStatus $from, ScanStatus $to): self
    {
        return new self(sprintf(
            'Scan %s was moved out of "%s" by another process; refused "%s".',
            $scanId,
            $from->value,
            $to->value,
        ));
    }
}
