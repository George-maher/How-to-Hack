<?php

namespace App\Exceptions;

use RuntimeException;

class ScannerExecutionException extends RuntimeException
{
    public function __construct(
        string $scannerName,
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null
    ) {
        parent::__construct(
            sprintf('[%s] %s', $scannerName, $message),
            $code,
            $previous
        );
    }
}
