<?php

namespace App\Exceptions;

use RuntimeException;

class ScannerNotFoundException extends RuntimeException
{
    public function __construct(string $scannerName)
    {
        parent::__construct("Scanner '{$scannerName}' not found in registry.");
    }
}
