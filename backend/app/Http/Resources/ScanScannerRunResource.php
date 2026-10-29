<?php

declare(strict_types=1);

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ScanScannerRunResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'scanner' => $this->scanner,
            'intrusiveness' => $this->intrusiveness,
            'outcome' => $this->outcome,
            // Never present a failed run as "no findings".
            'inconclusive' => $this->isInconclusive(),
            'findings_count' => $this->findings_count,
            'exit_code' => $this->exit_code,
            'duration_ms' => $this->duration_ms,
            'error' => $this->error,
            'diagnostics' => $this->diagnostics,
            'started_at' => $this->started_at,
            'finished_at' => $this->finished_at,
        ];
    }
}
