<?php

declare(strict_types=1);

namespace App\Models;

use App\DTOs\ScannerOutcome;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * One attempt at running one scanner within one scan.
 *
 * This row is what keeps "the process started", "the process finished", "the
 * output parsed" and "findings were found" separate facts.
 */
class ScanScannerRun extends Model
{
    protected $fillable = [
        'scan_id',
        'scanner',
        'intrusiveness',
        'outcome',
        'attempts',
        'exit_code',
        'duration_ms',
        'findings_count',
        'error',
        'stderr_excerpt',
        'diagnostics',
        'runner_job_id',
        'started_at',
        'finished_at',
    ];

    protected function casts(): array
    {
        return [
            'attempts' => 'integer',
            'exit_code' => 'integer',
            'duration_ms' => 'integer',
            'findings_count' => 'integer',
            'diagnostics' => 'array',
            'started_at' => 'datetime',
            'finished_at' => 'datetime',
        ];
    }

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }

    public function outcome(): ?ScannerOutcome
    {
        return ScannerOutcome::tryFrom((string) $this->outcome);
    }

    /**
     * True when this run proves nothing about the target either way.
     */
    public function isInconclusive(): bool
    {
        return $this->outcome()?->isSuccessful() !== true;
    }

    public function producedFindings(): bool
    {
        return ! $this->isInconclusive() && $this->findings_count > 0;
    }
}
