<?php

declare(strict_types=1);

namespace App\Models;

use App\Enums\ScanOutcomeReason;
use App\Enums\ScanStatus;
use App\Exceptions\InvalidScanTransition;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\DB;

/**
 * A scan run.
 *
 * Status is a guarded state machine. transitionTo() validates the edge *and*
 * performs a compare-and-set on the persisted status, so two workers (a
 * duplicate delivery, a re-queued job) cannot both apply a transition.
 */
class Scan extends Model
{
    use HasFactory;

    protected $fillable = [
        'project_id',
        'status',
        'plan',
        'plan_fingerprint',
        'target_host',
        'target_ports',
        'resolved_ips',
        'ai_reasoning',
        'completed_scanners',
        'metadata',
        'started_at',
        'heartbeat_at',
        'cancel_requested_at',
        'completed_at',
        'outcome_reason',
        'failure_detail',
        'degraded',
    ];

    protected function casts(): array
    {
        return [
            'status' => ScanStatus::class,
            'plan' => 'array',
            'target_ports' => 'array',
            'resolved_ips' => 'array',
            'ai_reasoning' => 'array',
            'completed_scanners' => 'array',
            'metadata' => 'array',
            'started_at' => 'datetime',
            'heartbeat_at' => 'datetime',
            'cancel_requested_at' => 'datetime',
            'completed_at' => 'datetime',
            'degraded' => 'boolean',
        ];
    }

    /*
    |--------------------------------------------------------------------------
    | Relations
    |--------------------------------------------------------------------------
    */

    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }

    public function results(): HasMany
    {
        return $this->hasMany(ScanResult::class);
    }

    public function scannerRuns(): HasMany
    {
        return $this->hasMany(ScanScannerRun::class);
    }

    public function approvals(): HasMany
    {
        return $this->hasMany(ScanApproval::class);
    }

    /**
     * The approval that currently authorises execution, if any.
     */
    public function approvedScope(): \Illuminate\Database\Eloquent\Relations\HasOne
    {
        return $this->hasOne(ScanApproval::class)
            ->where('status', ScanApproval::STATUS_APPROVED)
            ->latestOfMany();
    }

    /*
    |--------------------------------------------------------------------------
    | State machine
    |--------------------------------------------------------------------------
    */

    public function statusEnum(): ScanStatus
    {
        $status = $this->status;

        return $status instanceof ScanStatus ? $status : ScanStatus::fromLegacy((string) $status);
    }

    public function isTerminal(): bool
    {
        return $this->statusEnum()->isTerminal();
    }

    public function isInFlight(): bool
    {
        return $this->statusEnum()->isInFlight();
    }

    /**
     * @param  array<string, mixed>  $attributes
     *
     * @throws InvalidScanTransition
     */
    public function transitionTo(ScanStatus $to, array $attributes = []): self
    {
        $from = $this->statusEnum();

        if (! $from->canTransitionTo($to)) {
            throw InvalidScanTransition::between((string) $this->getKey(), $from, $to);
        }

        $values = array_merge($this->timestampsFor($to), array_diff_key($attributes, ['status' => true]));
        $values['status'] = $to->value;

        // Compare-and-set: if another process already moved this row, the update
        // touches nothing and we refuse rather than replaying the edge.
        $affected = DB::table('scans')
            ->where('id', $this->getKey())
            ->where('status', $from->value)
            ->update($values);

        if ($affected !== 1) {
            throw InvalidScanTransition::concurrent((string) $this->getKey(), $from, $to);
        }

        $this->forceFill($values);
        $this->syncOriginal();

        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    private function timestampsFor(ScanStatus $to): array
    {
        $values = ['updated_at' => now()];

        if ($to === ScanStatus::Running) {
            $values['started_at'] = $this->started_at ?? now();
            $values['heartbeat_at'] = now();
        }

        if ($to === ScanStatus::CancelRequested) {
            $values['cancel_requested_at'] = now();
        }

        if ($to->isTerminal()) {
            $values['completed_at'] = now();
        }

        return $values;
    }

    /**
     * Record liveness. Called between scanners so the reaper can tell a slow
     * scan from an abandoned one.
     */
    public function heartbeat(): void
    {
        if (! $this->isInFlight()) {
            return;
        }

        DB::table('scans')->where('id', $this->getKey())->update([
            'heartbeat_at' => now(),
            'updated_at' => now(),
        ]);

        $this->forceFill(['heartbeat_at' => now()]);
    }

    public function isHeartbeatStale(): bool
    {
        if ($this->statusEnum() !== ScanStatus::Running) {
            return false;
        }

        $threshold = (int) config('security.execution.heartbeat_stale_seconds', 300);
        $last = $this->heartbeat_at ?? $this->started_at ?? $this->updated_at;

        return $last === null || $last->lt(now()->subSeconds($threshold));
    }

    public function outcomeReason(): ?ScanOutcomeReason
    {
        return $this->outcome_reason !== null
            ? ScanOutcomeReason::tryFrom((string) $this->outcome_reason)
            : null;
    }

    /*
    |--------------------------------------------------------------------------
    | Backwards-compatible helpers
    |--------------------------------------------------------------------------
    */

    public function isPending(): bool
    {
        return in_array($this->statusEnum(), [ScanStatus::Queued, ScanStatus::AwaitingApproval], true);
    }

    public function isRunning(): bool
    {
        return $this->statusEnum() === ScanStatus::Running;
    }

    public function isCompleted(): bool
    {
        return $this->statusEnum() === ScanStatus::Completed;
    }

    public function isFailed(): bool
    {
        return $this->statusEnum() === ScanStatus::Failed;
    }

    public function addReasoning(string $entry): void
    {
        $reasoning = is_array($this->ai_reasoning) ? $this->ai_reasoning : [];
        $reasoning[] = ['timestamp' => now()->toIso8601String(), 'message' => $entry];

        $this->update(['ai_reasoning' => $reasoning]);
    }
}
