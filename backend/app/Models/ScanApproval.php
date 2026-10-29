<?php

declare(strict_types=1);

namespace App\Models;

use App\Security\Scan\ApprovalFingerprint;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

/**
 * An operator decision that a specific scan, against a specific target, with a
 * specific tool/option set, may execute — once.
 *
 * An approval is *not* a stored permission. It is a record of a decision tied
 * to a fingerprint; the execution path recomputes the fingerprint from the job
 * it is about to run and refuses to proceed if it no longer matches.
 */
class ScanApproval extends Model
{
    public const STATUS_PENDING = 'pending';
    public const STATUS_APPROVED = 'approved';
    public const STATUS_REJECTED = 'rejected';
    public const STATUS_EXPIRED = 'expired';
    public const STATUS_CONSUMED = 'consumed';

    protected $fillable = [
        'scan_id',
        'project_id',
        'user_id',
        'status',
        'target_url',
        'target_host',
        'target_ports',
        'tools',
        'options',
        'resolved_ips',
        'fingerprint',
        'scope_rule',
        'requested_at',
        'expires_at',
        'decided_at',
        'decided_by',
        'decision_note',
    ];

    protected function casts(): array
    {
        return [
            'target_ports' => 'array',
            'tools' => 'array',
            'options' => 'array',
            'resolved_ips' => 'array',
            'requested_at' => 'datetime',
            'expires_at' => 'datetime',
            'decided_at' => 'datetime',
        ];
    }

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }

    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function decider(): BelongsTo
    {
        return $this->belongsTo(User::class, 'decided_by');
    }

    public function isRequestExpired(): bool
    {
        if ($this->expires_at === null) {
            return true;
        }

        return $this->expires_at->isPast();
    }

    /**
     * Recompute the fingerprint the approval was granted for.
     */
    public function fingerprintFor(string $host, array $ports, array $tools, array $options = []): string
    {
        if ($host !== $this->target_host) {
            return '';
        }

        return ApprovalFingerprint::for($host, $ports, $tools, $options);
    }

    /**
     * An approval is usable only while it is approved, unexpired, unconsumed,
     * and its fingerprint still matches the plan about to run.
     */
    public function authorises(string $fingerprint): bool
    {
        return $this->status === self::STATUS_APPROVED
            && ! $this->isRequestExpired()
            && hash_equals((string) $this->fingerprint, $fingerprint);
    }

    public function scopeActionable($query)
    {
        return $query->where('status', self::STATUS_PENDING)
            ->where(fn ($q) => $q->whereNull('expires_at')->orWhere('expires_at', '>', now()));
    }

    public function idempotencyKey(): string
    {
        return Str::lower($this->fingerprint);
    }
}
