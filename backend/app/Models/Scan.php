<?php

namespace App\Models;

use App\Enums\ScanStatus;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Scan extends Model
{
    use HasFactory;
    protected $fillable = [
        'project_id',
        'status',
        'ai_reasoning',
        'completed_scanners',
        'metadata',
        'started_at',
        'completed_at',
    ];

    protected function casts(): array
    {
        return [
            'ai_reasoning' => 'array',
            'completed_scanners' => 'array',
            'metadata' => 'array',
            'started_at' => 'datetime',
            'completed_at' => 'datetime',
        ];
    }

    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }

    public function results(): HasMany
    {
        return $this->hasMany(ScanResult::class);
    }

    public function isPending(): bool
    {
        return $this->status === ScanStatus::Pending->value;
    }

    public function isRunning(): bool
    {
        return $this->status === ScanStatus::Running->value;
    }

    public function isCompleted(): bool
    {
        return $this->status === ScanStatus::Completed->value;
    }

    public function isFailed(): bool
    {
        return $this->status === ScanStatus::Failed->value;
    }

    public function markAsRunning(): void
    {
        $this->update([
            'status' => ScanStatus::Running->value,
            'started_at' => now(),
        ]);
    }

    public function markAsCompleted(): void
    {
        $this->update([
            'status' => ScanStatus::Completed->value,
            'completed_at' => now(),
        ]);
    }

    public function markAsFailed(): void
    {
        $this->update([
            'status' => ScanStatus::Failed->value,
            'completed_at' => now(),
        ]);
    }

    public function addReasoning(string $entry): void
    {
        $reasoning = $this->ai_reasoning ?? [];
        $reasoning[] = [
            'timestamp' => now()->toIso8601String(),
            'message' => $entry,
        ];
        $this->update(['ai_reasoning' => $reasoning]);
    }
}
