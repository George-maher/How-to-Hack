<?php

namespace App\Models;

use App\Enums\ScanStatus;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

class Project extends Model
{
    use HasFactory;
    use SoftDeletes;

    protected $fillable = [
        'user_id',
        'name',
        'target_url',
        'description',
        'status',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'metadata' => 'array',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function scans(): HasMany
    {
        return $this->hasMany(Scan::class);
    }

    public function latestScan()
    {
        return $this->hasOne(Scan::class)->latestOfMany();
    }

    public function activeScans()
    {
        return $this->scans()->whereIn('status', [
            ScanStatus::Pending->value,
            ScanStatus::Running->value,
        ]);
    }
}
