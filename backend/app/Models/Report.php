<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Report extends Model
{
    protected $fillable = [
        'scan_id',
        'title',
        'executive_summary',
        'technical_summary',
        'recommendations',
        'scan_data',
        'ai_analysis',
        'format',
        'status',
    ];

    protected function casts(): array
    {
        return [
            'scan_data' => 'array',
            'ai_analysis' => 'array',
        ];
    }

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }
}
