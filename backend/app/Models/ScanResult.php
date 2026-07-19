<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ScanResult extends Model
{
    use HasFactory;
    protected $fillable = [
        'scan_id',
        'scanner_name',
        'severity',
        'title',
        'description',
        'details',
        'file_path',
    ];

    protected function casts(): array
    {
        return [
            'details' => 'array',
        ];
    }

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }
}
