<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * Append-only security audit record.
 *
 * Secrets, tokens and full request payloads must never be written here; see
 * AuditLogger for the redaction rules.
 */
class AuditEvent extends Model
{
    public const UPDATED_AT = null;

    protected $fillable = [
        'event',
        'actor_type',
        'actor_id',
        'subject_type',
        'subject_id',
        'decision',
        'target',
        'context',
        'ip',
        'created_at',
    ];

    protected function casts(): array
    {
        return [
            'context' => 'array',
            'created_at' => 'datetime',
        ];
    }
}
