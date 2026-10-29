<?php

declare(strict_types=1);

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ScanApprovalResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'scan_id' => $this->scan_id,
            'project_id' => $this->project_id,
            'status' => $this->status,
            'target_host' => $this->target_host,
            'target_ports' => $this->target_ports,
            'tools' => $this->tools,
            'options' => $this->options,
            'fingerprint' => $this->fingerprint,
            'scope_rule' => $this->scope_rule,
            'requested_at' => $this->requested_at,
            'expires_at' => $this->expires_at,
            'expired' => $this->isRequestExpired(),
            'decided_at' => $this->decided_at,
            'decision_note' => $this->decision_note,
        ];
    }
}
