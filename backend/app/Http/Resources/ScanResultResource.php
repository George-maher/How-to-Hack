<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ScanResultResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'scan_id' => $this->scan_id,
            'scanner_name' => $this->scanner_name,
            'severity' => $this->severity,
            'title' => $this->title,
            'description' => $this->description,
            'details' => $this->details,
            'created_at' => $this->created_at,
        ];
    }
}
