<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ReportResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'scan_id' => $this->scan_id,
            'title' => $this->title,
            'executive_summary' => $this->executive_summary,
            'technical_summary' => $this->technical_summary,
            'recommendations' => $this->recommendations,
            'scan_data' => $this->scan_data,
            'ai_analysis' => $this->ai_analysis,
            'format' => $this->format,
            'status' => $this->status,
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at,
            'scan' => new ScanResource($this->whenLoaded('scan')),
        ];
    }
}
