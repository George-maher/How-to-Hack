<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ProjectResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->user_id,
            'name' => $this->name,
            'target_url' => $this->target_url,
            'description' => $this->description,
            'status' => $this->status,
            'scans_count' => $this->whenCounted('scans', fn () => $this->scans()->count()),
            'latest_scan' => new ScanResource($this->whenLoaded('latestScan')),
            'scans' => ScanResource::collection($this->whenLoaded('scans')),
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at,
        ];
    }
}
