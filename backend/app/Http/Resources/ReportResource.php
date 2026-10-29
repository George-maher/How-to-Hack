<?php

declare(strict_types=1);

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * Report metadata plus summaries.
 *
 * `scan_data` (the full evidence bundle) is deliberately excluded from listings
 * and only returned on the detail endpoint, because it can be large and it is
 * the most sensitive field in the response.
 */
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
            'format' => $this->format,
            'status' => $this->status,
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at,
            'scan_data' => $this->when(
                $request->routeIs('reports.show') || $request->boolean('include_scan_data'),
                fn () => $this->scan_data,
            ),
            'ai_analysis' => $this->when(
                $request->routeIs('reports.show') || $request->boolean('include_scan_data'),
                fn () => $this->ai_analysis,
            ),
            'scan' => new ScanResource($this->whenLoaded('scan')),
        ];
    }
}
