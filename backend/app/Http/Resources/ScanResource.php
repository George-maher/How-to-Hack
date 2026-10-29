<?php

declare(strict_types=1);

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * A scan, including its lifecycle state.
 *
 * `status` and `outcome_reason` are separate on purpose: "completed" plus
 * "partial" is a scan that ran but is missing coverage, while "failed" plus
 * "scanner_unavailable" is a scan that never proved anything. The UI renders
 * both.
 */
class ScanResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        $status = $this->statusEnum();

        return [
            'id' => $this->id,
            'project_id' => $this->project_id,
            'status' => $status->value,
            'status_label' => $status->label(),
            'is_terminal' => $status->isTerminal(),
            'outcome_reason' => $this->outcome_reason,
            'outcome_label' => $this->outcomeReasonLabel(),
            'failure_detail' => $this->failure_detail,
            'degraded' => (bool) $this->degraded,
            'ai_reasoning' => $this->ai_reasoning,
            'completed_scanners' => $this->completed_scanners,
            'results_count' => $this->results_count ?? $this->whenCounted('results', 0),
            'target_host' => $this->target_host,
            'target_ports' => $this->target_ports,
            'plan' => $this->plan,
            'started_at' => $this->started_at,
            'heartbeat_at' => $this->heartbeat_at,
            'cancel_requested_at' => $this->cancel_requested_at,
            'completed_at' => $this->completed_at,
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at,
            'scanner_runs' => ScanScannerRunResource::collection($this->whenLoaded('scannerRuns')),
            'approval' => new ScanApprovalResource($this->whenLoaded('approvedScope')),
            'project' => new ProjectResource($this->whenLoaded('project')),
        ];
    }

    private function outcomeReasonLabel(): ?string
    {
        if ($this->outcome_reason === null) {
            return null;
        }

        $reason = \App\Enums\ScanOutcomeReason::tryFrom((string) $this->outcome_reason);

        return $reason?->label();
    }
}
