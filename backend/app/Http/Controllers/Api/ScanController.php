<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Contracts\ScanRepositoryInterface;
use App\Enums\ScanStatus;
use App\Http\Controllers\Controller;
use App\Http\Resources\ScanResource;
use App\Jobs\CancelScanJob;
use App\Models\Project;
use App\Models\Scan;
use App\Services\Security\AuditLogger;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

class ScanController extends Controller
{
    public function __construct(
        private readonly ScanRepositoryInterface $scanRepository,
        private readonly AuditLogger $audit,
    ) {
    }

    public function index(Project $project): AnonymousResourceCollection
    {
        $this->authorize('view', $project);

        return ScanResource::collection($this->scanRepository->findByProject((int) $project->getKey()));
    }

    public function show(Scan $scan): JsonResponse
    {
        $this->authorize('view', $scan);

        return response()->json(new ScanResource($this->scanRepository->findWithResults((int) $scan->getKey())));
    }

    /**
     * Request cancellation.
     *
     * This records intent and asks the Runner to stop any live container. It
     * does not fabricate a `cancelled` state: the scan moves to
     * `cancel_requested` and only becomes `cancelled` when the worker (or the
     * reaper, after the worker is gone) confirms it.
     */
    public function cancel(Scan $scan): JsonResponse
    {
        $this->authorize('cancel', $scan);

        $scan->refresh();

        if ($scan->isTerminal()) {
            return response()->json([
                'message' => 'This scan has already finished.',
                'code' => 'scan_already_finished',
                'status' => $scan->statusEnum()->value,
            ], 409);
        }

        if ($scan->statusEnum() !== ScanStatus::CancelRequested) {
            $scan->transitionTo(ScanStatus::CancelRequested);
        }

        $this->audit->record(AuditLogger::SCAN_CANCEL_REQUESTED, 'requested', [
            'scan_id' => $scan->getKey(),
        ], $scan);

        CancelScanJob::dispatch((int) $scan->getKey());

        return response()->json([
            'message' => 'Cancellation requested. The scan will stop after the current step.',
            'status' => $scan->fresh()->statusEnum()->value,
            'confirmed' => false,
        ], 202);
    }
}
