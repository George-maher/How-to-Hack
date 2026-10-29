<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Exceptions\ApprovalRequired;
use App\Http\Controllers\Controller;
use App\Http\Resources\ScanApprovalResource;
use App\Models\Scan;
use App\Models\ScanApproval;
use App\Services\Security\ApprovalService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

/**
 * The only path that can turn a pending approval into a granted one.
 *
 * The AI planner and the queue worker cannot reach this class; nothing in the
 * scan pipeline calls grant().
 */
class ApprovalController extends Controller
{
    public function __construct(private readonly ApprovalService $approvals)
    {
    }

    public function index(Request $request): AnonymousResourceCollection
    {
        $status = $request->query('status');

        $query = ScanApproval::query()
            ->whereHas('project', fn ($q) => $q->where('user_id', $request->user()->getKey()))
            ->latest('id');

        if (is_string($status) && $status !== '') {
            $query->where('status', $status);
        }

        return ScanApprovalResource::collection($query->limit(100)->get());
    }

    public function show(ScanApproval $approval): ScanApprovalResource
    {
        $this->authorizeApproval($approval);

        return new ScanApprovalResource($approval);
    }

    public function approve(Request $request, ScanApproval $approval): JsonResponse
    {
        $this->authorizeApproval($approval);

        $note = $request->input('note');
        if ($note !== null && ! is_string($note)) {
            return response()->json(['message' => 'The note must be text.', 'code' => 'invalid_note'], 422);
        }

        try {
            $granted = $this->approvals->grant($approval, $request->user(), $note);
        } catch (ApprovalRequired $e) {
            return response()->json($e->toArray(), 409);
        } catch (\RuntimeException $e) {
            return response()->json([
                'message' => $e->getMessage(),
                'code' => 'approval_not_actionable',
            ], 409);
        }

        $scan = $granted->scan;
        if ($scan instanceof Scan) {
            \App\Jobs\RunScanJob::dispatch($scan);
        }

        return response()->json([
            'message' => 'Approved. The scan has been queued.',
            'approval' => new ScanApprovalResource($granted),
            'scan_status' => $scan?->fresh()?->statusEnum()->value,
        ]);
    }

    public function reject(Request $request, ScanApproval $approval): JsonResponse
    {
        $this->authorizeApproval($approval);

        $note = $request->input('note');

        $rejected = $this->approvals->reject($approval, $request->user(), is_string($note) ? $note : null);

        return response()->json([
            'message' => 'Rejected. The scan will not run.',
            'approval' => new ScanApprovalResource($rejected),
        ]);
    }

    private function authorizeApproval(ScanApproval $approval): void
    {
        $approval->loadMissing('project');

        abort_unless(
            $approval->project !== null && (int) $approval->project->user_id === (int) request()->user()->getKey(),
            403,
            'You may not act on this approval.',
        );
    }
}
