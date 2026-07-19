<?php

namespace App\Http\Controllers\Api;

use App\Contracts\ScanRepositoryInterface;
use App\Http\Controllers\Controller;
use App\Http\Resources\ScanResource;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

class ScanController extends Controller
{
    public function __construct(
        private readonly ScanRepositoryInterface $scanRepository,
    ) {}

    public function index(int $projectId): AnonymousResourceCollection
    {
        return ScanResource::collection(
            $this->scanRepository->findByProject($projectId)
        );
    }

    public function show(int $id): JsonResponse
    {
        $scan = $this->scanRepository->findWithResults($id);
        if (!$scan) {
            return response()->json(['message' => 'Scan not found'], 404);
        }
        return response()->json(new ScanResource($scan));
    }

    public function cancel(int $id): JsonResponse
    {
        $scan = $this->scanRepository->findById($id);
        if (!$scan) {
            return response()->json(['message' => 'Scan not found'], 404);
        }

        if ($scan->isPending() || $scan->isRunning()) {
            $this->scanRepository->update($scan, [
                'status' => 'cancelled',
                'completed_at' => now(),
            ]);
            return response()->json(['message' => 'Scan cancelled']);
        }

        return response()->json(['message' => 'Scan cannot be cancelled'], 400);
    }
}
