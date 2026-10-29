<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Contracts\ScanResultRepositoryInterface;
use App\Http\Controllers\Controller;
use App\Http\Resources\ScanResultResource;
use App\Models\Scan;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

class ScanResultController extends Controller
{
    public function __construct(
        private readonly ScanResultRepositoryInterface $scanResultRepository,
    ) {
    }

    public function index(Scan $scan): AnonymousResourceCollection
    {
        $this->authorize('viewResults', $scan);

        return ScanResultResource::collection(
            $this->scanResultRepository->findByScan((int) $scan->getKey())
        );
    }

    public function severityBreakdown(Scan $scan): JsonResponse
    {
        $this->authorize('viewResults', $scan);

        return response()->json(
            $this->scanResultRepository->severityBreakdown((int) $scan->getKey())
        );
    }
}
