<?php

namespace App\Http\Controllers\Api;

use App\Contracts\ScanResultRepositoryInterface;
use App\Http\Controllers\Controller;
use App\Http\Resources\ScanResultResource;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

class ScanResultController extends Controller
{
    public function __construct(
        private readonly ScanResultRepositoryInterface $scanResultRepository,
    ) {}

    public function index(int $scanId): AnonymousResourceCollection
    {
        return ScanResultResource::collection(
            $this->scanResultRepository->findByScan($scanId)
        );
    }

    public function severityBreakdown(int $scanId): JsonResponse
    {
        return response()->json(
            $this->scanResultRepository->countBySeverity($scanId)
        );
    }
}
