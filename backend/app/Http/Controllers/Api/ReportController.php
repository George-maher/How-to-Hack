<?php

namespace App\Http\Controllers\Api;

use App\Contracts\ReportRepositoryInterface;
use App\Http\Controllers\Controller;
use App\Http\Resources\ReportResource;
use App\Models\Scan;
use App\Services\Report\ReportGenerator;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

class ReportController extends Controller
{
    public function __construct(
        private readonly ReportRepositoryInterface $reportRepository,
        private readonly ReportGenerator $reportGenerator,
    ) {}

    public function all(): AnonymousResourceCollection
    {
        return ReportResource::collection(
            $this->reportRepository->findAll()
        );
    }

    public function index(int $scanId): AnonymousResourceCollection
    {
        return ReportResource::collection(
            $this->reportRepository->findByScan($scanId)
        );
    }

    public function show(int $id): ReportResource
    {
        $report = $this->reportRepository->findById($id);
        if (!$report) {
            abort(404, 'Report not found');
        }
        return new ReportResource($report);
    }

    public function generate(int $scanId, Request $request): JsonResponse
    {
        $scan = Scan::find($scanId);
        if (!$scan) {
            return response()->json(['message' => 'Scan not found'], 404);
        }

        $format = $request->input('format', 'html');
        if (!in_array($format, $this->reportGenerator->getFormatters())) {
            return response()->json(['message' => "Unsupported format: {$format}"], 422);
        }

        try {
            $result = $this->reportGenerator->generate($scan, $format);
            return response()->json([
                'message' => 'Report generated successfully',
                'report' => new ReportResource($result['report']),
            ], 201);
        } catch (\Throwable $e) {
            return response()->json(['message' => $e->getMessage()], 500);
        }
    }

    public function regenerate(int $id, Request $request): JsonResponse
    {
        $format = $request->input('format');
        if ($format && !in_array($format, $this->reportGenerator->getFormatters())) {
            return response()->json(['message' => "Unsupported format: {$format}"], 422);
        }

        try {
            $result = $this->reportGenerator->regenerate($id, $format ?? 'html');
            return response()->json([
                'message' => 'Report regenerated successfully',
                'report' => new ReportResource($result['report']),
            ]);
        } catch (\RuntimeException $e) {
            return response()->json(['message' => $e->getMessage()], 404);
        } catch (\Throwable $e) {
            return response()->json(['message' => $e->getMessage()], 500);
        }
    }

    public function download(int $id, Request $request): \Illuminate\Http\Response
    {
        $format = $request->input('format', 'html');

        try {
            $result = $this->reportGenerator->export($id, $format);
        } catch (\RuntimeException $e) {
            abort(404, $e->getMessage());
        }

        $report = $this->reportRepository->findById($id);
        $filename = str_replace(' ', '_', $report->title) . '.' . $result['formatter']->getExtension();

        return response($result['content'], 200, [
            'Content-Type' => $result['formatter']->getMimeType(),
            'Content-Disposition' => "attachment; filename=\"{$filename}\"",
        ]);
    }

    public function destroy(int $id): JsonResponse
    {
        $report = $this->reportRepository->findById($id);
        if (!$report) {
            return response()->json(['message' => 'Report not found'], 404);
        }

        $this->reportRepository->delete($report);
        return response()->json(['message' => 'Report deleted']);
    }

    public function formats(): JsonResponse
    {
        return response()->json($this->reportGenerator->getFormatters());
    }
}
