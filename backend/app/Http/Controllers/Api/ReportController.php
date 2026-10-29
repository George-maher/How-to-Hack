<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Contracts\ReportRepositoryInterface;
use App\Http\Controllers\Controller;
use App\Http\Resources\ReportResource;
use App\Models\Report;
use App\Models\Scan;
use App\Services\Report\ReportGenerator;
use App\Services\Security\AuditLogger;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use Illuminate\Http\Response;

class ReportController extends Controller
{
    public function __construct(
        private readonly ReportRepositoryInterface $reportRepository,
        private readonly ReportGenerator $reportGenerator,
        private readonly AuditLogger $audit,
    ) {
    }

    public function all(Request $request): AnonymousResourceCollection
    {
        return ReportResource::collection(
            $this->reportRepository->findAllForUser($request->user())
        );
    }

    public function index(Scan $scan): AnonymousResourceCollection
    {
        $this->authorize('view', $scan);

        return ReportResource::collection(
            $this->reportRepository->findByScan((int) $scan->getKey())
        );
    }

    public function show(Report $report): ReportResource
    {
        $this->authorize('view', $report);

        return new ReportResource($report);
    }

    public function generate(Scan $scan, Request $request): JsonResponse
    {
        $this->authorize('view', $scan);

        $format = (string) $request->input('format', 'html');
        if (! in_array($format, $this->reportGenerator->getFormatters(), true)) {
            return response()->json([
                'message' => "Unsupported format: {$format}",
                'code' => 'unsupported_format',
            ], 422);
        }

        // Reports are evidence: only generate them for scans that actually
        // finished, and never present a failed scan as a clean report.
        if (! $scan->isTerminal()) {
            return response()->json([
                'message' => 'The scan has not finished yet.',
                'code' => 'scan_not_finished',
                'status' => $scan->statusEnum()->value,
            ], 409);
        }

        try {
            $result = $this->reportGenerator->generate($scan, $format);
        } catch (\Throwable $e) {
            report($e);

            return response()->json([
                'message' => 'The report could not be generated.',
                'code' => 'report_generation_failed',
            ], 500);
        }

        $this->audit->record(AuditLogger::REPORT_GENERATED, 'allowed', [
            'scan_id' => $scan->getKey(),
            'report_id' => $result['report']->getKey(),
            'format' => $format,
        ], $result['report'], $request->user());

        return response()->json([
            'message' => 'Report generated.',
            'report' => new ReportResource($result['report']),
        ], 201);
    }

    public function regenerate(Report $report, Request $request): JsonResponse
    {
        $this->authorize('view', $report);

        $format = $request->input('format');
        if ($format !== null && ! in_array($format, $this->reportGenerator->getFormatters(), true)) {
            return response()->json([
                'message' => "Unsupported format: {$format}",
                'code' => 'unsupported_format',
            ], 422);
        }

        try {
            $result = $this->reportGenerator->regenerate((int) $report->getKey(), $format ?? 'html');
        } catch (\Throwable $e) {
            report($e);

            return response()->json([
                'message' => 'The report could not be regenerated.',
                'code' => 'report_generation_failed',
            ], 500);
        }

        return response()->json([
            'message' => 'Report regenerated.',
            'report' => new ReportResource($result['report']),
        ]);
    }

    /**
     * Authenticated download.
     *
     * The previous implementation returned the bytes to anyone who knew the id,
     * and the frontend used a plain <a href> (so the bearer token was never
     * sent). Both sides are fixed: the route requires auth, the policy checks
     * ownership, and the frontend downloads the body itself.
     */
    public function download(Report $report, Request $request): Response|JsonResponse
    {
        $this->authorize('download', $report);

        $format = (string) $request->input('format', 'html');

        try {
            $result = $this->reportGenerator->export((int) $report->getKey(), $format);
        } catch (\RuntimeException $e) {
            return response()->json([
                'message' => 'That report format is not available.',
                'code' => 'unsupported_format',
            ], 404);
        } catch (\Throwable $e) {
            report($e);

            return response()->json([
                'message' => 'The report could not be exported.',
                'code' => 'report_export_failed',
            ], 500);
        }

        $this->audit->record(AuditLogger::REPORT_DOWNLOADED, 'allowed', [
            'report_id' => $report->getKey(),
            'scan_id' => $report->scan_id,
            'format' => $format,
        ], $report, $request->user());

        $filename = preg_replace('/[^A-Za-z0-9._-]+/', '_', (string) $report->title) ?: 'report';
        $filename .= '.'.$result['formatter']->getExtension();

        return response($result['content'], 200, [
            'Content-Type' => $result['formatter']->getMimeType(),
            'Content-Disposition' => 'attachment; filename="'.$filename.'"',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    public function destroy(Report $report, Request $request): JsonResponse
    {
        $this->authorize('delete', $report);

        $this->audit->record(AuditLogger::REPORT_DELETED, 'allowed', [
            'report_id' => $report->getKey(),
            'scan_id' => $report->scan_id,
        ], $report, $request->user());

        $this->reportRepository->delete($report);

        return response()->json(['message' => 'Report deleted']);
    }

    public function formats(): JsonResponse
    {
        return response()->json($this->reportGenerator->getFormatters());
    }
}
