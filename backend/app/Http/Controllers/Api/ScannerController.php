<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Scanners\Registry\ScannerRegistry;
use Illuminate\Http\JsonResponse;

class ScannerController extends Controller
{
    public function __construct(
        private readonly ScannerRegistry $scannerRegistry,
    ) {
    }

    /**
     * The catalogue of scanners and whether running them needs approval.
     */
    public function index(): JsonResponse
    {
        $scanners = $this->scannerRegistry->all()->map(fn ($s) => [
            'name' => $s->name(),
            'description' => $s->description(),
            'category' => $s->category(),
            'severity' => $s->severity(),
            'dependencies' => $s->dependencies(),
            'intrusiveness' => $s->intrusiveness()->value,
            'requires_approval' => $s->intrusiveness()->requiresApproval(),
            'runner_tool' => $s->runnerTool(),
        ]);

        return response()->json($scanners->values());
    }
}
