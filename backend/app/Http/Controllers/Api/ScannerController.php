<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Scanners\Registry\ScannerRegistry;
use Illuminate\Http\JsonResponse;

class ScannerController extends Controller
{
    public function __construct(
        private readonly ScannerRegistry $scannerRegistry,
    ) {}

    public function index(): JsonResponse
    {
        $scanners = $this->scannerRegistry->all()->map(fn($s) => [
            'name' => $s->name(),
            'description' => $s->description(),
            'category' => $s->category(),
            'severity' => $s->severity(),
            'dependencies' => $s->dependencies(),
        ]);

        return response()->json($scanners->values());
    }
}
