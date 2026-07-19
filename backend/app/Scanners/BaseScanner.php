<?php

namespace App\Scanners;

use App\Contracts\ScannerInterface;
use App\DTOs\ScanResult;
use App\DTOs\ScanResultCollection;
use App\Exceptions\ScannerExecutionException;
use App\Models\Project;
use Illuminate\Support\Facades\Log;

abstract class BaseScanner implements ScannerInterface
{
    protected int $timeout;

    public function __construct()
    {
        $this->timeout = config('scanners.timeout', 30);
    }

    abstract public function name(): string;
    abstract public function description(): string;
    abstract public function category(): string;
    abstract public function severity(): string;
    abstract protected function scan(Project $project, array $context): ScanResultCollection;

    public function execute(Project $project, array $context = []): ScanResultCollection
    {
        $startTime = microtime(true);

        try {
            $results = $this->scan($project, $context);
            $this->logExecution($startTime, $results->count(), null);
            return $results;
        } catch (\Throwable $e) {
            $this->logExecution($startTime, 0, $e);
            throw new ScannerExecutionException(
                $this->name(),
                $e->getMessage(),
                (int) $e->getCode(),
                $e
            );
        }
    }

    public function dependencies(): array
    {
        return [];
    }

    public function requiresTarget(): bool
    {
        return true;
    }

    protected function createResult(string $severity, string $title, string $description, array $details = []): ScanResult
    {
        $validSeverity = in_array($severity, ['info', 'low', 'medium', 'high', 'critical'])
            ? \App\Enums\SeverityLevel::from($severity)
            : \App\Enums\SeverityLevel::Info;

        return new ScanResult(
            scannerName: $this->name(),
            severity: $validSeverity,
            title: $title,
            description: $description,
            details: $details,
        );
    }

    private function logExecution(float $startTime, int $resultCount, ?\Throwable $error): void
    {
        $elapsed = round((microtime(true) - $startTime) * 1000, 2);
        $context = [
            'scanner' => $this->name(),
            'duration_ms' => $elapsed,
            'results' => $resultCount,
        ];

        if ($error) {
            $context['error'] = $error->getMessage();
            Log::error('Scanner execution failed', $context);
        } else {
            Log::info('Scanner execution completed', $context);
        }
    }
}
