<?php

declare(strict_types=1);

namespace App\Scanners;

use App\Contracts\ScannerInterface;
use App\DTOs\ScanResult;
use App\DTOs\ScanResultCollection;
use App\DTOs\ScannerExecutionResult;
use App\DTOs\ScannerOutcome;
use App\Enums\ScannerIntrusiveness;
use App\Enums\SeverityLevel;
use App\Models\Project;
use App\Security\Http\SafeHttpClient;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Base class for scanners that run inside the PHP process.
 *
 * These scanners talk HTTP/DNS/sockets to the target directly, so they are the
 * one place where the API process is itself an outbound client. Two rules make
 * that acceptable:
 *   1. every HTTP request goes through SafeHttpClient (policy check + no
 *      redirects + pinned address), never the raw Http facade;
 *   2. the result states an outcome, so a failed scanner is never mistaken for
 *      a clean one.
 */
abstract class BaseScanner implements ScannerInterface
{
    protected int $timeout;

    public function __construct(protected readonly SafeHttpClient $http)
    {
        $this->timeout = (int) config('scanners.timeout', 30);
    }

    abstract public function name(): string;

    abstract public function description(): string;

    abstract public function category(): string;

    abstract public function severity(): string;

    abstract protected function scan(Project $project, array $context): ScanResultCollection;

    public function execute(Project $project, array $context = []): ScannerExecutionResult
    {
        $startedAt = microtime(true);

        try {
            $findings = $this->scan($project, $context);
            $elapsed = $this->elapsedMs($startedAt);

            $this->logExecution($elapsed, $findings->count(), null);

            return ScannerExecutionResult::success($this->name(), $findings, $elapsed);
        } catch (Throwable $e) {
            $elapsed = $this->elapsedMs($startedAt);
            $this->logExecution($elapsed, 0, $e);

            return ScannerExecutionResult::failure(
                $this->name(),
                ScannerOutcome::Failed->value,
                $e->getMessage(),
                $elapsed,
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

    /**
     * In-process scanners are passive unless they explicitly say otherwise;
     * anything that sends payloads or probes many ports overrides this.
     */
    public function intrusiveness(): ScannerIntrusiveness
    {
        return ScannerIntrusiveness::Passive;
    }

    public function runnerTool(): ?string
    {
        return null;
    }

    protected function createResult(string $severity, string $title, string $description, array $details = []): ScanResult
    {
        $valid = in_array($severity, ['info', 'low', 'medium', 'high', 'critical'], true)
            ? SeverityLevel::from($severity)
            : SeverityLevel::Info;

        return new ScanResult(
            scannerName: $this->name(),
            severity: $valid,
            title: $title,
            description: $description,
            details: $details,
        );
    }

    protected function elapsedMs(float $since): int
    {
        return (int) round((microtime(true) - $since) * 1000);
    }

    private function logExecution(int $elapsedMs, int $findingCount, ?Throwable $error): void
    {
        $context = [
            'scanner' => $this->name(),
            'duration_ms' => $elapsedMs,
            'findings' => $findingCount,
        ];

        if ($error !== null) {
            Log::error('Scanner execution failed', $context + ['error' => $error->getMessage()]);

            return;
        }

        Log::info('Scanner execution completed', $context);
    }
}
