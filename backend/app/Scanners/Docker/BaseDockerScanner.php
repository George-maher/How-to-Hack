<?php

namespace App\Scanners\Docker;

use App\Contracts\ScannerInterface;
use App\DTOs\ScanResult;
use App\DTOs\ScanResultCollection;
use App\Enums\SeverityLevel;
use App\Exceptions\ScannerExecutionException;
use App\Models\Project;
use Illuminate\Support\Facades\Log;

abstract class BaseDockerScanner implements ScannerInterface
{
    protected int $timeout;

    protected string $dockerImage = 'howtohack/scanner:latest';

    protected string $toolName = '';

    protected array $defaultArgs = [];

    public function __construct()
    {
        $this->timeout = config('scanners.timeout', 30);
    }

    abstract public function name(): string;

    abstract public function description(): string;

    abstract public function category(): string;

    abstract public function severity(): string;

    abstract protected function parseResults(string $rawOutput, Project $project): ScanResultCollection;

    public function execute(Project $project, array $context = []): ScanResultCollection
    {
        $startTime = microtime(true);
        $host = parse_url($project->target_url, PHP_URL_HOST) ?? $project->target_url;

        try {
            $command = $this->buildCommand($host, $context);
            $output = $this->runDocker($command);
            $results = $this->parseResults($output, $project);
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

    protected function buildCommand(string $target, array $context): array
    {
        return array_merge([$this->toolName, $target], $this->defaultArgs);
    }

    protected function runDocker(array $command): string
    {
        $targetHost = $command[1] ?? '';
        $safeTarget = preg_replace('/[^a-zA-Z0-9.:\/-]/', '', $targetHost);

        $dockerCmd = sprintf(
            'docker run --rm --network=host -v %s:/wordlists:ro %s %s 2>&1',
            escapeshellarg(base_path('storage/scanner/wordlists')),
            $this->dockerImage,
            implode(' ', array_map('escapeshellarg', $command))
        );

        Log::debug('Running Docker scanner', [
            'scanner' => $this->name(),
            'command' => $dockerCmd,
        ]);

        $output = shell_exec($dockerCmd);

        if ($output === null || $output === false) {
            throw new \RuntimeException("Docker execution failed for scanner: {$this->name()}");
        }

        Log::debug('Docker scanner output', [
            'scanner' => $this->name(),
            'output_length' => strlen($output),
        ]);

        return $output;
    }

    protected function createResult(
        string $severity,
        string $title,
        string $description,
        array $details = []
    ): ScanResult {
        $validSeverity = in_array($severity, ['info', 'low', 'medium', 'high', 'critical'])
            ? SeverityLevel::from($severity)
            : SeverityLevel::Info;

        return new ScanResult(
            scannerName: $this->name(),
            severity: $validSeverity,
            title: $title,
            description: $description,
            details: $details,
        );
    }

    protected function safeJsonDecode(string $input): array
    {
        $decoded = json_decode($input, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            Log::warning('JSON decode failed for scanner output', [
                'scanner' => $this->name(),
                'error' => json_last_error_msg(),
            ]);
            return [];
        }
        return is_array($decoded) ? $decoded : [$decoded];
    }

    public function dependencies(): array
    {
        return [];
    }

    public function requiresTarget(): bool
    {
        return true;
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
            Log::error('Docker scanner execution failed', $context);
        } else {
            Log::info('Docker scanner execution completed', $context);
        }
    }
}
