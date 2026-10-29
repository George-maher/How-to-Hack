<?php

declare(strict_types=1);

namespace App\Scanners\Docker;

use App\Contracts\ScannerInterface;
use App\DTOs\ScanResult;
use App\DTOs\ScanResultCollection;
use App\DTOs\ScannerExecutionResult;
use App\DTOs\ScannerOutcome;
use App\Enums\ScannerIntrusiveness;
use App\Enums\SeverityLevel;
use App\Models\Project;
use App\Models\Scan;
use App\Scanners\RunnerToolRegistry;
use App\Security\Target\ScopeDecision;
use App\Security\Target\TargetUrl;
use App\Services\Runner\RunnerClient;
use App\Services\Runner\RunnerRejected;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Base class for scanners executed by the Runner service.
 *
 * Before this change the class shelled out with `shell_exec('docker run ...')`
 * from inside the Laravel process, using `--network=host`. That is gone:
 *
 *  - the API never builds a command line, so no shell fragment can reach a
 *    scanner (the Runner owns argv from its own registry);
 *  - the target is re-evaluated by the Runner immediately before execution, so
 *    a job queued against a since-revoked approval cannot run;
 *  - the container is one-shot, read-only, non-root, capability-dropped and on
 *    a dedicated network;
 *  - a missing tool or unreachable Runner produces `unavailable`, not an empty
 *    result set.
 *
 * Subclasses only declare their registry tool name and how to parse stdout.
 */
abstract class BaseDockerScanner implements ScannerInterface
{
    protected int $timeout;

    /** Tool name in the Runner registry; must exist there. */
    protected string $toolName = '';

    public function __construct(protected readonly RunnerClient $runner)
    {
        $this->timeout = (int) config('scanners.timeout', 30);
    }

    abstract public function name(): string;

    abstract public function description(): string;

    abstract public function category(): string;

    abstract public function severity(): string;

    /**
     * Parse the tool's stdout.
     *
     * Must throw when the payload is not the format it expects: an unparseable
     * payload is an explicit `invalid_output` outcome, never "no findings".
     */
    abstract protected function parseResults(string $rawOutput, Project $project): ScanResultCollection;

    public function execute(Project $project, array $context = []): ScannerExecutionResult
    {
        $startedAt = microtime(true);

        /** @var Scan|null $scan */
        $scan = $context['scan'] ?? null;

        if (! $scan instanceof Scan) {
            // There is no ad-hoc execution path: a scanner only runs as part of
            // an approved scan.
            return ScannerExecutionResult::failure(
                $this->name(),
                ScannerOutcome::Blocked->value,
                'No scan context: scanners only run as part of an approved scan.',
            );
        }

        $tool = $this->runnerTool();
        if ($tool === null) {
            return ScannerExecutionResult::failure(
                $this->name(),
                ScannerOutcome::Failed->value,
                'Scanner declares no Runner tool.',
            );
        }

        /** @var ScopeDecision|null $scope */
        $scope = $context['scope'] ?? null;
        $originalUrl = (string) $project->target_url;

        // Use the *normalized* host the policy approved, not the raw text of the
        // URL: `2130706433` and `127.0.0.1` are the same destination, and the
        // Runner refuses a job whose URL and host disagree.
        $host = $scope?->host ?? (string) parse_url($originalUrl, PHP_URL_HOST);
        $scheme = strtolower((string) (parse_url($originalUrl, PHP_URL_SCHEME) ?: 'https'));
        $port = (int) ($context['port'] ?? parse_url($originalUrl, PHP_URL_PORT) ?? ($scheme === 'https' ? 443 : 80));

        $url = TargetUrl::rebuild($originalUrl, $host, $scheme, $port);

        $jobId = (string) ($context['job_id'] ?? RunnerClient::jobId($scan, $tool));
        $timeoutMs = $this->timeoutMs();

        try {
            $response = $this->runner->run([
                'job_id' => $jobId,
                'scan_id' => (int) $scan->getKey(),
                'tool' => $tool,
                'target' => [
                    'host' => $host,
                    'url' => $url,
                    'scheme' => $scheme,
                    'port' => $port,
                ],
                'scope' => $this->scopeDocument(),
                'pinned_ips' => is_array($scan->resolved_ips) ? $scan->resolved_ips : null,
                'limits' => ['timeout_ms' => $timeoutMs],
                'approval' => is_string($scan->plan_fingerprint)
                    ? ['fingerprint' => $scan->plan_fingerprint, 'approved_at' => null]
                    : null,
            ]);
        } catch (RunnerRejected $e) {
            Log::warning('Runner rejected the job', [
                'scanner' => $this->name(),
                'scan_id' => $scan->getKey(),
                'reason' => $e->reason,
            ]);

            return ScannerExecutionResult::failure(
                $this->name(),
                $e->reason === 'runner_scope_denied' ? ScannerOutcome::Blocked->value : ScannerOutcome::Unavailable->value,
                $e->getMessage(),
                $this->elapsedMs($startedAt),
                runnerJobId: $jobId,
            );
        }

        $elapsed = $this->elapsedMs($startedAt);
        $outcome = $this->outcomeFrom($response);
        $exitCode = isset($response['exit_code']) ? (int) $response['exit_code'] : null;
        $stderr = isset($response['stderr']) && is_string($response['stderr']) && $response['stderr'] !== ''
            ? mb_substr($response['stderr'], 0, 2000)
            : null;

        if ($outcome !== ScannerOutcome::Completed) {
            return ScannerExecutionResult::failure(
                $this->name(),
                $outcome->value,
                isset($response['diagnostic']) ? (string) $response['diagnostic'] : $outcome->label(),
                (int) ($response['duration_ms'] ?? $elapsed),
                $exitCode,
                $stderr,
                $jobId,
            );
        }

        $stdout = is_string($response['stdout'] ?? null) ? $response['stdout'] : '';

        try {
            $findings = $this->parseResults($stdout, $project);
        } catch (Throwable $e) {
            Log::warning('Scanner output could not be parsed', [
                'scanner' => $this->name(),
                'scan_id' => $scan->getKey(),
                'error' => $e->getMessage(),
                'stdout_bytes' => strlen($stdout),
            ]);

            return ScannerExecutionResult::failure(
                $this->name(),
                ScannerOutcome::InvalidOutput->value,
                'Output could not be parsed: '.$e->getMessage(),
                (int) ($response['duration_ms'] ?? $elapsed),
                $exitCode,
                $stderr,
                $jobId,
            );
        }

        return ScannerExecutionResult::success(
            $this->name(),
            $findings,
            (int) ($response['duration_ms'] ?? $elapsed),
            $exitCode,
            $stderr,
            $jobId,
        );
    }

    public function dependencies(): array
    {
        return [];
    }

    public function requiresTarget(): bool
    {
        return true;
    }

    public function runnerTool(): ?string
    {
        return $this->toolName !== '' ? $this->toolName : null;
    }

    public function intrusiveness(): ScannerIntrusiveness
    {
        // Classification comes from the shared registry so the API and the
        // Runner cannot disagree. Unknown tools are Active.
        return RunnerToolRegistry::intrusiveness($this->runnerTool() ?? '');
    }

    /**
     * The scope document the Runner re-evaluates. Operator policy only; nothing
     * here is derived from user input.
     *
     * @return array<string, mixed>
     */
    protected function scopeDocument(): array
    {
        return app(\App\Services\Security\TargetScopeService::class)->runnerScopeDocument();
    }

    /**
     * @param  array<string, mixed>  $response
     */
    protected function outcomeFrom(array $response): ScannerOutcome
    {
        return match ((string) ($response['outcome'] ?? 'failed')) {
            'completed' => ScannerOutcome::Completed,
            'timed_out' => ScannerOutcome::TimedOut,
            'unavailable' => ScannerOutcome::Unavailable,
            'cancelled' => ScannerOutcome::Cancelled,
            'blocked' => ScannerOutcome::Blocked,
            default => ScannerOutcome::Failed,
        };
    }

    protected function createResult(
        string $severity,
        string $title,
        string $description,
        array $details = []
    ): ScanResult {
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

    /**
     * Strict JSON decode (JSON array/object or NDJSON).
     *
     * Throws on unusable input rather than returning an empty array: the caller
     * must be able to tell "the tool reported nothing" from "we could not read
     * the tool".
     *
     * @return array<int|string, mixed>
     *
     * @throws \RuntimeException
     */
    protected function safeJsonDecode(string $input): array
    {
        $trimmed = trim($input);

        if ($trimmed === '') {
            // Empty output from a tool that succeeded is a legitimate "nothing
            // found" for most tools.
            return [];
        }

        $decoded = json_decode($trimmed, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
            return $decoded;
        }

        // NDJSON: one JSON value per line.
        $records = [];
        $sawJson = false;

        foreach (explode("\n", $trimmed) as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            if (! str_starts_with($line, '{') && ! str_starts_with($line, '[')) {
                continue;
            }

            $decodedLine = json_decode($line, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decodedLine)) {
                $sawJson = true;
                $records[] = $decodedLine;
            }
        }

        if ($sawJson) {
            return $records;
        }

        throw new \RuntimeException('scanner output was not valid JSON');
    }

    protected function timeoutMs(): int
    {
        return max(1, (int) config('security.execution.per_scanner_timeout_seconds', 120)) * 1000;
    }

    protected function elapsedMs(float $since): int
    {
        return (int) round((microtime(true) - $since) * 1000);
    }
}
