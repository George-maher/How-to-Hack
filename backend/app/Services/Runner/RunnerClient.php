<?php

declare(strict_types=1);

namespace App\Services\Runner;

use App\Models\Scan;
use App\Security\Scan\JobId;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Client for the scanner Runner service.
 *
 * The Laravel process has no Docker access and no way to start a process: the
 * only capability it has is "ask the Runner to run a registered tool against an
 * authorised target". That narrowness is the point.
 *
 * Contract (see runner/README.md):
 *   POST /jobs  { job_id, scan_id, tool, target, scope, pinned_ips, limits, approval }
 *   -> 200 { job_id, tool, outcome, exit_code, duration_ms, stdout, stderr, truncated, diagnostic }
 *   -> 403 { error: 'target_not_allowed', reason, scope }
 *   -> 422 { error: 'invalid_job', field, message }
 *   -> 409 { error: 'job_in_progress' }   -> 429 { error: 'runner_busy' }
 */
final class RunnerClient
{
    public function __construct(
        private readonly string $baseUrl,
        private readonly string $secret,
        private readonly int $timeoutSeconds = 300,
        private readonly int $connectTimeoutSeconds = 10,
        private readonly bool $enabled = true,
    ) {
    }

    public static function fromConfig(): self
    {
        return new self(
            (string) config('security.runner.url'),
            (string) config('security.runner.secret'),
            (int) config('security.runner.timeout_seconds', 330),
            (int) config('security.runner.connect_timeout_seconds', 10),
            (bool) config('security.runner.enabled', true),
        );
    }

    /**
     * Deterministic job id for one scanner within one scan.
     *
     * Determinism is the idempotency mechanism: a duplicate queue delivery
     * produces the same id, so the Runner replays the recorded result instead
     * of starting a second container. It includes the plan fingerprint, so a
     * scan whose plan changed gets a fresh job rather than a stale replay.
     *
     * Matches the Runner's schema: ^[A-Za-z0-9_-]{8,64}$
     */
    public static function jobId(Scan $scan, string $tool): string
    {
        return JobId::for(
            (int) $scan->getKey(),
            $tool,
            is_string($scan->plan_fingerprint) ? $scan->plan_fingerprint : null,
        );
    }

    /**
     * A runner is usable only when the operator enabled it, gave it a URL and a
     * secret strong enough to authenticate with. Anything less is reported as
     * `runner_not_configured` rather than attempted.
     */
    public function isConfigured(): bool
    {
        return $this->enabled && $this->baseUrl !== '' && strlen($this->secret) >= 32;
    }

    /**
     * @param  array<string, mixed>  $job
     * @return array<string, mixed>
     *
     * @throws RunnerRejected
     */
    public function run(array $job): array
    {
        if (! $this->isConfigured()) {
            throw new RunnerRejected('runner_not_configured', 'The scanner service is not configured.');
        }

        $body = json_encode($job, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($body === false) {
            throw new RunnerRejected('runner_encoding', 'The job could not be encoded.');
        }

        $timeout = (int) ($job['limits']['timeout_ms'] ?? 300_000);
        $response = $this->send('POST', '/jobs', $body, (int) ceil($timeout / 1000) + 30);

        if ($response['status'] === 403) {
            throw new RunnerRejected(
                'runner_scope_denied',
                'The scanner service refused the target: '.($response['body']['reason'] ?? 'unknown'),
            );
        }

        if ($response['status'] === 409) {
            throw new RunnerRejected('runner_job_conflict', 'The scanner service is already running this job.');
        }

        if ($response['status'] === 429) {
            throw new RunnerRejected('runner_busy', 'The scanner service is busy. Try again shortly.');
        }

        if ($response['status'] !== 200 || ! is_array($response['body'])) {
            throw new RunnerRejected(
                'runner_error',
                sprintf('The scanner service returned HTTP %d.', $response['status']),
            );
        }

        return $response['body'];
    }

    /**
     * @return array{tools: list<array<string, mixed>>}
     */
    public function tools(): array
    {
        $response = $this->send('GET', '/tools', '');

        if ($response['status'] !== 200) {
            throw new RunnerRejected('runner_error', 'The tool catalogue is unavailable.');
        }

        return is_array($response['body']) ? $response['body'] : ['tools' => []];
    }

    /**
     * Ask the Runner to stop a job. Returns true only when the Runner confirmed
     * it killed a live container; false means "not confirmed", which callers
     * must report honestly rather than assuming the job stopped.
     */
    public function cancel(string $jobId): bool
    {
        if (! $this->isConfigured()) {
            return false;
        }

        $response = $this->send('POST', '/jobs/'.rawurlencode($jobId).'/cancel', '{}', 15);

        return $response['status'] === 202;
    }

    /**
     * @return array<string, mixed>
     */
    public function health(): array
    {
        $response = $this->send('GET', '/health', '');

        return is_array($response['body']) ? $response['body'] : [];
    }

    /**
     * @return array{status: int, body: mixed}
     *
     * @throws RunnerRejected
     */
    private function send(string $method, string $path, string $body, int $timeoutSeconds = 20): array
    {
        $timestamp = (string) time();
        $signature = hash_hmac('sha256', $timestamp.'.'.$body, $this->secret);

        try {
            $pending = Http::timeout($timeoutSeconds)
                ->connectTimeout(max(1, min($this->connectTimeoutSeconds, $timeoutSeconds)))
                ->withHeaders([
                    'x-runner-timestamp' => $timestamp,
                    'x-runner-signature' => $signature,
                ]);

            $response = $method === 'GET'
                ? $pending->get($this->baseUrl.$path)
                : $pending->withBody($body, 'application/json')->post($this->baseUrl.$path);
        } catch (Throwable $e) {
            throw new RunnerRejected('runner_unreachable', 'The scanner service could not be reached.');
        }

        return [
            'status' => $response->status(),
            'body' => $response->json(),
        ];
    }
}
