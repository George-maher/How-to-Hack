<?php

declare(strict_types=1);

namespace App\Services;

use App\Contracts\ProjectRepositoryInterface;
use App\Contracts\ScanRepositoryInterface;
use App\DTOs\ScannerOutcome;
use App\Enums\ScanStatus;
use App\Enums\ScannerIntrusiveness;
use App\Exceptions\ApprovalRequired;
use App\Exceptions\TargetNotAuthorised;
use App\Models\Project;
use App\Models\Scan;
use App\Models\User;
use App\Scanners\Registry\ScannerRegistry;
use App\Security\Scan\ScanPlan;
use App\Services\Security\ApprovalService;
use App\Services\Security\AuditLogger;
use App\Services\Security\TargetScopeService;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class ProjectService
{
    public function __construct(
        private readonly ProjectRepositoryInterface $projectRepository,
        private readonly ScanRepositoryInterface $scanRepository,
        private readonly ScannerRegistry $registry,
        private readonly TargetScopeService $scope,
        private readonly ApprovalService $approvals,
        private readonly AuditLogger $audit,
    ) {
    }

    public function create(array $data): Project
    {
        return $this->projectRepository->create($data);
    }

    public function update(Project $project, array $data): Project
    {
        return $this->projectRepository->update($project, $data);
    }

    public function delete(Project $project): void
    {
        $this->projectRepository->delete($project);
    }

    /**
     * Create a scan for a project.
     *
     * Order of operations matters:
     *  1. resolve the requested tool set against the registry (never trust the
     *     request to name tools we do not have);
     *  2. build the plan and persist it *before* approval, so the fingerprint
     *     has something stable to bind to;
     *  3. evaluate the target policy at the API boundary and again in the
     *     worker;
     *  4. request approval if the plan contains any active scanner;
     *  5. only then dispatch.
     *
     * @param  array<string, mixed>  $options
     *
     * @throws TargetNotAuthorised
     */
    public function initiateScan(Project $project, array $options = [], ?User $actor = null): Scan
    {
        $ports = $this->resolvePorts($project, $options);
        $plan = $this->resolvePlan($options);

        if ($plan->tools() === []) {
            throw new \RuntimeException('No registered scanners are available for this scan.');
        }

        // API-boundary scope check. The Runner re-checks independently.
        $decision = $this->scope->evaluate((string) $project->target_url, $ports);
        if (! $decision->allowed) {
            throw TargetNotAuthorised::fromDecision($decision);
        }

        $activeScans = $project->activeScans()->count();
        if ($activeScans > 0) {
            throw new \RuntimeException('This project already has a scan in progress. Wait for it to finish or cancel it.');
        }

        $fingerprint = $plan->fingerprint($decision->host, $decision->ports);

        return DB::transaction(function () use ($project, $plan, $decision, $fingerprint, $ports, $actor) {
            $scan = $this->scanRepository->create([
                'project_id' => $project->getKey(),
                'status' => ScanStatus::Queued->value,
                'ai_reasoning' => [],
                'completed_scanners' => [],
                'plan' => $plan->toArray(),
                'plan_fingerprint' => $fingerprint,
                'target_url' => (string) $project->target_url,
                'target_host' => $decision->host,
                'target_ports' => $decision->ports,
                'resolved_ips' => $decision->resolvedIps,
            ]);

            $this->audit->record(AuditLogger::SCAN_CREATED, 'allowed', [
                'scan_id' => $scan->getKey(),
                'project_id' => $project->getKey(),
                'target' => $project->target_url,
                'host' => $decision->host,
                'ports' => $decision->ports,
                'tools' => $plan->tools(),
                'active_tools' => $plan->activeTools(),
                'requires_approval' => $plan->requiresApproval(),
                'scope_rule' => $decision->matchedRule,
                'fingerprint' => $fingerprint,
            ], $scan, $actor);

            if ($plan->requiresApproval()) {
                $this->approvals->request($scan, $plan, $decision);

                // Nothing is queued: the scan is inert until a human approves it.
                return $scan->refresh();
            }

            \App\Jobs\RunScanJob::dispatch($scan);

            return $scan->refresh();
        });
    }

    /**
     * @param  array<string, mixed>  $options
     */
    private function resolvePlan(array $options): ScanPlan
    {
        $requested = $options['tools'] ?? null;
        $available = $this->registry->all();

        $intrusiveness = [];
        $tools = [];

        foreach ($available as $name => $scanner) {
            if (is_array($requested) && $requested !== [] && ! in_array($name, $requested, true)) {
                continue;
            }

            $tools[] = (string) $name;
            $intrusiveness[(string) $name] = $scanner->intrusiveness();
        }

        // A request may only narrow the registry, never extend it.
        if (is_array($requested)) {
            foreach ($requested as $name) {
                if (! $available->has($name)) {
                    Log::warning('Requested unknown scanner ignored', ['scanner' => $name]);
                }
            }
        }

        return ScanPlan::create($tools, $intrusiveness, array_filter([
            'max_scanners' => $options['max_scanners'] ?? null,
            'notes' => $options['notes'] ?? null,
        ], static fn ($v) => $v !== null));
    }

    /**
     * @param  array<string, mixed>  $options
     * @return list<int>
     */
    private function resolvePorts(Project $project, array $options): array
    {
        $parsed = parse_url((string) $project->target_url);
        $scheme = strtolower((string) ($parsed['scheme'] ?? 'https'));
        $default = (int) ($parsed['port'] ?? ($scheme === 'https' ? 443 : 80));

        $requested = is_array($options['ports'] ?? null) ? $options['ports'] : [];

        $ports = array_values(array_unique(array_filter(
            array_map('intval', array_merge([$default], $requested)),
            static fn (int $p) => $p >= 1 && $p <= 65535,
        )));

        sort($ports);

        return array_slice($ports, 0, 20);
    }
}
