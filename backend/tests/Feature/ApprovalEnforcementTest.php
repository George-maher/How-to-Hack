<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Enums\ScanStatus;
use App\Models\Project;
use App\Models\Scan;
use App\Models\ScanApproval;
use App\Models\User;
use App\Security\Scan\ScanPlan;
use App\Services\Security\ApprovalService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * SEC-03: explicit approval for active scans.
 *
 * Every test here asserts a refusal. There is no "proceed anyway" path, and the
 * tests deliberately try to find one (expired approval, changed plan, reused
 * approval, out-of-plan tool).
 */
class ApprovalEnforcementTest extends TestCase
{
    use RefreshDatabase;

    private User $user;

    private Project $project;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = User::factory()->create();
        $this->project = Project::factory()->create([
            'user_id' => $this->user->id,
            'target_url' => 'https://app.example.com',
        ]);

    }

    private function authenticated(): static
    {
        $token = Str::random(40);
        $this->user->forceFill(['api_token' => hash('sha256', $token)])->save();

        return $this->withHeader('Authorization', 'Bearer '.$token);
    }

    private function plan(array $tools = ['port_scanner', 'http_analyzer']): ScanPlan
    {
        $intrusiveness = [];
        foreach ($tools as $tool) {
            $intrusiveness[$tool] = $tool === 'port_scanner'
                ? \App\Enums\ScannerIntrusiveness::Active
                : \App\Enums\ScannerIntrusiveness::Passive;
        }

        return ScanPlan::create($tools, $intrusiveness);
    }

    private function scanWithApproval(string $status = ScanApproval::STATUS_APPROVED): array
    {
        $plan = $this->plan();
        $scan = Scan::factory()->create([
            'project_id' => $this->project->id,
            'status' => ScanStatus::AwaitingApproval,
            'target_host' => 'app.example.com',
            'target_ports' => [443],
            'plan' => $plan->toArray(),
            'plan_fingerprint' => $plan->fingerprint('app.example.com', [443]),
        ]);

        $approval = ScanApproval::create([
            'scan_id' => $scan->id,
            'project_id' => $this->project->id,
            'user_id' => $this->user->id,
            'status' => $status,
            'target_url' => 'https://app.example.com',
            'target_host' => 'app.example.com',
            'target_ports' => [443],
            'tools' => $plan->tools(),
            'options' => [],
            'fingerprint' => $plan->fingerprint('app.example.com', [443]),
            'requested_at' => now(),
            'expires_at' => now()->addMinutes(30),
        ]);

        return [$scan, $approval];
    }

    public function test_active_scans_do_not_run_until_approved(): void
    {
        \Illuminate\Support\Facades\Queue::fake();

        [$scan] = $this->scanWithApproval(ScanApproval::STATUS_PENDING);

        /** @var ApprovalService $service */
        $service = app(ApprovalService::class);

        $this->expectException(\App\Exceptions\ApprovalRequired::class);

        $service->verifyForExecution($scan, $this->plan());
    }

    public function test_an_approved_scan_passes_verification(): void
    {
        [$scan, $approval] = $this->scanWithApproval();

        $service = app(ApprovalService::class);
        $verified = $service->verifyForExecution($scan, $this->plan());

        $this->assertSame($approval->id, $verified->id);
    }

    public function test_an_expired_approval_is_refused(): void
    {
        [$scan, $approval] = $this->scanWithApproval();
        $approval->forceFill(['expires_at' => now()->subMinute()])->save();

        $service = app(ApprovalService::class);

        $this->expectException(\App\Exceptions\ApprovalRequired::class);
        $service->verifyForExecution($scan->fresh(), $this->plan());
    }

    public function test_changing_the_tool_set_invalidates_the_approval(): void
    {
        [$scan] = $this->scanWithApproval();

        $wider = $this->plan(['port_scanner', 'http_analyzer', 'sqli_assessment']);

        $service = app(ApprovalService::class);

        $this->expectException(\App\Exceptions\ApprovalRequired::class);
        $service->verifyForExecution($scan, $wider);
    }

    public function test_changing_the_ports_invalidates_the_approval(): void
    {
        [$scan] = $this->scanWithApproval();
        $scan->forceFill(['target_ports' => [443, 22]])->save();

        $service = app(ApprovalService::class);

        $this->expectException(\App\Exceptions\ApprovalRequired::class);
        $service->verifyForExecution($scan->fresh(), $this->plan());
    }

    public function test_an_approval_cannot_be_consumed_twice(): void
    {
        [$scan, $approval] = $this->scanWithApproval();
        $service = app(ApprovalService::class);

        $this->assertTrue($service->consume($approval));
        $this->assertFalse($service->consume($approval->fresh()));

        $this->expectException(\App\Exceptions\ApprovalRequired::class);
        $service->verifyForExecution($scan->fresh(), $this->plan());
    }

    public function test_only_pending_approvals_can_be_granted(): void
    {
        [, $approval] = $this->scanWithApproval(ScanApproval::STATUS_REJECTED);

        $service = app(ApprovalService::class);

        $this->expectException(\RuntimeException::class);
        $service->grant($approval, $this->user);
    }

    public function test_an_expired_request_cannot_be_granted(): void
    {
        [, $approval] = $this->scanWithApproval(ScanApproval::STATUS_PENDING);
        $approval->forceFill(['expires_at' => now()->subMinute()])->save();

        $service = app(ApprovalService::class);

        $this->expectException(\App\Exceptions\ApprovalRequired::class);
        $service->grant($approval->fresh(), $this->user);
    }

    public function test_approval_is_audited(): void
    {
        [, $approval] = $this->scanWithApproval(ScanApproval::STATUS_PENDING);

        $service = app(ApprovalService::class);
        $service->grant($approval, $this->user, 'looks fine');

        $this->assertDatabaseHas('audit_events', [
            'event' => 'approval.granted',
            'subject_id' => (string) $approval->id,
        ]);
    }

    public function test_the_ai_cannot_grant_an_approval(): void
    {
        // The AI service has no dependency on ApprovalService; this test fails
        // if someone wires one in later without thinking about it.
        $reflection = new \ReflectionClass(\App\Services\Ai\AiAgentService::class);
        $source = file_get_contents($reflection->getFileName());

        $this->assertStringNotContainsString('ApprovalService', $source);
        $this->assertStringNotContainsString('ScanApproval', $source);
    }
}
