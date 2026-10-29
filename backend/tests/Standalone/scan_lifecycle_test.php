<?php
declare(strict_types=1);

/*
 * Standalone lifecycle/approval-fingerprint test. See target_policy_test.php
 * for the rationale; this file is runnable with any PHP binary.
 */

$app = dirname(__DIR__, 2).'/app/';
require $app . 'Enums/ScanStatus.php';
require $app . 'Enums/ScannerIntrusiveness.php';
require $app . 'Security/Scan/CanonicalJson.php';
require $app . 'Security/Scan/ApprovalFingerprint.php';
require $app . 'Security/Scan/ScanPlan.php';

use App\Enums\ScanStatus;
use App\Enums\ScannerIntrusiveness;
use App\Security\Scan\ScanPlan;
use App\Security\Scan\ApprovalFingerprint;

$pass = 0; $fail = 0; $failures = [];
function check(string $n, $a, $e) { global $pass,$fail,$failures; if ($a === $e) { $pass++; return; } $fail++; $failures[] = sprintf("%-55s expected=%-22s actual=%s", $n, var_export($e,true), var_export($a,true)); }

// --- State machine ----------------------------------------------------------
check('queued->running', ScanStatus::Queued->canTransitionTo(ScanStatus::Running), true);
check('queued->awaiting_approval', ScanStatus::Queued->canTransitionTo(ScanStatus::AwaitingApproval), true);
check('awaiting->queued (approved)', ScanStatus::AwaitingApproval->canTransitionTo(ScanStatus::Queued), true);
check('awaiting->running (skip approval)', ScanStatus::AwaitingApproval->canTransitionTo(ScanStatus::Running), false);
check('running->completed', ScanStatus::Running->canTransitionTo(ScanStatus::Completed), true);
check('running->cancel_requested', ScanStatus::Running->canTransitionTo(ScanStatus::CancelRequested), true);
check('cancel_requested->cancelled', ScanStatus::CancelRequested->canTransitionTo(ScanStatus::Cancelled), true);
check('cancel_requested->completed', ScanStatus::CancelRequested->canTransitionTo(ScanStatus::Completed), true);
check('running->queued (rewind)', ScanStatus::Running->canTransitionTo(ScanStatus::Queued), false);
check('completed->running (terminal)', ScanStatus::Completed->canTransitionTo(ScanStatus::Running), false);
check('failed->failed (same state)', ScanStatus::Failed->canTransitionTo(ScanStatus::Failed), false);
check('running->timed_out', ScanStatus::Running->canTransitionTo(ScanStatus::TimedOut), true);
check('queued is in flight', ScanStatus::Queued->isInFlight(), true);
check('completed not in flight', ScanStatus::Completed->isInFlight(), false);
check('cancelled terminal', ScanStatus::Cancelled->isTerminal(), true);
check('cancel_requested not terminal', ScanStatus::CancelRequested->isTerminal(), false);
check('legacy pending maps to queued', ScanStatus::fromLegacy('pending'), ScanStatus::Queued);
check('legacy running preserved', ScanStatus::fromLegacy('running'), ScanStatus::Running);

// --- Plan -------------------------------------------------------------------
$cls = [
    'port_scanner' => ScannerIntrusiveness::Passive,
    'http_analyzer' => ScannerIntrusiveness::Passive,
    'nuclei' => ScannerIntrusiveness::Active,
    'xss_assessment' => ScannerIntrusiveness::Active,
];
$passive = ScanPlan::create(['port_scanner','http_analyzer','not_a_scanner'], $cls);
check('unknown tools dropped', $passive->tools(), ['http_analyzer','port_scanner']);
check('passive plan needs no approval', $passive->requiresApproval(), false);
check('passive plan is passive only', $passive->isPassiveOnly(), true);

$active = ScanPlan::create(['port_scanner','nuclei','xss_assessment'], $cls);
check('active tools detected', $active->activeTools(), ['nuclei','xss_assessment']);
check('active plan needs approval', $active->requiresApproval(), true);
check('plan.has rejects unapproved', $active->has('ffuf'), false);
check('plan.has accepts approved', $active->has('nuclei'), true);

// --- Fingerprint binding ----------------------------------------------------
$f1 = $active->fingerprint('app.example.com', [443]);
$f2 = $active->fingerprint('app.example.com', [443]);
check('fingerprint deterministic', $f1, $f2);
check('fingerprint order-insensitive (ports)', $active->fingerprint('app.example.com',[443,80]), $active->fingerprint('app.example.com',[80,443]));
check('fingerprint changes with host', $active->fingerprint('other.example.com',[443]) !== $f1, true);
check('fingerprint changes with port', $active->fingerprint('app.example.com',[8443]) !== $f1, true);
check('fingerprint changes with tools', $active->fingerprint('app.example.com',[443]) !== ScanPlan::create(['port_scanner','nuclei'],$cls)->fingerprint('app.example.com',[443]), true);
check('fingerprint changes with options', $active->fingerprint('app.example.com',[443]) !== ScanPlan::create(['port_scanner','nuclei','xss_assessment'],$cls,['max_scanners'=>5])->fingerprint('app.example.com',[443]), true);
check('fingerprint is 64 hex chars', preg_match('/^[0-9a-f]{64}$/', $f1), 1);

// --- Option normalisation ---------------------------------------------------
$withBad = ScanPlan::create(['nuclei'], $cls, ['max_scanners' => 9999, 'include_dependencies' => 'yes', 'notes' => str_repeat('a', 900), 'evil_key' => 'x']);
check('max_scanners clamped', $withBad->option('max_scanners'), 60);
check('non-bool option dropped', $withBad->option('include_dependencies'), null);
check('unknown option dropped', $withBad->option('evil_key'), null);
check('notes truncated', strlen((string) $withBad->option('notes')), 500);

// --- ApprovalFingerprint direct --------------------------------------------
check('ApprovalFingerprint::for stable', ApprovalFingerprint::for('a.com',[443],['b','a']), ApprovalFingerprint::for('a.com',[443],['a','b']));
check('ApprovalFingerprint normalises host case', ApprovalFingerprint::for('A.COM',[443],['a']), ApprovalFingerprint::for('a.com',[443],['a']));

echo "\n";
foreach ($failures as $f) echo "FAIL  $f\n";
echo sprintf("\nPHP 8.2 lifecycle harness: %d passed, %d failed\n", $pass, $fail);
exit($fail === 0 ? 0 : 1);
