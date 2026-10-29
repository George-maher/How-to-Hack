<?php
declare(strict_types=1);

/*
 * Standalone test for the approval fingerprint + plan enforcement.
 * Dependency-free: any PHP binary can run it.
 */

$app = dirname(__DIR__, 2).'/app/';

foreach ([
    'Enums/ScanStatus.php',
    'Enums/ScanOutcomeReason.php',
    'Enums/ScannerIntrusiveness.php',
    'Security/Scan/CanonicalJson.php',
    'Security/Scan/ApprovalFingerprint.php',
    'Security/Scan/ScanPlan.php',
] as $file) {
    require $app.$file;
}

use App\Enums\ScanStatus;
use App\Enums\ScanOutcomeReason;
use App\Enums\ScannerIntrusiveness;
use App\Security\Scan\ApprovalFingerprint;
use App\Security\Scan\ScanPlan;

$pass = 0; $fail = 0; $failures = [];
function check(string $n, $a, $e): void {
    global $pass, $fail, $failures;
    if ($a === $e) { $pass++; return; }
    $fail++;
    $failures[] = sprintf("%-64s expected=%-22s actual=%s", $n, var_export($e, true), var_export($a, true));
}

// ---------------------------------------------------------------- state machine
$terminal = [ScanStatus::Completed, ScanStatus::Failed, ScanStatus::Cancelled, ScanStatus::TimedOut];
foreach ($terminal as $t) {
    check("terminal {$t->value} allows nothing", $t->allowedTransitions(), []);
    check("terminal {$t->value} isTerminal", $t->isTerminal(), true);
}

check('queued -> running', ScanStatus::Queued->canTransitionTo(ScanStatus::Running), true);
check('queued -> awaiting_approval', ScanStatus::Queued->canTransitionTo(ScanStatus::AwaitingApproval), true);
check('queued -> completed is invalid', ScanStatus::Queued->canTransitionTo(ScanStatus::Completed), false);
check('queued -> queued is a no-op', ScanStatus::Queued->canTransitionTo(ScanStatus::Queued), false);
check('awaiting_approval -> running blocked', ScanStatus::AwaitingApproval->canTransitionTo(ScanStatus::Running), false);
check('awaiting_approval -> queued (approved)', ScanStatus::AwaitingApproval->canTransitionTo(ScanStatus::Queued), true);
check('running -> cancel_requested', ScanStatus::Running->canTransitionTo(ScanStatus::CancelRequested), true);
check('running -> completed', ScanStatus::Running->canTransitionTo(ScanStatus::Completed), true);
check('cancel_requested -> cancelled', ScanStatus::CancelRequested->canTransitionTo(ScanStatus::Cancelled), true);
check('cancel_requested -> running blocked', ScanStatus::CancelRequested->canTransitionTo(ScanStatus::Running), false);
check('completed cannot be revived', ScanStatus::Completed->canTransitionTo(ScanStatus::Running), false);

foreach ([ScanStatus::Queued, ScanStatus::AwaitingApproval, ScanStatus::Running, ScanStatus::CancelRequested] as $s) {
    check("{$s->value} isInFlight", $s->isInFlight(), true);
    check("{$s->value} isTerminal false", $s->isTerminal(), false);
}

// ------------------------------------------------------------------ plan rules
$registry = [
    'port_scanner' => ScannerIntrusiveness::Active,
    'http_analyzer' => ScannerIntrusiveness::Passive,
    'security_headers' => ScannerIntrusiveness::Passive,
    'sqli_assessment' => ScannerIntrusiveness::Active,
];

$passive = ScanPlan::create(['http_analyzer', 'security_headers'], $registry);
check('passive plan needs no approval', $passive->requiresApproval(), false);
check('passive plan activeTools empty', $passive->activeTools(), []);

$mixed = ScanPlan::create(['http_analyzer', 'sqli_assessment'], $registry);
check('mixed plan needs approval', $mixed->requiresApproval(), true);
check('mixed plan activeTools', $mixed->activeTools(), ['sqli_assessment']);

$unknown = ScanPlan::create(['nonexistent_scanner'], $registry);
check('unknown tool is dropped from the plan', $unknown->tools(), []);
check('empty plan needs no approval', $unknown->requiresApproval(), false);

$plan = ScanPlan::create(['port_scanner', 'http_analyzer'], $registry, ['max_scanners' => 5]);
check('plan has()', $plan->has('port_scanner'), true);
check('plan has() rejects outside tool', $plan->has('nuclei'), false);
check('options are normalised', $plan->option('max_scanners'), 5);
check('unknown options are dropped', $plan->option('inject'), null);

// ------------------------------------------------------------- fingerprinting
$fp1 = $plan->fingerprint('app.example.com', [443]);
$fp2 = $plan->fingerprint('app.example.com', [443]);
check('fingerprint is stable', $fp1 === $fp2, true);
check('fingerprint is 64 hex chars', (bool) preg_match('/^[0-9a-f]{64}$/', $fp1), true);

check('different host changes fingerprint', $plan->fingerprint('other.example.com', [443]) !== $fp1, true);
check('different ports change fingerprint', $plan->fingerprint('app.example.com', [443, 8443]) !== $fp1, true);
check('port order does not matter', $plan->fingerprint('app.example.com', [8443, 443]), $plan->fingerprint('app.example.com', [443, 8443]));

$wider = ScanPlan::create(['port_scanner', 'http_analyzer', 'sqli_assessment'], $registry, ['max_scanners' => 5]);
check('adding a tool changes fingerprint', $wider->fingerprint('app.example.com', [443]) !== $fp1, true);

$withOpt = ScanPlan::create(['port_scanner', 'http_analyzer'], $registry, ['max_scanners' => 6]);
check('changing options changes fingerprint', $withOpt->fingerprint('app.example.com', [443]) !== $fp1, true);

check('host case is normalised', ApprovalFingerprint::for('APP.Example.COM', [443], ['a'], []) === ApprovalFingerprint::for('app.example.com', [443], ['a'], []), true);
check('tool order is normalised', ApprovalFingerprint::for('h', [443], ['b', 'a'], []) === ApprovalFingerprint::for('h', [443], ['a', 'b'], []), true);

// ----------------------------------------------------------- outcome honesty
check('completed is successful', ScanOutcomeReason::Completed->isSuccessful(), true);
check('no_findings is successful', ScanOutcomeReason::NoFindings->isSuccessful(), true);
check('partial is not successful', ScanOutcomeReason::Partial->isSuccessful(), false);
check('scanner_unavailable is not successful', ScanOutcomeReason::ScannerUnavailable->isSuccessful(), false);
check('timed_out style reasons differ', ScanOutcomeReason::ScannerTimeout !== ScanOutcomeReason::Completed, true);
check('every reason has a label', array_filter(ScanOutcomeReason::cases(), fn ($c) => $c->label() === '') === [], true);

// --------------------------------------------------------------------- report
echo "\n";
if ($fail > 0) {
    echo "FAILURES:\n".implode("\n", $failures)."\n\n";
}
echo sprintf("PHP 8.2 approval/plan harness: %d passed, %d failed\n", $pass, $fail);
exit($fail === 0 ? 0 : 1);
