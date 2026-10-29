<?php

namespace App\Contracts;

use App\DTOs\ScannerExecutionResult;
use App\Enums\ScannerIntrusiveness;
use App\Models\Project;

interface ScannerInterface
{
    public function name(): string;

    public function description(): string;

    public function category(): string;

    public function severity(): string;

    /**
     * Execute the scanner.
     *
     * The result always states an outcome. A scanner that produced no findings
     * and one that failed to run are different results, and callers must never
     * collapse them.
     *
     * @param  array<string, mixed>  $context  includes `scan`, `job_id`,
     *                                         `pinned_ips`, `scope` and
     *                                         `approval_fingerprint` when run
     *                                         as part of a scan.
     */
    public function execute(Project $project, array $context = []): ScannerExecutionResult;

    public function dependencies(): array;

    public function requiresTarget(): bool;

    /**
     * Whether running this scanner requires explicit operator approval.
     * Unclassified scanners must be treated as Active (fail closed).
     */
    public function intrusiveness(): ScannerIntrusiveness;

    /**
     * The Runner registry tool this scanner delegates to, or null when the
     * scanner runs in-process. When non-null, the scanner must not invoke any
     * process itself: the Runner owns argv construction.
     */
    public function runnerTool(): ?string;
}
