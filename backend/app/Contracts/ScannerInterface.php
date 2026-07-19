<?php

namespace App\Contracts;

use App\DTOs\ScanResultCollection;
use App\Models\Project;

interface ScannerInterface
{
    public function name(): string;
    public function description(): string;
    public function category(): string;
    public function severity(): string;
    public function execute(Project $project, array $context = []): ScanResultCollection;
    public function dependencies(): array;
    public function requiresTarget(): bool;
}
