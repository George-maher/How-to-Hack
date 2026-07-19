<?php

namespace App\Contracts;

use App\DTOs\ScanContext;

interface AiProviderInterface
{
    public function decideNextScanner(ScanContext $context): string;
    public function analyzeResults(array $results, array $reasoningChain): string;
    public function shouldStop(array $completedScanners, array $results): bool;
}
