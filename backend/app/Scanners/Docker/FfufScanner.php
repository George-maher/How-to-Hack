<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class FfufScanner extends BaseDockerScanner
{
    protected string $toolName = 'ffuf';

    public function name(): string
    {
        return 'ffuf';
    }

    public function description(): string
    {
        return 'Fast web fuzzer for directory and parameter discovery';
    }

    public function category(): string
    {
        return ScannerCategory::WebApplication->value;
    }

    public function severity(): string
    {
        return 'high';
    }

    protected function parseResults(string $rawOutput, Project $project): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $data = $this->safeJsonDecode($rawOutput);

        $fuzzResults = $data['results'] ?? [];

        if (!empty($fuzzResults)) {
            foreach ($fuzzResults as $result) {
                $url = $result['url'] ?? '';
                $status = $result['status'] ?? 0;
                $length = $result['length'] ?? 0;

                if ($status >= 200 && $status < 400) {
                    $results->add($this->createResult(
                        'medium',
                        "Fuzzed endpoint: HTTP {$status} - {$url}",
                        "FFUF discovered endpoint: {$url} (size: {$length})",
                        ['url' => $url, 'status' => $status, 'length' => $length]
                    ));
                }
            }

            if ($results->count() > 0) {
                $results->add($this->createResult(
                    'info',
                    'Fuzzing complete',
                    sprintf('FFUF discovered %d valid endpoint(s)', $results->count()),
                    ['total_found' => $results->count()]
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No fuzzing results',
                'FFUF did not discover additional endpoints'
            ));
        }

        return $results;
    }

    protected function buildCommand(string $target, array $context): array
    {
        return ['ffuf', '-u', rtrim($target, '/') . '/FUZZ', '-w', '/wordlists/common.txt', '-json'];
    }
}
