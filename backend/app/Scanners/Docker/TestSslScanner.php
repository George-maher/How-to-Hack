<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class TestSslScanner extends BaseDockerScanner
{
    protected string $toolName = 'testssl';

    public function name(): string
    {
        return 'testssl';
    }

    public function description(): string
    {
        return 'Comprehensive SSL/TLS security assessment tool';
    }

    public function category(): string
    {
        return ScannerCategory::Infrastructure->value;
    }

    public function severity(): string
    {
        return 'high';
    }

    protected function parseResults(string $rawOutput, Project $project): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $data = $this->safeJsonDecode($rawOutput);

        if (!empty($data)) {
            $findings = [];
            $scanResults = $data['scanResult'] ?? $data;

            foreach ($scanResults as $key => $value) {
                if (is_array($value)) {
                    $severity = $this->mapSeverity($value['severity'] ?? 'INFO');
                    $id = $value['id'] ?? $key;
                    $finding = $value['finding'] ?? json_encode($value);

                    $results->add($this->createResult(
                        $severity,
                        "TestSSL: {$id}",
                        $finding,
                        ['test_id' => $id, 'finding' => $finding, 'severity_original' => $value['severity'] ?? 'INFO']
                    ));
                    $findings[] = $id;
                }
            }

            if (empty($findings)) {
                $results->add($this->createResult(
                    'info',
                    'SSL assessment complete',
                    'testssl.sh completed assessment'
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'SSL assessment complete',
                'testssl.sh completed assessment with no JSON findings'
            ));
        }

        return $results;
    }

    private function mapSeverity(string $severity): string
    {
        return match (strtoupper($severity)) {
            'CRITICAL', 'HIGH' => 'high',
            'MEDIUM' => 'medium',
            'LOW' => 'low',
            default => 'info',
        };
    }
}
