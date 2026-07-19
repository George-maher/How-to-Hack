<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class KatanaScanner extends BaseDockerScanner
{
    protected string $toolName = 'katana';

    public function name(): string
    {
        return 'katana';
    }

    public function description(): string
    {
        return 'Web crawler and endpoint discovery tool';
    }

    public function category(): string
    {
        return ScannerCategory::WebApplication->value;
    }

    public function severity(): string
    {
        return 'info';
    }

    protected function parseResults(string $rawOutput, Project $project): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $lines = array_filter(explode("\n", trim($rawOutput)));

        $endpoints = [];
        foreach ($lines as $line) {
            $entry = json_decode($line, true);
            if (isset($entry['endpoint'])) {
                $endpoints[] = $entry['endpoint'];
            } elseif (filter_var(trim($line), FILTER_VALIDATE_URL)) {
                $endpoints[] = trim($line);
            }
        }

        $endpoints = array_unique($endpoints);

        if (!empty($endpoints)) {
            $results->add($this->createResult(
                'info',
                'Endpoints discovered via Katana crawler',
                sprintf('Katana discovered %d unique endpoint(s)', count($endpoints)),
                ['endpoints' => $endpoints]
            ));

            $sensitive = [];
            foreach ($endpoints as $ep) {
                if (preg_match('/\.(env|git|config|sql|bak|old|phpinfo|log)$/i', $ep)) {
                    $sensitive[] = $ep;
                }
            }

            if (!empty($sensitive)) {
                $results->add($this->createResult(
                    'high',
                    'Sensitive endpoints exposed',
                    sprintf('Found %d potentially sensitive endpoint(s): %s',
                        count($sensitive), implode(', ', array_slice($sensitive, 0, 10))),
                    ['sensitive_endpoints' => $sensitive]
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No endpoints discovered',
                'Katana did not discover any endpoints'
            ));
        }

        return $results;
    }
}
