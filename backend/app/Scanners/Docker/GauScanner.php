<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class GauScanner extends BaseDockerScanner
{
    protected string $toolName = 'gau';

    public function name(): string
    {
        return 'gau';
    }

    public function description(): string
    {
        return 'Get All URLs - fetches known URLs from public sources';
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

        $urls = [];
        foreach ($lines as $line) {
            $entry = json_decode($line, true);
            if (isset($entry['url'])) {
                $urls[] = $entry['url'];
            } elseif (filter_var(trim($line), FILTER_VALIDATE_URL)) {
                $urls[] = trim($line);
            }
        }

        $urls = array_unique($urls);

        if (!empty($urls)) {
            $results->add($this->createResult(
                'info',
                'Known URLs gathered from public sources',
                sprintf('GAU gathered %d known URL(s) from public sources', count($urls)),
                ['urls' => array_slice($urls, 0, 100)]
            ));

            $paramUrls = array_filter($urls, fn($u) => str_contains($u, '?') || str_contains($u, '='));
            if (!empty($paramUrls)) {
                $results->add($this->createResult(
                    'low',
                    'URLs with parameters discovered',
                    sprintf('Found %d URL(s) with query parameters', count($paramUrls)),
                    ['parameterized_urls' => array_slice($paramUrls, 0, 50)]
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No URLs gathered',
                'GAU did not find any known URLs from public sources'
            ));
        }

        return $results;
    }
}
