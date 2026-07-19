<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class WaybackUrlsScanner extends BaseDockerScanner
{
    protected string $toolName = 'waybackurls';

    public function name(): string
    {
        return 'waybackurls';
    }

    public function description(): string
    {
        return 'Fetches historical URLs from Wayback Machine';
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
            $url = trim($line);
            if (filter_var($url, FILTER_VALIDATE_URL)) {
                $urls[] = $url;
            }
        }

        $urls = array_unique($urls);

        if (!empty($urls)) {
            $results->add($this->createResult(
                'info',
                'Historical URLs retrieved from Wayback Machine',
                sprintf('Found %d historical URL(s) from Wayback Machine', count($urls)),
                ['urls' => array_slice($urls, 0, 100)]
            ));

            $endpoints = [];
            foreach ($urls as $url) {
                $parsed = parse_url($url);
                $path = $parsed['path'] ?? '/';
                $endpoints[$path] = ($endpoints[$path] ?? 0) + 1;
            }
            arsort($endpoints);

            $results->add($this->createResult(
                'low',
                'Most crawled endpoints from Wayback',
                sprintf('Found %d unique path(s) historically', count($endpoints)),
                ['top_endpoints' => array_slice($endpoints, 0, 20)]
            ));
        } else {
            $results->add($this->createResult(
                'info',
                'No Wayback Machine URLs',
                'Wayback Machine did not return historical URLs for this target'
            ));
        }

        return $results;
    }
}
