<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class HakrawlerScanner extends BaseDockerScanner
{
    protected string $toolName = 'hakrawler';

    public function name(): string
    {
        return 'hakrawler';
    }

    public function description(): string
    {
        return 'Web crawler for endpoint discovery and JavaScript analysis';
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
        $jsFiles = [];
        $forms = [];

        foreach ($lines as $line) {
            $entry = json_decode($line, true);
            if (!$entry) {
                continue;
            }
            $url = $entry['url'] ?? $entry['endpoint'] ?? '';
            $source = $entry['source'] ?? '';

            if (!empty($url)) {
                $urls[] = $url;
                if (preg_match('/\.js$/i', $url)) {
                    $jsFiles[] = $url;
                }
                if (str_contains($source, 'form')) {
                    $forms[] = $url;
                }
            }
        }

        $urls = array_unique($urls);

        if (!empty($urls)) {
            $results->add($this->createResult(
                'info',
                'URLs discovered via Hakrawler',
                sprintf('Discovered %d unique URL(s)', count($urls)),
                ['urls' => array_slice($urls, 0, 100)]
            ));

            if (!empty($jsFiles)) {
                $results->add($this->createResult(
                    'low',
                    'JavaScript files discovered',
                    sprintf('Found %d JavaScript file(s) for analysis', count($jsFiles)),
                    ['js_files' => $jsFiles]
                ));
            }

            if (!empty($forms)) {
                $results->add($this->createResult(
                    'medium',
                    'Forms discovered on target',
                    sprintf('Found %d form(s) that may handle user input', count($forms)),
                    ['form_endpoints' => $forms]
                ));
            }
        } else {
            $results->add($this->createResult(
                'info',
                'No URLs discovered',
                'Hakrawler did not discover any URLs'
            ));
        }

        return $results;
    }
}
