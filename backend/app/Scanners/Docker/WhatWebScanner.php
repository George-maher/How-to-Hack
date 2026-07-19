<?php

namespace App\Scanners\Docker;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerCategory;
use App\Models\Project;

class WhatWebScanner extends BaseDockerScanner
{
    protected string $toolName = 'whatweb';

    protected array $defaultArgs = ['--aggression', '3'];

    public function name(): string
    {
        return 'whatweb';
    }

    public function description(): string
    {
        return 'Web technology fingerprinting and version detection';
    }

    public function category(): string
    {
        return ScannerCategory::Reconnaissance->value;
    }

    public function severity(): string
    {
        return 'info';
    }

    protected function parseResults(string $rawOutput, Project $project): ScanResultCollection
    {
        $results = new ScanResultCollection();
        $data = $this->safeJsonDecode($rawOutput);

        $technologies = [];
        if (!empty($data) && isset($data[0])) {
            $entry = $data[0];
            foreach ($entry as $key => $value) {
                if (!in_array($key, ['target', 'http_status', 'redirect_to', 'country', 'ip', 'title', 'priority'])) {
                    $technologies[$key] = is_array($value) ? implode(', ', $value) : (string) $value;
                }
            }
        }

        if (!empty($technologies)) {
            $results->add($this->createResult(
                'info',
                'Web technologies fingerprinted',
                sprintf('Identified %d technology/ies via WhatWeb', count($technologies)),
                ['technologies' => $technologies, 'raw' => $data]
            ));
        } else {
            $results->add($this->createResult(
                'info',
                'No technologies fingerprinted',
                'WhatWeb could not identify specific technologies'
            ));
        }

        return $results;
    }
}
