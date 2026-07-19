<?php

namespace App\Services\Report\Formatters;

class MarkdownFormatter implements ReportFormatterInterface
{
    public function format(array $data): string
    {
        $lines = [];

        $lines[] = "# {$data['title']}";
        $lines[] = '';
        $lines[] = "**Generated:** {$data['generated_at']}";
        $lines[] = "**Target:** {$data['target']}";
        $lines[] = "**Status:** {$data['status']}";
        $lines[] = '';

        if (!empty($data['executive_summary'])) {
            $lines[] = '## Executive Summary';
            $lines[] = '';
            $lines[] = $data['executive_summary'];
            $lines[] = '';
        }

        if (!empty($data['technical_summary'])) {
            $lines[] = '## Technical Summary';
            $lines[] = '';
            $lines[] = $data['technical_summary'];
            $lines[] = '';
        }

        if (!empty($data['target_info'])) {
            $lines[] = '## Target Information';
            $lines[] = '';
            foreach ($data['target_info'] as $key => $value) {
                $lines[] = "- **{$key}:** {$value}";
            }
            $lines[] = '';
        }

        if (!empty($data['scan_timeline'])) {
            $lines[] = '## Scan Timeline';
            $lines[] = '';
            foreach ($data['scan_timeline'] as $entry) {
                $lines[] = "- {$entry['label']}: {$entry['value']}";
            }
            $lines[] = '';
        }

        if (!empty($data['technologies'])) {
            $lines[] = '## Technologies Detected';
            $lines[] = '';
            foreach ($data['technologies'] as $tech) {
                $lines[] = "- {$tech}";
            }
            $lines[] = '';
        }

        if (!empty($data['open_ports'])) {
            $lines[] = '## Open Ports';
            $lines[] = '';
            foreach ($data['open_ports'] as $port) {
                $lines[] = "- Port {$port['port']}/{$port['service']} ({$port['severity']})";
            }
            $lines[] = '';
        }

        if (!empty($data['endpoints'])) {
            $lines[] = "## HTTP 200 Endpoints";
            $lines[] = '';
            foreach ($data['endpoints'] as $ep) {
                $lines[] = "- {$ep}";
            }
            $lines[] = '';
        }

        if (!empty($data['vulnerabilities'])) {
            $lines[] = '## Vulnerabilities Found';
            $lines[] = '';
            foreach ($data['vulnerabilities'] as $vuln) {
                $lines[] = "- [{$vuln['severity']}] {$vuln['title']}: {$vuln['description']}";
            }
            $lines[] = '';
        }

        if (!empty($data['risk_score'])) {
            $lines[] = "## Risk Score";
            $lines[] = '';
            $lines[] = "**Overall Risk:** {$data['risk_score']['level']} ({$data['risk_score']['score']}/10)";
            $lines[] = '';
        }

        if (!empty($data['severity_levels'])) {
            $lines[] = '## Severity Levels';
            $lines[] = '';
            foreach ($data['severity_levels'] as $severity => $count) {
                $bar = str_repeat('█', $count);
                $lines[] = "- {$severity}: {$count} {$bar}";
            }
            $lines[] = '';
        }

        if (!empty($data['xss_findings'])) {
            $lines[] = '## XSS Findings';
            $lines[] = '';
            foreach ($data['xss_findings'] as $xss) {
                $lines[] = "- [{$xss['severity']}] {$xss['title']}: {$xss['description']}";
                $lines[] = "  - Affected: {$xss['affected_endpoint']}";
            }
            $lines[] = '';
        }

        if (!empty($data['sqli_findings'])) {
            $lines[] = '## SQL Injection Findings';
            $lines[] = '';
            foreach ($data['sqli_findings'] as $sqli) {
                $lines[] = "- [{$sqli['severity']}] {$sqli['title']}: {$sqli['description']}";
                $lines[] = "  - Affected: {$sqli['affected_endpoint']}";
            }
            $lines[] = '';
        }

        if (!empty($data['api_findings'])) {
            $lines[] = '## API Assessment Findings';
            $lines[] = '';
            foreach ($data['api_findings'] as $api) {
                $lines[] = "- [{$api['severity']}] {$api['title']}: {$api['description']}";
            }
            $lines[] = '';
        }

        if (!empty($data['security_header_findings'])) {
            $lines[] = '## Security Header Analysis';
            $lines[] = '';
            foreach ($data['security_header_findings'] as $sh) {
                $lines[] = "- [{$sh['severity']}] {$sh['title']}: {$sh['description']}";
            }
            $lines[] = '';
        }

        if (!empty($data['ai_analysis'])) {
            $lines[] = '## AI Analysis';
            $lines[] = '';
            $lines[] = $data['ai_analysis'];
            $lines[] = '';
        }

        if (!empty($data['recommendations'])) {
            $lines[] = '## Recommendations';
            $lines[] = '';
            foreach ($data['recommendations'] as $rec) {
                $lines[] = "- {$rec}";
            }
            $lines[] = '';
        }

        if (!empty($data['mitigation_steps'])) {
            $lines[] = '## Mitigation Steps';
            $lines[] = '';
            foreach ($data['mitigation_steps'] as $step) {
                $lines[] = "- {$step}";
            }
            $lines[] = '';
        }

        if (!empty($data['scan_statistics'])) {
            $lines[] = '## Scan Statistics';
            $lines[] = '';
            foreach ($data['scan_statistics'] as $key => $value) {
                $lines[] = "- {$key}: {$value}";
            }
            $lines[] = '';
        }

        if (!empty($data['scanner_execution_history'])) {
            $lines[] = '## Scanner Execution History';
            $lines[] = '';
            foreach ($data['scanner_execution_history'] as $entry) {
                $lines[] = "- {$entry}";
            }
            $lines[] = '';
        }

        return implode("\n", $lines);
    }

    public function getMimeType(): string
    {
        return 'text/markdown';
    }

    public function getExtension(): string
    {
        return 'md';
    }
}
