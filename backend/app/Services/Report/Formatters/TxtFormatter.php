<?php

namespace App\Services\Report\Formatters;

class TxtFormatter implements ReportFormatterInterface
{
    public function format(array $data): string
    {
        $lines = [];

        $width = 72;
        $lines[] = str_repeat('=', $width);
        $lines[] = strtoupper($data['title']);
        $lines[] = str_repeat('=', $width);
        $lines[] = '';
        $lines[] = "Generated: {$data['generated_at']}";
        $lines[] = "Target: {$data['target']}";
        $lines[] = "Status: {$data['status']}";
        $lines[] = '';

        if (!empty($data['executive_summary'])) {
            $lines[] = str_repeat('-', $width);
            $lines[] = 'EXECUTIVE SUMMARY';
            $lines[] = str_repeat('-', $width);
            $lines[] = '';
            $lines[] = $data['executive_summary'];
            $lines[] = '';
        }

        if (!empty($data['technical_summary'])) {
            $lines[] = str_repeat('-', $width);
            $lines[] = 'TECHNICAL SUMMARY';
            $lines[] = str_repeat('-', $width);
            $lines[] = '';
            $lines[] = $data['technical_summary'];
            $lines[] = '';
        }

        if (!empty($data['target_info'])) {
            $lines[] = str_repeat('-', $width);
            $lines[] = 'TARGET INFORMATION';
            $lines[] = str_repeat('-', $width);
            $lines[] = '';
            foreach ($data['target_info'] as $key => $value) {
                $lines[] = "  {$key}: {$value}";
            }
            $lines[] = '';
        }

        if (!empty($data['vulnerabilities'])) {
            $lines[] = str_repeat('-', $width);
            $lines[] = 'VULNERABILITIES FOUND';
            $lines[] = str_repeat('-', $width);
            $lines[] = '';
            foreach ($data['vulnerabilities'] as $vuln) {
                $lines[] = "  [{$vuln['severity']}] {$vuln['title']}";
                $lines[] = "       {$vuln['description']}";
            }
            $lines[] = '';
        }

        if (!empty($data['recommendations'])) {
            $lines[] = str_repeat('-', $width);
            $lines[] = 'RECOMMENDATIONS';
            $lines[] = str_repeat('-', $width);
            $lines[] = '';
            foreach ($data['recommendations'] as $rec) {
                $lines[] = "  * {$rec}";
            }
            $lines[] = '';
        }

        if (!empty($data['risk_score'])) {
            $lines[] = str_repeat('-', $width);
            $lines[] = 'RISK ASSESSMENT';
            $lines[] = str_repeat('-', $width);
            $lines[] = '';
            $lines[] = "  Overall Risk: {$data['risk_score']['level']} ({$data['risk_score']['score']}/10)";
            $lines[] = '';
        }

        $lines[] = str_repeat('=', $width);
        $lines[] = 'END OF REPORT';
        $lines[] = str_repeat('=', $width);

        return implode("\n", $lines);
    }

    public function getMimeType(): string
    {
        return 'text/plain';
    }

    public function getExtension(): string
    {
        return 'txt';
    }
}
