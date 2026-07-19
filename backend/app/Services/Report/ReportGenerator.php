<?php

namespace App\Services\Report;

use App\Contracts\ReportRepositoryInterface;
use App\Models\Scan;
use App\Models\ScanResult;
use App\Services\Report\Formatters\HtmlFormatter;
use App\Services\Report\Formatters\JsonFormatter;
use App\Services\Report\Formatters\MarkdownFormatter;
use App\Services\Report\Formatters\PdfFormatter;
use App\Services\Report\Formatters\ReportFormatterInterface;
use App\Services\Report\Formatters\TxtFormatter;
use Illuminate\Support\Facades\Log;

class ReportGenerator
{
    private array $formatters;

    public function __construct(
        private readonly ReportRepositoryInterface $reportRepository,
    ) {
        $this->formatters = [
            'pdf' => PdfFormatter::class,
            'json' => JsonFormatter::class,
            'html' => HtmlFormatter::class,
            'md' => MarkdownFormatter::class,
            'txt' => TxtFormatter::class,
        ];
    }

    public function generate(Scan $scan, string $format = 'html'): array
    {
        $scan->loadMissing(['project', 'results']);

        $data = $this->buildData($scan);

        $formatter = $this->resolveFormatter($format);
        $content = $formatter->format($data);

        $report = $this->reportRepository->create([
            'scan_id' => $scan->id,
            'title' => "Security Scan Report - {$scan->project->name}",
            'executive_summary' => $data['executive_summary'] ?? null,
            'technical_summary' => $data['technical_summary'] ?? null,
            'recommendations' => $data['recommendations'] ? implode("\n", $data['recommendations']) : null,
            'scan_data' => $data,
            'ai_analysis' => $data['ai_analysis'] ?? null,
            'format' => $format,
            'status' => 'generated',
        ]);

        return [
            'report' => $report,
            'content' => $content,
            'formatter' => $formatter,
        ];
    }

    public function regenerate(int $reportId, string $format = 'html'): array
    {
        $report = $this->reportRepository->findById($reportId);
        if (!$report) {
            throw new \RuntimeException('Report not found');
        }

        $scan = $report->scan;
        if (!$scan) {
            throw new \RuntimeException('Associated scan not found');
        }

        $data = $this->buildData($scan);
        $formatter = $this->resolveFormatter($format);
        $content = $formatter->format($data);

        $this->reportRepository->update($report, [
            'title' => "Security Scan Report - {$scan->project->name}",
            'executive_summary' => $data['executive_summary'] ?? $report->executive_summary,
            'technical_summary' => $data['technical_summary'] ?? $report->technical_summary,
            'recommendations' => $data['recommendations'] ? implode("\n", $data['recommendations']) : $report->recommendations,
            'scan_data' => $data,
            'ai_analysis' => $data['ai_analysis'] ?? $report->ai_analysis,
            'format' => $format,
            'status' => 'regenerated',
        ]);

        return [
            'report' => $report->fresh(),
            'content' => $content,
            'formatter' => $formatter,
        ];
    }

    public function export(int $reportId, string $format): array
    {
        $report = $this->reportRepository->findById($reportId);
        if (!$report) {
            throw new \RuntimeException('Report not found');
        }

        $formatter = $this->resolveFormatter($format);
        $data = $report->scan_data ?? [];
        $content = $formatter->format($data);

        return [
            'content' => $content,
            'formatter' => $formatter,
        ];
    }

    private function buildData(Scan $scan): array
    {
        $project = $scan->project;
        $results = $scan->results;
        $findings = $results->groupBy('scanner_name');

        $vulnerabilities = $results->map(fn(ScanResult $r) => [
            'severity' => $r->severity,
            'title' => $r->title,
            'description' => $r->description,
            'scanner' => $r->scanner_name,
        ])->toArray();

        $severityCounts = $results->groupBy('severity')->map->count()->toArray();
        $severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
        $severityLevels = [];
        foreach ($severityOrder as $sev) {
            $severityLevels[$sev] = $severityCounts[$sev] ?? 0;
        }

        $portResults = $findings->get('port_scanner', collect())->merge($findings->get('nmap', collect()));
        $openPorts = [];
        foreach ($portResults as $result) {
            $details = $result->details ?? [];
            if (isset($details['port'])) {
                $openPorts[] = [
                    'port' => $details['port'],
                    'service' => $details['service'] ?? 'unknown',
                    'severity' => $result->severity,
                ];
            }
        }

        $directoryResults = $findings->get('directory_brute_forcer', collect())
            ->merge($findings->get('dirsearch', collect()))
            ->merge($findings->get('ffuf', collect()));
        $http200Endpoints = [];
        foreach ($directoryResults as $result) {
            $details = $result->details ?? [];
            $statusCode = (int) ($details['status_code'] ?? $details['status'] ?? 0);
            if ($statusCode === 200 || $statusCode === 0) {
                $http200Endpoints[] = $details['url'] ?? $details['path'] ?? $result->title;
            }
        }

        $techResults = $findings->get('technology_detector', collect())
            ->merge($findings->get('whatweb', collect()))
            ->merge($findings->get('httpx', collect()));
        $technologies = $techResults->map(fn($r) => $r->title)->toArray();

        $securityHeadersResults = $findings->get('security_headers', collect());
        $securityHeaderFindings = $securityHeadersResults->map(fn($r) => [
            'severity' => $r->severity,
            'title' => $r->title,
            'description' => $r->description,
            'details' => $r->details ?? [],
        ])->toArray();

        $xssResults = $findings->get('xss_assessment', collect());
        $xssFindings = $xssResults->map(fn($r) => [
            'severity' => $r->severity,
            'title' => $r->title,
            'description' => $r->description,
            'affected_endpoint' => $r->details['affected_endpoint'] ?? $r->details['affected_fields'] ?? 'N/A',
            'remediation' => $r->details['remediation'] ?? 'Implement proper output encoding and input validation.',
        ])->toArray();

        $sqliResults = $findings->get('sqli_assessment', collect());
        $sqliFindings = $sqliResults->map(fn($r) => [
            'severity' => $r->severity,
            'title' => $r->title,
            'description' => $r->description,
            'affected_endpoint' => $r->details['affected_endpoint'] ?? $r->details['affected_parameter'] ?? 'N/A',
            'remediation' => $r->details['remediation'] ?? 'Use parameterized queries.',
        ])->toArray();

        $apiResults = $findings->get('api_assessment', collect());
        $apiFindings = $apiResults->map(fn($r) => [
            'severity' => $r->severity,
            'title' => $r->title,
            'description' => $r->description,
            'details' => $r->details ?? [],
        ])->toArray();

        $findingsTotal = $results->count();
        $criticalCount = $severityLevels['critical'] ?? 0;
        $highCount = $severityLevels['high'] ?? 0;
        $riskScore = $this->calculateRiskScore($criticalCount, $highCount, $findingsTotal, $xssFindings, $sqliFindings);

        $scannerHistory = $scan->completed_scanners ?? [];
        $reasoning = $scan->ai_reasoning ?? [];
        $reasoningHistory = array_map(fn($e) => $e['message'] ?? '', $reasoning);

        $aiAnalysis = $this->generateAiAnalysis($scan, $results, $severityLevels);

        $executiveSummary = $this->buildExecutiveSummary($project, $scan, $findingsTotal, $riskScore, $severityLevels);
        $technicalSummary = $this->buildTechnicalSummary($scan, $findings, $severityLevels);
        $recommendations = $this->buildRecommendations($results);
        $mitigationSteps = $this->buildMitigationSteps($results, $xssFindings, $sqliFindings);

        return [
            'title' => "Security Scan Report - {$project->name}",
            'generated_at' => now()->toIso8601String(),
            'target' => $project->target_url,
            'status' => $scan->status,
            'project_name' => $project->name,
            'project_description' => $project->description,
            'executive_summary' => $executiveSummary,
            'technical_summary' => $technicalSummary,
            'target_info' => [
                'URL' => $project->target_url,
                'Description' => $project->description ?? 'N/A',
                'Project ID' => (string) $project->id,
            ],
            'scan_timeline' => [
                ['label' => 'Started', 'value' => $scan->started_at?->toIso8601String() ?? 'N/A'],
                ['label' => 'Completed', 'value' => $scan->completed_at?->toIso8601String() ?? 'N/A'],
                ['label' => 'Duration', 'value' => $this->getDuration($scan)],
                ['label' => 'Status', 'value' => $scan->status],
            ],
            'technologies' => $technologies,
            'open_ports' => $openPorts,
            'endpoints' => $http200Endpoints,
            'vulnerabilities' => $vulnerabilities,
            'risk_score' => $riskScore,
            'severity_levels' => $severityLevels,
            'xss_findings' => $xssFindings,
            'sqli_findings' => $sqliFindings,
            'api_findings' => $apiFindings,
            'security_header_findings' => $securityHeaderFindings,
            'ai_analysis' => $aiAnalysis,
            'recommendations' => $recommendations,
            'mitigation_steps' => $mitigationSteps,
            'scan_statistics' => [
                'Total Findings' => (string) $findingsTotal,
                'Scanners Executed' => (string) count($scannerHistory),
                'Critical Issues' => (string) $criticalCount,
                'High Issues' => (string) $highCount,
                'Open Ports Detected' => (string) count($openPorts),
                'HTTP Endpoints Found' => (string) count($http200Endpoints),
                'Technologies Identified' => (string) count($technologies),
                'XSS Findings' => (string) count($xssFindings),
                'SQL Injection Findings' => (string) count($sqliFindings),
                'API Findings' => (string) count($apiFindings),
                'Security Header Issues' => (string) count($securityHeaderFindings),
            ],
            'scanner_execution_history' => $scannerHistory,
            'reasoning_history' => $reasoningHistory,
        ];
    }

    private function resolveFormatter(string $format): ReportFormatterInterface
    {
        $class = $this->formatters[$format] ?? null;
        if (!$class) {
            throw new \InvalidArgumentException("Unsupported format: {$format}");
        }
        return app($class);
    }

    private function calculateRiskScore(int $critical, int $high, int $total, array $xssFindings = [], array $sqliFindings = []): array
    {
        $baseScore = ($critical * 3 + $high * 1.5) / max(1, $total) * 10;

        $xssCritical = count(array_filter($xssFindings, fn($f) => $f['severity'] === 'critical'));
        $xssHigh = count(array_filter($xssFindings, fn($f) => $f['severity'] === 'high'));
        $sqliCritical = count(array_filter($sqliFindings, fn($f) => $f['severity'] === 'critical'));

        $penalty = ($xssCritical + $sqliCritical) * 1.5 + $xssHigh * 0.5;

        $score = min(10, round($baseScore + $penalty, 1));

        $level = match (true) {
            $score >= 8 => 'critical',
            $score >= 6 => 'high',
            $score >= 3 => 'medium',
            default => 'low',
        };

        return ['score' => $score, 'level' => $level];
    }

    private function getDuration(Scan $scan): string
    {
        if (!$scan->started_at) {
            return 'N/A';
        }
        $end = $scan->completed_at ?? now();
        $minutes = (int) $end->diffInMinutes($scan->started_at);
        $seconds = (int) $end->diffInSeconds($scan->started_at) % 60;
        return "{$minutes}m {$seconds}s";
    }

    private function buildExecutiveSummary($project, $scan, int $totalFindings, array $riskScore, array $severityLevels): string
    {
        $critical = $severityLevels['critical'] ?? 0;
        $high = $severityLevels['high'] ?? 0;
        $medium = $severityLevels['medium'] ?? 0;

        return "A security scan of {$project->target_url} ({$project->name}) completed with a risk level of {$riskScore['level']} ({$riskScore['score']}/10). "
            . "The scan identified {$totalFindings} finding(s) across multiple security categories, including {$critical} critical, {$high} high, and {$medium} medium severity issues. "
            . "Immediate attention is recommended for critical and high-severity findings to mitigate potential security risks.";
    }

    private function buildTechnicalSummary($scan, $findings, array $severityLevels): string
    {
        $parts = [];
        foreach ($findings as $scanner => $results) {
            $parts[] = "{$scanner}: {$results->count()} finding(s)";
        }
        $scannerSummary = implode('; ', $parts);

        return "Scan #{$scan->id} utilized " . count($findings) . " scanner(s) to enumerate the target. "
            . "{$scannerSummary}. "
            . "The scan ran for {$this->getDuration($scan)} and completed with status '{$scan->status}'.";
    }

    private function buildRecommendations($results): array
    {
        $recs = [];
        $added = [];

        foreach ($results as $result) {
            $severity = $result->severity;
            $title = $result->title;

            if (in_array($severity, ['critical', 'high']) && !in_array($title, $added)) {
                $added[] = $title;
                $recs[] = "Address '{$title}' — prioritize remediation of {$severity}-severity issues immediately.";
            }
        }

        if (empty($recs)) {
            $recs[] = 'No critical or high-severity issues found. Continue regular security monitoring.';
            $recs[] = 'Keep software and dependencies up to date.';
            $recs[] = 'Perform periodic security assessments.';
        } else {
            $recs[] = 'Implement a web application firewall (WAF) for additional protection.';
            $recs[] = 'Conduct regular security training for development teams.';
            $recs[] = 'Establish a vulnerability management program with defined SLAs.';
        }

        return $recs;
    }

    private function buildMitigationSteps($results, array $xssFindings = [], array $sqliFindings = []): array
    {
        $steps = [];

        foreach ($results as $result) {
            $title = strtolower($result->title);
            if (str_contains($title, 'open port')) {
                $steps[] = "Close unnecessary ports or restrict access via firewall rules.";
            } elseif (str_contains($title, 'accessible path') || str_contains($title, 'discovered path')) {
                $steps[] = "Restrict access to sensitive paths and directories. Implement proper authentication.";
            } elseif (str_contains($title, 'ssl') || str_contains($title, 'certificate') || str_contains($title, 'cipher')) {
                $steps[] = "Renew and properly configure SSL/TLS certificates. Disable weak ciphers and deprecated protocols.";
            } elseif (str_contains($title, 'dns')) {
                $steps[] = "Review DNS configuration and prevent information disclosure.";
            } elseif (str_contains($title, 'xss') || str_contains($title, 'cross-site')) {
                $steps[] = "Implement Content-Security-Policy headers and context-aware output encoding to prevent XSS.";
            } elseif (str_contains($title, 'sql') || str_contains($title, 'injection')) {
                $steps[] = "Use parameterized queries or prepared statements for all database operations.";
            } elseif (str_contains($title, 'security header') || str_contains($title, 'missing')) {
                $steps[] = "Implement missing security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options.";
            } elseif (str_contains($title, 'api') || str_contains($title, 'endpoint')) {
                $steps[] = "Implement authentication and rate limiting for all API endpoints.";
            } elseif (str_contains($title, 'jwt') || str_contains($title, 'token')) {
                $steps[] = "Ensure JWT tokens use strong signing algorithms and are not exposed in client-side responses.";
            } elseif (str_contains($title, 'cookie')) {
                $steps[] = "Set Secure, HttpOnly, and SameSite flags on all cookies.";
            } elseif (str_contains($title, 'cors')) {
                $steps[] = "Restrict CORS policy to specific trusted origins instead of wildcard (*).";
            }
        }

        if (!empty($xssFindings)) {
            $steps[] = "Address XSS vulnerabilities: implement output encoding, CSP headers, and input validation.";
        }
        if (!empty($sqliFindings)) {
            $steps[] = "Address SQL injection vulnerabilities: migrate to parameterized queries and implement WAF rules.";
        }

        if (empty($steps)) {
            $steps = [
                'Review and apply security best practices for the target environment.',
                'Enable security headers (CSP, HSTS, X-Frame-Options).',
                'Implement rate limiting and input validation.',
                'Conduct regular security assessments and penetration testing.',
            ];
        }

        $steps[] = 'Schedule a follow-up scan after applying mitigations.';
        $steps[] = 'Document all findings and remediation actions for compliance.';
        return array_unique($steps);
    }

    private function generateAiAnalysis(Scan $scan, $results, array $severityLevels): string
    {
        try {
            $provider = app(\App\Services\Ai\AiAgentService::class);
            $reflection = new \ReflectionMethod($provider, 'resolveProvider');
            $reflection->setAccessible(true);
            $aiProvider = $reflection->invoke($provider);

            $context = [
                'scan_id' => $scan->id,
                'target' => $scan->project->target_url,
                'total_findings' => $results->count(),
                'severity_breakdown' => $severityLevels,
                'status' => $scan->status,
            ];

            return $aiProvider->analyzeResults(
                $results->groupBy('scanner_name')->toArray(),
                $scan->ai_reasoning ?? []
            );
        } catch (\Throwable $e) {
            Log::warning('AI analysis generation failed, using fallback', ['error' => $e->getMessage()]);
            return $this->fallbackAiAnalysis($results, $severityLevels);
        }
    }

    private function fallbackAiAnalysis($results, array $severityLevels): string
    {
        $total = $results->count();
        $critical = $severityLevels['critical'] ?? 0;
        $high = $severityLevels['high'] ?? 0;

        $analysis = "Security scan completed with {$total} total finding(s). ";
        $analysis .= "The assessment revealed {$critical} critical and {$high} high-severity issues that require immediate attention. ";

        if ($critical > 0 || $high > 0) {
            $analysis .= "Priority should be given to addressing critical and high-severity findings, as they represent the most significant security risks to the target application. ";
        } else {
            $analysis .= "No critical or high-severity issues were identified, suggesting a reasonable security posture. ";
        }

        $analysis .= "Regular security assessments and monitoring are recommended to maintain this security posture.";

        return $analysis;
    }

    public function getFormatters(): array
    {
        return array_keys($this->formatters);
    }
}
