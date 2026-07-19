<?php

namespace App\Services\Ai\Providers;

use App\Contracts\AiProviderInterface;
use App\DTOs\ScanContext;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class OpenAiProvider implements AiProviderInterface
{
    private string $apiKey;
    private string $model;
    private float $temperature;
    private int $maxTokens;

    public function __construct()
    {
        $config = config('ai-agent.providers.openai');
        $this->apiKey = $config['api_key'] ?? '';
        $this->model = $config['model'] ?? 'gpt-4';
        $this->temperature = (float) ($config['temperature'] ?? 0.3);
        $this->maxTokens = (int) ($config['max_tokens'] ?? 2000);
    }

    public function decideNextScanner(ScanContext $context): string
    {
        if (empty($this->apiKey)) {
            return $this->fallbackDecision($context);
        }

        try {
            $response = Http::withToken($this->apiKey)
                ->timeout(30)
                ->post('https://api.openai.com/v1/chat/completions', [
                    'model' => $this->model,
                    'temperature' => $this->temperature,
                    'max_tokens' => $this->maxTokens,
                    'messages' => [
                        ['role' => 'system', 'content' => $this->getSystemPrompt()],
                        ['role' => 'user', 'content' => $this->buildPrompt($context)],
                    ],
                ]);

            $result = $response->json();
            $decision = trim($result['choices'][0]['message']['content'] ?? '');
            Log::info('OpenAI AI decision received', ['decision' => $decision]);
            return $decision;
        } catch (\Throwable $e) {
            Log::warning('OpenAI AI provider failed, using fallback', ['error' => $e->getMessage()]);
            return $this->fallbackDecision($context);
        }
    }

    public function analyzeResults(array $results, array $reasoningChain): string
    {
        if (empty($this->apiKey)) {
            return $this->fallbackAnalysis($results);
        }

        try {
            $response = Http::withToken($this->apiKey)
                ->timeout(60)
                ->post('https://api.openai.com/v1/chat/completions', [
                    'model' => $this->model,
                    'temperature' => 0.4,
                    'max_tokens' => 3000,
                    'messages' => [
                        ['role' => 'system', 'content' => $this->getAnalysisSystemPrompt()],
                        ['role' => 'user', 'content' => $this->buildAnalysisPrompt($results, $reasoningChain)],
                    ],
                ]);

            $result = $response->json();
            return trim($result['choices'][0]['message']['content'] ?? $this->fallbackAnalysis($results));
        } catch (\Throwable $e) {
            Log::warning('OpenAI analysis failed', ['error' => $e->getMessage()]);
            return $this->fallbackAnalysis($results);
        }
    }

    public function shouldStop(array $completedScanners, array $results): bool
    {
        if (empty($this->apiKey)) {
            return $this->fallbackShouldStop($completedScanners, $results);
        }

        try {
            $response = Http::withToken($this->apiKey)
                ->timeout(15)
                ->post('https://api.openai.com/v1/chat/completions', [
                    'model' => 'gpt-3.5-turbo',
                    'temperature' => 0.1,
                    'max_tokens' => 50,
                    'messages' => [
                        ['role' => 'system', 'content' => 'You are a security scan planner. Return STOP if no valuable scanning remains, CONTINUE if more scanning could provide value. Consider: new findings, uncovered categories, potential high-value targets.'],
                        ['role' => 'user', 'content' => json_encode([
                            'completed_scanners' => $completedScanners,
                            'findings_summary' => $this->summarizeResults($results),
                        ])],
                    ],
                ]);

            $result = $response->json();
            $decision = strtoupper(trim($result['choices'][0]['message']['content'] ?? 'STOP'));
            return $decision !== 'CONTINUE';
        } catch (\Throwable) {
            return $this->fallbackShouldStop($completedScanners, $results);
        }
    }

    private function getSystemPrompt(): string
    {
        return <<<PROMPT
You are an intelligent security assessment planner. Your role is to decide which scanner to run next based on target analysis, technologies detected, open ports, and previous results.

AVAILABLE SCANNERS - organized by category and purpose:

=== RECONNAISSANCE ===
- port_scanner: Basic TCP port scan (29 common ports)
- nmap: Advanced port scan with service version detection (top 1000 ports)
- dns_enumerator: PHP-based DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
- dnsrecon: Advanced DNS enumeration with zone transfer detection
- subdomain_enumerator: Basic subdomain brute-force via gethostbyname
- subfinder: Passive subdomain enumeration from multiple public sources
- amass: Comprehensive subdomain discovery and network mapping
- theharvester: OSINT gathering (emails, hosts from public sources)
- whois_lookup: WHOIS domain registration information

=== TECHNOLOGY DETECTION ===
- technology_detector: PHP-based tech fingerprinting (headers + body patterns)
- whatweb: Advanced web technology fingerprinting and version detection
- httpx: HTTP probing with tech detection and status code discovery

=== WEB DISCOVERY ===
- http_analyzer: HTTP security header and response analysis
- security_headers: Detailed security header audit (HSTS, CSP, XFO, XCTO, RP, PP, cookies)
- directory_brute_forcer: Common web directory/file enumeration (30+ paths)
- dirsearch: Extensive directory and file brute-forcing
- ffuf: Fast web fuzzer for content and parameter discovery
- katana: Web crawler for endpoint discovery
- hakrawler: JavaScript analysis, form discovery, and endpoint crawling
- gau: Get All URLs - known URLs from public archives
- waybackurls: Historical URLs from Wayback Machine

=== API ASSESSMENT ===
- api_assessment: API endpoint discovery, OpenAPI/Swagger analysis, JWT inspection, CORS checks

=== VULNERABILITY ASSESSMENT ===
- ssl_scanner: Basic SSL/TLS certificate analysis (PHP-based)
- sslscan: SSL/TLS cipher and protocol strength scanner
- testssl: Comprehensive SSL/TLS security assessment
- nuclei: Fast vulnerability scanning using YAML templates (1000s of templates)
- nikto: Web server vulnerability and misconfiguration scanner
- wapiti: Web application vulnerability scanner (XSS, SQLi, file inclusion, etc.)

=== SPECIALIZED ASSESSMENT ===
- xss_assessment: Authorized XSS detection (reflected, stored, DOM-based, input validation)
- sqli_assessment: Authorized SQL injection detection (error-based, time-based, boolean-based)

SCANNER WORKFLOW RULES:
1. Start with reconnaissance (port_scanner or nmap) to discover attack surface
2. Run technology detection (technology_detector, whatweb, httpx) after ports are known
3. If HTTP/HTTPS ports found, run web discovery scanners (http_analyzer, security_headers, directory_brute_forcer, dirsearch)
4. Run subdomain discovery if the target is a domain (subfinder, amass, dnsrecon)
5. Run vulnerability scanners only after understanding the target (nuclei, nikto, wapiti)
6. Run specialized assessment (xss_assessment, sqli_assessment) only if web app technologies are detected
7. Run API assessment if API endpoints or patterns are found
8. Run SSL scanners only if ports 443/8443 are open
9. NEVER suggest a scanner that has already been completed
10. Respect scanner dependencies (ssl_scanner needs port_scanner, etc.)
11. Return "STOP" when no valuable scanner remains

Return only one scanner name or "STOP".
PROMPT;
    }

    private function getAnalysisSystemPrompt(): string
    {
        return <<<PROMPT
You are a professional penetration tester writing a security assessment report. Analyze the scan findings and provide:

1. EXECUTIVE SUMMARY: Brief overview for management (2-3 sentences)
2. TECHNICAL SUMMARY: Detailed technical findings (3-5 sentences)
3. KEY FINDINGS: List of critical and high-severity issues
4. RISK ANALYSIS: Assessment of overall risk level
5. RECOMMENDATIONS: Prioritized remediation steps
6. TECHNOLOGY-SPECIFIC ADVICE: Security recommendations based on detected technologies

Be specific, professional, and actionable. Focus on helping the development team remediate issues.
PROMPT;
    }

    private function buildPrompt(ScanContext $context): string
    {
        $data = $context->toArray();
        $target = $data['target'];
        $completed = implode(', ', $data['completed_scanners']);
        $results = json_encode($data['results_summary'] ?? [], JSON_PRETTY_PRINT);
        $reasoning = implode("\n", array_map(fn($r) => "- {$r}", $data['reasoning_history']));

        return "Target: {$target}\nCompleted scanners: [{$completed}]\n\nResults summary:\n{$results}\n\nReasoning history:\n{$reasoning}\n\nWhat scanner should run next? Return only the scanner name or STOP.";
    }

    private function buildAnalysisPrompt(array $results, array $reasoningChain): string
    {
        $summary = [];
        foreach ($results as $scanner => $findings) {
            $count = count($findings);
            $severities = [];
            foreach ($findings as $f) {
                $sev = $f['severity'] ?? 'info';
                $severities[$sev] = ($severities[$sev] ?? 0) + 1;
            }
            $summary[] = "- {$scanner}: {$count} findings (" . json_encode($severities) . ")";
        }

        return "Scan Findings:\n" . implode("\n", $summary) . "\n\nReasoning Chain:\n" . json_encode($reasoningChain) . "\n\nProvide a comprehensive security assessment analysis.";
    }

    private function summarizeResults(array $results): array
    {
        $summary = [];
        foreach ($results as $scanner => $findings) {
            $severityCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
            foreach ($findings as $f) {
                $sev = $f['severity'] ?? 'info';
                $severityCounts[$sev] = ($severityCounts[$sev] ?? 0) + 1;
            }
            $summary[$scanner] = $severityCounts;
        }
        return $summary;
    }

    private function fallbackDecision(ScanContext $context): string
    {
        $registry = app(\App\Scanners\Registry\ScannerRegistry::class);
        $data = $context->toArray();

        $priorityOrder = [
            'port_scanner', 'nmap',
            'dns_enumerator', 'dnsrecon', 'subdomain_enumerator', 'subfinder', 'amass',
            'technology_detector', 'whatweb', 'httpx',
            'http_analyzer', 'security_headers',
            'directory_brute_forcer', 'dirsearch', 'ffuf', 'katana', 'hakrawler',
            'gau', 'waybackurls',
            'whois_lookup', 'theharvester',
            'api_assessment',
            'ssl_scanner', 'sslscan', 'testssl',
            'nuclei', 'nikto', 'wapiti',
            'xss_assessment', 'sqli_assessment',
        ];

        foreach ($priorityOrder as $priority) {
            if (!in_array($priority, $context->completedScanners)) {
                try {
                    $scanner = $registry->get($priority);
                    $deps = $scanner->dependencies();
                    $depsMet = true;
                    foreach ($deps as $dep) {
                        if (!in_array($dep, $context->completedScanners)) {
                            $depsMet = false;
                            break;
                        }
                    }
                    if ($depsMet) {
                        return $priority;
                    }
                } catch (\Throwable) {
                    continue;
                }
            }
        }

        return 'STOP';
    }

    private function fallbackAnalysis(array $results): string
    {
        $total = 0;
        $severityCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
        $scanners = [];

        foreach ($results as $scanner => $findings) {
            $scanners[] = $scanner;
            foreach ($findings as $f) {
                $total++;
                $sev = $f['severity'] ?? 'info';
                $severityCounts[$sev] = ($severityCounts[$sev] ?? 0) + 1;
            }
        }

        $text = "Security assessment completed using " . count($scanners) . " scanner(s): " . implode(', ', $scanners) . ". ";
        $text .= "A total of {$total} finding(s) were identified: {$severityCounts['critical']} critical, {$severityCounts['high']} high, {$severityCounts['medium']} medium, {$severityCounts['low']} low, and {$severityCounts['info']} informational. ";

        if ($severityCounts['critical'] > 0 || $severityCounts['high'] > 0) {
            $text .= "Immediate remediation is recommended for critical and high-severity issues. ";
        } else {
            $text .= "No critical or high-severity issues were identified. Continue regular security monitoring. ";
        }

        $text .= "Priority should be given to addressing identified vulnerabilities based on their severity and potential business impact. ";
        $text .= "Remediation steps include applying security patches, hardening configurations, implementing security headers, and following secure coding practices.";

        return $text;
    }

    private function fallbackShouldStop(array $completedScanners, array $results): bool
    {
        $highValue = 0;
        foreach ($results as $findings) {
            foreach ($findings as $finding) {
                if (in_array($finding['severity'] ?? '', ['high', 'critical'])) {
                    $highValue++;
                }
            }
        }
        return $highValue === 0 && count($completedScanners) >= 4;
    }
}
