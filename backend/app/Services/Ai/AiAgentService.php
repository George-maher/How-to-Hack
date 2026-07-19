<?php

namespace App\Services\Ai;

use App\Contracts\AiProviderInterface;
use App\DTOs\ScanContext;
use App\Models\Scan;
use App\Scanners\Registry\ScannerRegistry;
use Illuminate\Support\Facades\Log;

class AiAgentService
{
    private AiProviderInterface $provider;
    private ReasoningChain $reasoningChain;

    public function __construct(
        private readonly ScannerRegistry $scannerRegistry,
    ) {
        $this->reasoningChain = new ReasoningChain();
        $this->provider = $this->resolveProvider();
    }

    public function decideNextScanner(Scan $scan, ScanContext $context): ?string
    {
        $decision = $this->provider->decideNextScanner($context);

        if ($decision === 'STOP' || $decision === '') {
            $this->logDecision($scan, 'STOP', 'No additional useful scanners identified');
            return null;
        }

        if ($this->isDuplicate($decision, $context)) {
            $this->logDecision($scan, $decision, 'Skipped: already executed');
            return null;
        }

        if (!$this->isValidScanner($decision)) {
            $this->logDecision($scan, $decision, 'Invalid scanner name, stopping');
            return null;
        }

        $reason = $this->buildReason($decision, $context);
        $this->logDecision($scan, $decision, $reason);
        $this->reasoningChain->add($decision, $reason, $this->buildDecisionContext($context));
        $scan->addReasoning("Decision: {$decision} - {$reason}");

        return $decision;
    }

    public function shouldStop(Scan $scan, array $completedScanners, array $results): bool
    {
        $shouldStop = $this->provider->shouldStop($completedScanners, $results);
        if ($shouldStop) {
            $stopReason = $this->buildStopReason($completedScanners, $results);
            $this->logDecision($scan, 'STOP', $stopReason);
            $this->reasoningChain->add('STOP', $stopReason);
            $scan->addReasoning("Decision: STOP - {$stopReason}");
        }
        return $shouldStop;
    }

    public function getReasoningChain(): ReasoningChain
    {
        return $this->reasoningChain;
    }

    private function resolveProvider(): AiProviderInterface
    {
        $provider = config('ai-agent.default_provider', 'openai');
        $class = match ($provider) {
            'claude' => \App\Services\Ai\Providers\ClaudeProvider::class,
            'openrouter' => \App\Services\Ai\Providers\OpenRouterProvider::class,
            default => \App\Services\Ai\Providers\OpenAiProvider::class,
        };
        return app($class);
    }

    private function isDuplicate(string $scannerName, ScanContext $context): bool
    {
        return in_array($scannerName, $context->completedScanners);
    }

    private function isValidScanner(string $name): bool
    {
        try {
            $this->scannerRegistry->get($name);
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private function buildReason(string $scannerName, ScanContext $context): string
    {
        $scanner = $this->scannerRegistry->get($scannerName);
        $category = $scanner->category();
        $description = $scanner->description();
        $completed = count($context->completedScanners);
        $total = $this->scannerRegistry->count();

        $contextSummary = $this->summarizeFindings($context);
        $specificReason = $this->getSpecificReason($scannerName, $context, $contextSummary);

        return sprintf(
            'Selected %s [%s] - %s. %s (completed: %d/%d scanners)',
            $scannerName,
            $category,
            $description,
            $specificReason,
            $completed,
            $total
        );
    }

    private function getSpecificReason(string $scannerName, ScanContext $context, string $summary): string
    {
        $reasons = [
            'port_scanner' => 'Initial port discovery to determine attack surface',
            'nmap' => 'Detailed port and service version detection',
            'dns_enumerator' => 'DNS reconnaissance to map target infrastructure',
            'dnsrecon' => 'Advanced DNS record enumeration',
            'subdomain_enumerator' => 'Basic subdomain discovery via DNS resolution',
            'subfinder' => 'Passive subdomain enumeration from public sources',
            'amass' => 'Comprehensive subdomain enumeration and network mapping',
            'theharvester' => 'OSINT gathering for emails and hosts',
            'http_analyzer' => 'HTTP security header and configuration analysis',
            'security_headers' => 'Detailed security header audit (HSTS, CSP, XFO, etc.)',
            'technology_detector' => 'Web technology fingerprinting',
            'whatweb' => 'Advanced web technology and version detection',
            'httpx' => 'HTTP probing and technology detection',
            'directory_brute_forcer' => 'Common web path enumeration',
            'dirsearch' => 'Extensive directory and file brute-forcing',
            'ffuf' => 'Fast web fuzzing for content discovery',
            'katana' => 'Web crawling for endpoint discovery',
            'hakrawler' => 'JavaScript analysis and form discovery',
            'gau' => 'Known URL gathering from public archives',
            'waybackurls' => 'Historical URL discovery from Wayback Machine',
            'ssl_scanner' => 'Basic SSL/TLS certificate analysis',
            'sslscan' => 'SSL/TLS cipher and protocol strength scanning',
            'testssl' => 'Comprehensive SSL/TLS security assessment',
            'whois_lookup' => 'WHOIS domain registration information gathering',
            'nuclei' => 'Template-based vulnerability scanning',
            'nikto' => 'Web server vulnerability and misconfiguration scanning',
            'wapiti' => 'Web application vulnerability scanning (XSS, SQLi, injections)',
            'api_assessment' => 'API endpoint discovery and security analysis',
            'xss_assessment' => 'Authorized XSS vulnerability assessment',
            'sqli_assessment' => 'Authorized SQL injection vulnerability assessment',
        ];

        return $reasons[$scannerName] ?? 'Scanner selected based on assessment requirements';
    }

    private function buildDecisionContext(ScanContext $context): array
    {
        return [
            'completed_count' => count($context->completedScanners),
            'total_available' => count($context->availableScanners),
            'findings_summary' => $this->summarizeFindings($context),
        ];
    }

    private function summarizeFindings(ScanContext $context): string
    {
        $results = $context->toArray()['results_summary'] ?? [];
        if (empty($results)) {
            return 'No findings yet';
        }

        $parts = [];
        foreach ($results as $scanner => $summary) {
            $counts = $summary['severity_breakdown'] ?? [];
            $parts[] = "{$scanner}: " . json_encode($counts);
        }
        return implode('; ', $parts);
    }

    private function buildStopReason(array $completedScanners, array $results): string
    {
        $highValue = 0;
        foreach ($results as $findings) {
            foreach ($findings as $finding) {
                $severity = $finding['severity'] ?? 'info';
                if (in_array($severity, ['high', 'critical'])) {
                    $highValue++;
                }
            }
        }

        $reason = sprintf(
            'Scan complete. Executed %d scanner(s), identified %d high/critical finding(s).',
            count($completedScanners),
            $highValue
        );

        if ($highValue === 0 && count($completedScanners) >= 4) {
            $reason .= ' No high-value findings detected after sufficient scanning coverage.';
        } elseif ($highValue > 0) {
            $reason .= ' Sufficient findings collected for comprehensive reporting.';
        }

        return $reason;
    }

    private function logDecision(Scan $scan, string $decision, string $reason): void
    {
        Log::info('AI Agent Decision', [
            'scan_id' => $scan->id,
            'project_id' => $scan->project_id,
            'decision' => $decision,
            'reason' => $reason,
        ]);
    }

    public function switchProvider(string $provider): void
    {
        $this->provider = match ($provider) {
            'claude' => app(\App\Services\Ai\Providers\ClaudeProvider::class),
            'openrouter' => app(\App\Services\Ai\Providers\OpenRouterProvider::class),
            default => app(\App\Services\Ai\Providers\OpenAiProvider::class),
        };
    }
}
