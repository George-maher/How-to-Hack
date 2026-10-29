<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerIntrusiveness;
use App\Enums\ScannerCategory;
use App\Models\Project;

class XssAssessmentScanner extends BaseScanner
{
    private array $xssPayloads = [
        'reflected' => [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '\'><img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
            '\';alert(1);//',
            '"><svg onload=alert(1)>',
        ],
        'stored' => [
            '<script>alert("stored")</script>',
            '<img src=x onerror=alert("stored")>',
        ],
    ];

    private array $parameterNames = [
        'q', 's', 'search', 'query', 'id', 'page', 'name', 'user',
        'username', 'email', 'comment', 'message', 'text', 'input',
        'url', 'redirect', 'return', 'next', 'file', 'dir', 'cmd',
        'exec', 'command', 'action', 'lang', 'theme', 'view', 'template',
    ];

    public function name(): string
    {
        return 'xss_assessment';
    }

    public function description(): string
    {
        return 'Authorized XSS vulnerability assessment - detects potential reflected and stored XSS issues';
    }

    public function category(): string
    {
        return ScannerCategory::SpecializedAssessment->value;
    }

    public function severity(): string
    {
        return 'high';
    }

    public function intrusiveness(): ScannerIntrusiveness
    {
        return ScannerIntrusiveness::Active;
    }
    /**
     * Sends script payloads, so it is an active scanner. It requires explicit operator approval.
     */

    protected function scan(Project $project, array $context): ScanResultCollection
    {
        $results = new ScanResultCollection();

        try {
            $baseUrl = rtrim($project->target_url, '/');

            $response = $this->http->guarded($this->timeout)
                ->withOptions(['allow_redirects' => true])
                ->get($baseUrl);

            $body = $response->body();
            $contentType = $response->header('Content-Type', '');

            $this->analyzeInputReflection($baseUrl, $results);
            $this->analyzeInputValidationWeaknesses($body, $results);
            $this->analyzeOutputEncoding($baseUrl, $response->headers(), $body, $results);
            $this->analyzeFormsAndParameters($body, $baseUrl, $results);

            if ($results->count() === 0) {
                $results->add($this->createResult(
                    'info',
                    'No XSS issues identified',
                    'Initial analysis did not identify obvious XSS vulnerabilities. Further manual testing is recommended.'
                ));
            }

        } catch (\Throwable $e) {
            $results->add($this->createResult(
                'info',
                'XSS assessment incomplete',
                "XSS assessment could not be completed: {$e->getMessage()}"
            ));
        }

        return $results;
    }

    private function analyzeInputReflection(string $baseUrl, ScanResultCollection $results): void
    {
        foreach ($this->parameterNames as $param) {
            foreach (array_slice($this->xssPayloads['reflected'], 0, 3) as $payload) {
                try {
                    $url = $baseUrl . '?' . http_build_query([$param => $payload]);
                    $response = $this->http->guarded(5)
                        ->withOptions(['allow_redirects' => false])
                        ->get($url);

                    $responseBody = $response->body();

                    if (str_contains($responseBody, $payload) || str_contains($responseBody, html_entity_decode($payload))) {
                        $severity = $this->determineXssSeverity($response, $payload);

                        $results->add($this->createResult(
                            $severity,
                            'Potential Reflected XSS',
                            "Parameter '{$param}' reflects input without proper sanitization",
                            [
                                'affected_endpoint' => $url,
                                'parameter' => $param,
                                'payload' => $payload,
                                'evidence' => substr($responseBody, 0, 500),
                                'type' => 'reflected',
                                'remediation' => 'Implement proper output encoding and input validation. Use Content-Security-Policy headers.',
                            ]
                        ));
                        break;
                    }
                } catch (\Throwable) {
                    continue;
                }
            }
        }
    }

    private function analyzeInputValidationWeaknesses(string $body, ScanResultCollection $results): void
    {
        if (preg_match_all('/<input[^>]*name=["\']([^"\']+)["\'][^>]*>/i', $body, $matches)) {
            $inputs = $matches[1];
            $findings = [];

            foreach ($inputs as $input) {
                if (!preg_match('/\b(maxlength|pattern|required)\b/i', $body)) {
                    $findings[] = $input;
                }
            }

            if (!empty($findings)) {
                $results->add($this->createResult(
                    'medium',
                    'Input validation weaknesses detected',
                    sprintf('Found %d input field(s) without adequate validation', count($findings)),
                    [
                        'affected_fields' => $findings,
                        'type' => 'input_validation',
                        'remediation' => 'Implement server-side validation with proper allow-listing. Use type-specific validation for all input fields.',
                    ]
                ));
            }
        }

        if (preg_match('/<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>/i', $body, $textareaMatches)) {
            $results->add($this->createResult(
                'high',
                'Textarea input found - potential stored XSS risk',
                'Textarea inputs that store and display user content are potential vectors for stored XSS',
                [
                    'affected_fields' => $textareaMatches[1],
                    'type' => 'stored_xss_risk',
                    'remediation' => 'Apply context-aware output encoding. Use DOMPurify for sanitizing HTML content. Implement Content-Security-Policy.',
                ]
            ));
        }
    }

    private function analyzeOutputEncoding(string $baseUrl, array $headers, string $body, ScanResultCollection $results): void
    {
        if (preg_match('/<\?=\s*\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*;/i', $body)) {
            $results->add($this->createResult(
                'medium',
                'Potential output encoding issues',
                'Short echo tags detected - may indicate unescaped output',
                [
                    'type' => 'output_encoding',
                    'remediation' => 'Use proper escaping functions (htmlspecialchars, htmlentities) for all user-controlled output.',
                ]
            ));
        }

        if (preg_match('/\.innerHTML\s*=|\.html\(\s*[^)]*\s*\)/i', $body)) {
            $results->add($this->createResult(
                'high',
                'Dangerous HTML injection patterns detected',
                'Use of innerHTML or .html() can lead to DOM-based XSS if unsanitized',
                [
                    'type' => 'dom_xss',
                    'remediation' => 'Use textContent/.text() instead of innerHTML/.html(). Sanitize with DOMPurify if HTML is required.',
                ]
            ));
        }

        $ct = strtolower(implode(', ', $headers['content-type'] ?? ['']));
        if (!str_contains($ct, 'charset=utf-8') && !str_contains($ct, 'charset=utf8')) {
            $results->add($this->createResult(
                'low',
                'Character encoding not explicitly set to UTF-8',
                'Missing charset=utf-8 in Content-Type may lead to encoding-based XSS attacks',
                [
                    'type' => 'encoding_xss',
                    'remediation' => 'Set charset=utf-8 in Content-Type header to prevent encoding-based attacks.',
                ]
            ));
        }
    }

    private function analyzeFormsAndParameters(string $body, string $baseUrl, ScanResultCollection $results): void
    {
        preg_match_all('/<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>/i', $body, $formMatches, PREG_SET_ORDER);
        preg_match_all('/<input[^>]*type=["\'](?:hidden|text|search)["\'][^>]*name=["\']([^"\']+)["\'][^>]*>/i', $body, $paramMatches);

        if (!empty($formMatches)) {
            $results->add($this->createResult(
                'low',
                'Forms detected for XSS testing',
                sprintf('Found %d form(s) and %d input parameter(s) for potential XSS assessment',
                    count($formMatches),
                    count($paramMatches[1] ?? [])
                ),
                [
                    'forms_found' => count($formMatches),
                    'parameters_found' => count($paramMatches[1] ?? []),
                    'type' => 'information',
                    'remediation' => 'Test all input fields with XSS payloads during manual assessment.',
                ]
            ));
        }
    }

    private function determineXssSeverity($response, string $payload): string
    {
        $body = $response->body();

        if (str_contains($body, '<script>' . $payload)) {
            return 'critical';
        }

        if (str_contains($body, $payload) && str_contains($body, '<script>')) {
            return 'high';
        }

        if (str_contains($body, $payload)) {
            return 'medium';
        }

        return 'low';
    }

    public function dependencies(): array
    {
        return ['http_analyzer'];
    }
}
