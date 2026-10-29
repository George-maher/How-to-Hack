<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Enums\ScannerIntrusiveness;
use App\Enums\ScannerCategory;
use App\Models\Project;

class SqlInjectionAssessmentScanner extends BaseScanner
{
    private array $sqliPayloads = [
        '\'',
        '\' OR \'1\'=\'1',
        '\' OR 1=1 --',
        '\' UNION SELECT NULL--',
        '\' UNION SELECT 1,2,3--',
        '\' AND 1=1--',
        '\' AND 1=2--',
        '\' WAITFOR DELAY \'0:0:5\'--',
        '\' OR SLEEP(5)--',
        '\' OR pg_sleep(5)--',
        '\' OR dbms_lock.sleep(5)--',
    ];

    private array $errorPatterns = [
        '/you have an error in your sql syntax/i',
        '/warning: mysql/i',
        '/unclosed quotation mark/i',
        '/sqlite_error/i',
        '/odbc drivers sql/i',
        '/microsoft ole db/i',
        '/postgresql.*error/i',
        '/psql.*error/i',
        '/ora-[0-9]{5}/i',
        '/plsql.*error/i',
        '/driver.*error/i',
        '/supplied argument is not a valid/i',
        '/column.*not found/i',
        '/table.*doesn\'t exist/i',
        '/division by zero.*sql/i',
        '/jdbc.*error/i',
        '/sqlcmd.*error/i',
        '/sqlite3/i',
        '/mysql_fetch/i',
        '/mysqli_error/i',
        '/pg_exec/i',
        '/db2.*error/i',
        '/mssql.*error/i',
    ];

    private array $parameterNames = [
        'id', 'cat', 'product', 'page', 'item', 'article',
        'news', 'blog', 'post', 'comment', 'user', 'username',
        'email', 'search', 'q', 's', 'sort', 'order', 'limit',
        'offset', 'group', 'lang', 'file', 'download', 'img',
        'image', 'photo', 'gallery', 'album', 'video',
    ];

    private array $sqliTimePatterns = [
        '\' OR SLEEP(5)--',
        '\' OR pg_sleep(5)--',
        '\' WAITFOR DELAY \'0:0:5\'--',
    ];

    public function name(): string
    {
        return 'sqli_assessment';
    }

    public function description(): string
    {
        return 'Authorized SQL Injection vulnerability assessment';
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
     * Sends injection payloads, so it is an active scanner. It requires explicit operator approval.
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

            $this->analyzeErrorBasedInjection($baseUrl, $results);
            $this->analyzeTimeBasedInjection($baseUrl, $results);
            $this->analyzeInsecureInputHandling($body, $results);
            $this->analyzeBooleanBasedInjection($baseUrl, $results);

            if ($results->count() === 0) {
                $results->add($this->createResult(
                    'info',
                    'No SQL Injection issues automatically detected',
                    'Automated SQL injection assessment did not identify clear vulnerabilities. Manual testing with authenticated access is recommended for comprehensive assessment.'
                ));
            }

        } catch (\Throwable $e) {
            $results->add($this->createResult(
                'info',
                'SQL Injection assessment incomplete',
                "SQL Injection assessment could not be completed: {$e->getMessage()}"
            ));
        }

        return $results;
    }

    private function analyzeErrorBasedInjection(string $baseUrl, ScanResultCollection $results): void
    {
        foreach ($this->parameterNames as $param) {
            foreach ($this->sqliPayloads as $payload) {
                try {
                    $url = $baseUrl . '?' . http_build_query([$param => $payload]);
                    $response = $this->http->guarded(5)
                        ->withOptions(['allow_redirects' => false])
                        ->get($url);

                    $responseBody = $response->body();

                    foreach ($this->errorPatterns as $pattern) {
                        if (preg_match($pattern, $responseBody)) {
                            $results->add($this->createResult(
                                'critical',
                                'Potential SQL Injection (Error-based)',
                                "Parameter '{$param}' appears vulnerable to error-based SQL injection with payload: {$payload}",
                                [
                                    'affected_endpoint' => $url,
                                    'parameter' => $param,
                                    'payload' => $payload,
                                    'type' => 'error_based',
                                    'remediation' => 'Use parameterized queries or prepared statements. Avoid dynamic SQL string concatenation. Implement input validation with allow-listing.',
                                ]
                            ));
                            break 2;
                        }
                    }
                } catch (\Throwable) {
                    continue;
                }
            }
        }
    }

    private function analyzeTimeBasedInjection(string $baseUrl, ScanResultCollection $results): void
    {
        foreach ($this->parameterNames as $param) {
            $baselineTime = null;

            try {
                $start = microtime(true);
                $this->http->guarded(10)
                    ->withOptions(['allow_redirects' => false])
                    ->get($baseUrl);
                $baselineTime = (microtime(true) - $start) * 1000;
            } catch (\Throwable) {
                continue;
            }

            foreach ($this->sqliTimePatterns as $payload) {
                try {
                    $url = $baseUrl . '?' . http_build_query([$param => $payload]);
                    $start = microtime(true);
                    $this->http->guarded(15)
                        ->withOptions(['allow_redirects' => false])
                        ->get($url);
                    $responseTime = (microtime(true) - $start) * 1000;

                    if ($baselineTime !== null && $responseTime > ($baselineTime + 3000)) {
                        $results->add($this->createResult(
                            'critical',
                            'Potential SQL Injection (Time-based)',
                            "Parameter '{$param}' may be vulnerable to time-based SQL injection. Response time increased from {$baselineTime}ms to {$responseTime}ms",
                            [
                                'affected_endpoint' => $url,
                                'parameter' => $param,
                                'payload' => $payload,
                                'baseline_time_ms' => round($baselineTime, 2),
                                'response_time_ms' => round($responseTime, 2),
                                'type' => 'time_based',
                                'remediation' => 'Use parameterized queries. Implement query timeout controls. Apply Web Application Firewall (WAF) rules.',
                            ]
                        ));
                        break 2;
                    }
                } catch (\Throwable) {
                    continue;
                }
            }
        }
    }

    private function analyzeBooleanBasedInjection(string $baseUrl, ScanResultCollection $results): void
    {
        foreach ($this->parameterNames as $param) {
            $truePayload = "' AND 1=1--";
            $falsePayload = "' AND 1=2--";

            try {
                $trueUrl = $baseUrl . '?' . http_build_query([$param => $truePayload]);
                $falseUrl = $baseUrl . '?' . http_build_query([$param => $falsePayload]);

                $trueResponse = $this->http->guarded(5)
                    ->withOptions(['allow_redirects' => false])
                    ->get($trueUrl);

                $falseResponse = $this->http->guarded(5)
                    ->withOptions(['allow_redirects' => false])
                    ->get($falseUrl);

                $trueLength = strlen($trueResponse->body());
                $falseLength = strlen($falseResponse->body());

                if (abs($trueLength - $falseLength) > 50) {
                    $results->add($this->createResult(
                        'high',
                        'Potential SQL Injection (Boolean-based)',
                        "Parameter '{$param}' shows different responses for TRUE/FALSE conditions (diff: " . abs($trueLength - $falseLength) . " bytes)",
                        [
                            'affected_parameter' => $param,
                            'true_response_length' => $trueLength,
                            'false_response_length' => $falseLength,
                            'type' => 'boolean_based',
                            'remediation' => 'Use parameterized queries. Ensure consistent error responses regardless of query success/failure. Implement generic error messages.',
                        ]
                    ));
                }
            } catch (\Throwable) {
                continue;
            }
        }
    }

    private function analyzeInsecureInputHandling(string $body, ScanResultCollection $results): void
    {
        if (preg_match('/\$_(GET|POST|REQUEST|COOKIE)\s*\[/i', $body)) {
            $results->add($this->createResult(
                'medium',
                'Direct superglobal access detected',
                'Code directly accesses superglobals (\$_GET, \$_POST, etc.) which may bypass input filtering',
                [
                    'type' => 'insecure_input_handling',
                    'remediation' => 'Use framework input handling (Request::input(), validate(), etc.) instead of direct superglobal access.',
                ]
            ));
        }

        if (preg_match('/mysql_query|mysqli_query|pg_query|sqlite_query|db_query/i', $body)) {
            $results->add($this->createResult(
                'high',
                'Deprecated database query patterns detected',
                'Direct database query functions detected - may indicate SQL injection vulnerable code',
                [
                    'type' => 'insecure_db_pattern',
                    'remediation' => 'Migrate to parameterized queries using PDO or an ORM/query builder. Never concatenate user input into SQL strings.',
                ]
            ));
        }

        if (preg_match('/LIMIT\s+\d+,\s*\d+|OFFSET\s+\d+|ORDER\s+BY\s+\w+/i', $body)) {
            $results->add($this->createResult(
                'low',
                'SQL query patterns detected in source',
                'SQL-like patterns found in response body - may indicate exposed query logic',
                [
                    'type' => 'information_leakage',
                    'remediation' => 'Avoid exposing SQL logic in responses. Use consistent error handling that does not reveal query structure.',
                ]
            ));
        }
    }

    public function dependencies(): array
    {
        return ['http_analyzer', 'technology_detector'];
    }
}
