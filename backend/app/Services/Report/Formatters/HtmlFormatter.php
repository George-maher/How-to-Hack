<?php

namespace App\Services\Report\Formatters;

class HtmlFormatter implements ReportFormatterInterface
{
    public function format(array $data): string
    {
        $execSummary = !empty($data['executive_summary'])
            ? "<section><h2>Executive Summary</h2><p>{$this->escape($data['executive_summary'])}</p></section>"
            : '';

        $techSummary = !empty($data['technical_summary'])
            ? "<section><h2>Technical Summary</h2><p>{$this->escape($data['technical_summary'])}</p></section>"
            : '';

        $targetInfo = '';
        if (!empty($data['target_info'])) {
            $rows = '';
            foreach ($data['target_info'] as $key => $value) {
                $rows .= "<tr><td>{$this->escape($key)}</td><td>{$this->escape($value)}</td></tr>";
            }
            $targetInfo = "<section><h2>Target Information</h2><table>{$rows}</table></section>";
        }

        $timeline = '';
        if (!empty($data['scan_timeline'])) {
            $rows = '';
            foreach ($data['scan_timeline'] as $entry) {
                $rows .= "<tr><td>{$this->escape($entry['label'])}</td><td>{$this->escape($entry['value'])}</td></tr>";
            }
            $timeline = "<section><h2>Scan Timeline</h2><table>{$rows}</table></section>";
        }

        $techs = !empty($data['technologies'])
            ? '<section><h2>Technologies Detected</h2><ul>' . implode('', array_map(fn($t) => "<li>{$this->escape($t)}</li>", $data['technologies'])) . '</ul></section>'
            : '';

        $ports = '';
        if (!empty($data['open_ports'])) {
            $rows = '';
            foreach ($data['open_ports'] as $p) {
                $rows .= "<tr><td>{$p['port']}</td><td>{$p['service']}</td><td class=\"{$p['severity']}\">{$p['severity']}</td></tr>";
            }
            $ports = "<section><h2>Open Ports</h2><table><tr><th>Port</th><th>Service</th><th>Severity</th></tr>{$rows}</table></section>";
        }

        $endpoints = !empty($data['endpoints'])
            ? '<section><h2>HTTP 200 Endpoints</h2><ul>' . implode('', array_map(fn($e) => "<li><code>{$this->escape($e)}</code></li>", $data['endpoints'])) . '</ul></section>'
            : '';

        $vulns = '';
        if (!empty($data['vulnerabilities'])) {
            $rows = '';
            foreach ($data['vulnerabilities'] as $v) {
                $rows .= "<tr><td class=\"{$v['severity']}\">{$v['severity']}</td><td>{$this->escape($v['title'])}</td><td>{$this->escape($v['description'])}</td></tr>";
            }
            $vulns = "<section><h2>Vulnerabilities Found</h2><table><tr><th>Severity</th><th>Title</th><th>Description</th></tr>{$rows}</table></section>";
        }

        $risk = '';
        if (!empty($data['risk_score'])) {
            $level = $data['risk_score']['level'];
            $score = $data['risk_score']['score'];
            $risk = "<section><h2>Risk Score</h2><div class=\"risk-indicator {$level}\"><strong>{$level}</strong> ({$score}/10)</div></section>";
        }

        $severitySection = '';
        if (!empty($data['severity_levels'])) {
            $max = max($data['severity_levels']) ?: 1;
            $bars = '';
            foreach ($data['severity_levels'] as $sev => $count) {
                $pct = ($count / $max) * 100;
                $bars .= "<div class=\"sev-row\"><span class=\"sev-label\">{$sev}</span><div class=\"sev-track\"><div class=\"sev-bar sev-{$sev}\" style=\"width:{$pct}%\"></div></div><span>{$count}</span></div>";
            }
            $severitySection = "<section><h2>Severity Levels</h2><div class=\"severity-bars\">{$bars}</div></section>";
        }

        $aiAnalysis = !empty($data['ai_analysis'])
            ? "<section><h2>AI Analysis</h2><div class=\"ai-content\">{$this->escape($data['ai_analysis'])}</div></section>"
            : '';

        $recs = !empty($data['recommendations'])
            ? '<section><h2>Recommendations</h2><ul>' . implode('', array_map(fn($r) => "<li>{$this->escape($r)}</li>", $data['recommendations'])) . '</ul></section>'
            : '';

        $mitigation = !empty($data['mitigation_steps'])
            ? '<section><h2>Mitigation Steps</h2><ol>' . implode('', array_map(fn($s) => "<li>{$this->escape($s)}</li>", $data['mitigation_steps'])) . '</ol></section>'
            : '';

        $xssSection = '';
        if (!empty($data['xss_findings'])) {
            $rows = '';
            foreach ($data['xss_findings'] as $xss) {
                $sev = $xss['severity'] ?? 'info';
                $rows .= "<tr><td class=\"{$sev}\">{$sev}</td><td>{$this->escape($xss['title'])}</td><td>{$this->escape($xss['description'])}</td><td>{$this->escape($xss['affected_endpoint'])}</td></tr>";
            }
            $xssSection = "<section><h2>XSS Findings</h2><p>Cross-Site Scripting (XSS) assessment identified potential issues that require investigation and remediation.</p><table><tr><th>Severity</th><th>Title</th><th>Description</th><th>Affected Endpoint</th></tr>{$rows}</table></section>";
        }

        $sqliSection = '';
        if (!empty($data['sqli_findings'])) {
            $rows = '';
            foreach ($data['sqli_findings'] as $sqli) {
                $sev = $sqli['severity'] ?? 'info';
                $rows .= "<tr><td class=\"{$sev}\">{$sev}</td><td>{$this->escape($sqli['title'])}</td><td>{$this->escape($sqli['description'])}</td><td>{$this->escape($sqli['affected_endpoint'])}</td></tr>";
            }
            $sqliSection = "<section><h2>SQL Injection Findings</h2><p>SQL Injection assessment identified potential vulnerabilities that require immediate investigation.</p><table><tr><th>Severity</th><th>Title</th><th>Description</th><th>Affected Endpoint</th></tr>{$rows}</table></section>";
        }

        $apiSection = '';
        if (!empty($data['api_findings'])) {
            $rows = '';
            foreach ($data['api_findings'] as $api) {
                $sev = $api['severity'] ?? 'info';
                $rows .= "<tr><td class=\"{$sev}\">{$sev}</td><td>{$this->escape($api['title'])}</td><td>{$this->escape($api['description'])}</td></tr>";
            }
            $apiSection = "<section><h2>API Assessment Findings</h2><table><tr><th>Severity</th><th>Title</th><th>Description</th></tr>{$rows}</table></section>";
        }

        $secHeadersSection = '';
        if (!empty($data['security_header_findings'])) {
            $rows = '';
            foreach ($data['security_header_findings'] as $sh) {
                $sev = $sh['severity'] ?? 'info';
                $rows .= "<tr><td class=\"{$sev}\">{$sev}</td><td>{$this->escape($sh['title'])}</td><td>{$this->escape($sh['description'])}</td></tr>";
            }
            $secHeadersSection = "<section><h2>Security Header Analysis</h2><p>Analysis of HTTP security headers reveals configuration issues that should be addressed.</p><table><tr><th>Severity</th><th>Title</th><th>Description</th></tr>{$rows}</table></section>";
        }

        $stats = '';
        if (!empty($data['scan_statistics'])) {
            $rows = '';
            foreach ($data['scan_statistics'] as $key => $value) {
                $rows .= "<tr><td>{$this->escape($key)}</td><td>{$this->escape((string)$value)}</td></tr>";
            }
            $stats = "<section><h2>Scan Statistics</h2><table>{$rows}</table></section>";
        }

        $scannerHistory = !empty($data['scanner_execution_history'])
            ? '<section><h2>Scanner Execution History</h2><ul>' . implode('', array_map(fn($e) => "<li>{$this->escape($e)}</li>", $data['scanner_execution_history'])) . '</ul></section>'
            : '';

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{$this->escape($data['title'])}</title>
<style>
body {
  font-family: 'Georgia', 'Times New Roman', Times, serif;
  line-height: 1.7;
  color: #1a1a1a;
  background: #ffffff;
  max-width: 800px;
  margin: 0 auto;
  padding: 2.5rem 2rem;
  font-size: 11pt;
}
h1 {
  font-family: 'Helvetica Neue', 'Arial', sans-serif;
  font-size: 22pt;
  color: #1a1a1a;
  border-bottom: 2px solid #1a1a1a;
  padding-bottom: 0.4rem;
  margin-bottom: 0.3rem;
  font-weight: 700;
  letter-spacing: -0.3px;
}
h2 {
  font-family: 'Helvetica Neue', 'Arial', sans-serif;
  font-size: 14pt;
  color: #2c3e50;
  margin-top: 1.8rem;
  margin-bottom: 0.6rem;
  padding-bottom: 0.25rem;
  border-bottom: 1px solid #d0d0d0;
  font-weight: 600;
}
section { margin: 1.2rem 0; }
p { margin: 0.6rem 0; text-align: justify; }
table {
  width: 100%;
  border-collapse: collapse;
  margin: 0.8rem 0;
  font-size: 10.5pt;
  font-family: 'Helvetica Neue', 'Arial', sans-serif;
}
th, td {
  padding: 0.45rem 0.6rem;
  text-align: left;
  border-bottom: 1px solid #d0d0d0;
}
th {
  background: #f5f5f5;
  color: #1a1a1a;
  font-weight: 600;
}
tr:last-child td { border-bottom: none; }
ul, ol { margin-left: 1.5rem; }
li { margin: 0.25rem 0; }
code {
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  background: #f5f5f5;
  padding: 0.1rem 0.3rem;
  font-size: 10pt;
  color: #2c3e50;
  border-radius: 2px;
}
.meta {
  font-family: 'Helvetica Neue', 'Arial', sans-serif;
  color: #666;
  font-size: 9.5pt;
  margin: 0.8rem 0 1.5rem 0;
  line-height: 1.6;
  border-bottom: 1px solid #e0e0e0;
  padding-bottom: 1rem;
}
.critical { color: #c0392b; font-weight: 600; }
.high { color: #d35400; font-weight: 600; }
.medium { color: #b7950b; font-weight: 600; }
.low { color: #2980b9; }
.info { color: #27ae60; }
.risk-indicator {
  padding: 0.8rem 1rem;
  text-align: center;
  font-family: 'Helvetica Neue', 'Arial', sans-serif;
  font-size: 13pt;
  margin: 1rem 0;
  border-radius: 4px;
  font-weight: 600;
}
.risk-indicator.critical { background: #fdeaea; color: #c0392b; border: 1px solid #c0392b; }
.risk-indicator.high { background: #fef5e7; color: #d35400; border: 1px solid #d35400; }
.risk-indicator.medium { background: #fef9e7; color: #b7950b; border: 1px solid #b7950b; }
.risk-indicator.low { background: #eaf2f8; color: #2980b9; border: 1px solid #2980b9; }
.ai-content {
  background: #f9f9f9;
  padding: 1rem 1.25rem;
  border-left: 3px solid #2c3e50;
  margin: 0.8rem 0;
  white-space: pre-wrap;
  font-size: 10.5pt;
  line-height: 1.6;
  border-radius: 2px;
}
.severity-bars { margin: 0.6rem 0; font-family: 'Helvetica Neue', 'Arial', sans-serif; }
.sev-row { display: flex; align-items: center; gap: 0.5rem; margin: 0.25rem 0; font-size: 10pt; }
.sev-label { width: 70px; text-transform: capitalize; font-weight: 500; }
.sev-track { flex: 1; height: 20px; background: #e8e8e8; border-radius: 2px; overflow: hidden; }
.sev-bar { height: 100%; border-radius: 2px; }
.sev-critical { background: #c0392b; }
.sev-high { background: #d35400; }
.sev-medium { background: #b7950b; }
.sev-low { background: #2980b9; }
.sev-info { background: #27ae60; }
@media print {
  body { padding: 1.5cm; max-width: none; }
  h1 { border-bottom-color: #1a1a1a; }
  section { page-break-inside: avoid; }
}
</style>
</head>
<body>
<h1>{$this->escape($data['title'])}</h1>
<div class="meta">Generated: {$data['generated_at']} | Target: {$this->escape($data['target'])} | Status: {$data['status']}</div>
{$execSummary}
{$techSummary}
{$targetInfo}
{$timeline}
{$techs}
{$ports}
{$endpoints}
{$vulns}
{$xssSection}
{$sqliSection}
{$apiSection}
{$secHeadersSection}
{$risk}
{$severitySection}
{$aiAnalysis}
{$recs}
{$mitigation}
{$stats}
{$scannerHistory}
</body>
</html>
HTML;
    }

    public function getMimeType(): string
    {
        return 'text/html';
    }

    public function getExtension(): string
    {
        return 'html';
    }

    private function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}
