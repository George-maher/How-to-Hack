<?php

namespace App\Services\Report\Formatters;

class PdfFormatter implements ReportFormatterInterface
{
    public function format(array $data): string
    {
        $html = app(HtmlFormatter::class)->format($data);

        $stylesheet = <<<CSS
body {
  font-family: 'Georgia', 'Times New Roman', Times, serif;
  line-height: 1.7;
  color: #1a1a1a;
  font-size: 11pt;
  padding: 1.5cm;
}
h1 {
  font-family: 'Helvetica', 'Arial', sans-serif;
  font-size: 20pt;
  color: #1a1a1a;
  border-bottom: 2px solid #1a1a1a;
  padding-bottom: 6pt;
  margin-bottom: 0;
  font-weight: 700;
  letter-spacing: -0.3px;
}
h2 {
  font-family: 'Helvetica', 'Arial', sans-serif;
  font-size: 14pt;
  color: #2c3e50;
  margin-top: 18pt;
  margin-bottom: 8pt;
  padding-bottom: 3pt;
  border-bottom: 1px solid #d0d0d0;
  font-weight: 600;
}
p { margin: 6pt 0; text-align: justify; }
table {
  width: 100%;
  border-collapse: collapse;
  margin: 8pt 0;
  font-size: 10pt;
  font-family: 'Helvetica', 'Arial', sans-serif;
}
th, td { padding: 4pt 6pt; text-align: left; border-bottom: 1px solid #d0d0d0; }
th { background: #f5f5f5; color: #1a1a1a; font-weight: 600; }
tr:last-child td { border-bottom: none; }
ul, ol { margin-left: 18pt; }
li { margin: 2pt 0; }
code {
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  background: #f5f5f5;
  padding: 1pt 3pt;
  font-size: 10pt;
  color: #2c3e50;
  border-radius: 2pt;
}
.meta {
  font-family: 'Helvetica', 'Arial', sans-serif;
  color: #666;
  font-size: 9.5pt;
  margin: 8pt 0 16pt 0;
  line-height: 1.6;
}
.critical { color: #c0392b; font-weight: 600; }
.high { color: #d35400; font-weight: 600; }
.medium { color: #b7950b; font-weight: 600; }
.low { color: #2980b9; }
.info { color: #27ae60; }
.risk-indicator {
  padding: 8pt 10pt;
  text-align: center;
  font-family: 'Helvetica', 'Arial', sans-serif;
  font-size: 13pt;
  margin: 10pt 0;
  border-radius: 4pt;
  font-weight: 600;
}
.risk-indicator.critical { background: #fdeaea; color: #c0392b; border: 1px solid #c0392b; }
.risk-indicator.high { background: #fef5e7; color: #d35400; border: 1px solid #d35400; }
.risk-indicator.medium { background: #fef9e7; color: #b7950b; border: 1px solid #b7950b; }
.risk-indicator.low { background: #eaf2f8; color: #2980b9; border: 1px solid #2980b9; }
.ai-content {
  background: #f9f9f9;
  padding: 10pt 12pt;
  border-left: 3pt solid #2c3e50;
  margin: 8pt 0;
  white-space: pre-wrap;
  font-size: 10.5pt;
  line-height: 1.6;
  border-radius: 2pt;
}
.severity-bars { margin: 6pt 0; font-family: 'Helvetica', 'Arial', sans-serif; }
.sev-row { display: flex; align-items: center; gap: 6pt; margin: 2pt 0; font-size: 10pt; }
.sev-label { width: 70px; text-transform: capitalize; font-weight: 500; }
.sev-track { flex: 1; height: 18px; background: #e8e8e8; border-radius: 2pt; overflow: hidden; }
.sev-bar { height: 100%; border-radius: 2pt; }
.sev-critical { background: #c0392b; }
.sev-high { background: #d35400; }
.sev-medium { background: #b7950b; }
.sev-low { background: #2980b9; }
.sev-info { background: #27ae60; }
CSS;

        $styledHtml = str_replace('</head>', "<style>{$stylesheet}</style></head>", $html);

        if (!class_exists(\Dompdf\Dompdf::class)) {
            return $styledHtml;
        }

        $domPdf = new \Dompdf\Dompdf();
        $domPdf->loadHtml($styledHtml);
        $domPdf->setPaper('A4', 'portrait');
        $domPdf->render();
        return $domPdf->output();
    }

    public function getMimeType(): string
    {
        return 'application/pdf';
    }

    public function getExtension(): string
    {
        return 'pdf';
    }
}
