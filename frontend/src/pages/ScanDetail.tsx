import { useEffect, useState, useRef, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { reportsApi, scansApi } from '../services/api';
import type { Report, Scan, ScanResult, SeverityLevel } from '../types';

const SEVERITY_ORDER: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'info'];

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'all'>('all');
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadData = useCallback(async () => {
    try {
      const scanId = Number(id);
      const [scanData, resultsData, reportsData] = await Promise.all([
        scansApi.get(scanId),
        scansApi.results(scanId),
        reportsApi.list(scanId).catch(() => [] as Report[]),
      ]);
      setReports(reportsData);
      setScan(scanData);
      setResults(resultsData);

      const terminal = ['completed', 'failed', 'cancelled'];
      if (terminal.includes(scanData.status) && pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    } catch (err: any) {
      setError(err.message);
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadData();

    pollingRef.current = setInterval(loadData, 5000);

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    };
  }, [loadData]);

  const filteredResults =
    severityFilter === 'all'
      ? results
      : results.filter((r) => r.severity === severityFilter);

  const groupedByScanner = filteredResults.reduce<
    Record<string, ScanResult[]>
  >((acc, result) => {
    if (!acc[result.scanner_name]) acc[result.scanner_name] = [];
    acc[result.scanner_name].push(result);
    return acc;
  }, {});

  if (loading) {
    return (
      <div className="scan-detail">
        <div className="scan-header">
          <div className="skeleton skeleton-text short" style={{ width: '100px' }} />
          <div className="skeleton skeleton-text" style={{ width: '200px' }} />
        </div>
        <div className="scan-info">
          <div className="skeleton skeleton-text" />
          <div className="skeleton skeleton-text" />
          <div className="skeleton skeleton-text" />
        </div>
        <div className="severity-chart">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="severity-bar-container">
              <div className="skeleton skeleton-text short" style={{ width: '70px' }} />
              <div className="skeleton" style={{ flex: 1, height: '24px' }} />
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (error) return <div className="error">{error}</div>;
  if (!scan) return <div className="error">Scan not found</div>;

  const severityCounts = SEVERITY_ORDER.map(
    (sev) => results.filter((r) => r.severity === sev).length
  );

  return (
    <div className="scan-detail">
      <div className="scan-header">
        <button onClick={() => navigate(-1)} className="btn-back">
          &larr; Back
        </button>
        <h1>Scan #{scan.id}</h1>
        <span className={`scan-badge-large scan-${scan.status}`}>{scan.status}</span>
      </div>

      <div className="scan-info">
        <div className="info-row">
          <strong>Project:</strong>{' '}
          <Link to={`/projects/${scan.project_id}`}>View Project</Link>
        </div>
        <div className="info-row">
          <strong>Status:</strong> {scan.status}
        </div>
        <div className="info-row">
          <strong>Started:</strong>{' '}
          {scan.started_at ? new Date(scan.started_at).toLocaleString() : 'N/A'}
        </div>
        <div className="info-row">
          <strong>Completed:</strong>{' '}
          {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'In progress'}
        </div>
        <div className="info-row">
          <strong>Scanners executed:</strong>{' '}
          {scan.completed_scanners?.length ?? 0}
        </div>
      </div>

      <div className="severity-chart">
        <h2>Findings by Severity</h2>
        <div className="severity-bars">
          {SEVERITY_ORDER.map((sev, i) => (
            <div key={sev} className="severity-bar-container">
              <span className="severity-label">{sev}</span>
              <div className="severity-bar-track">
                <div
                  className={`severity-bar severity-${sev}`}
                  style={{
                    width: `${Math.max(
                      (severityCounts[i] / Math.max(...severityCounts, 1)) * 100,
                      severityCounts[i] > 0 ? 10 : 0
                    )}%`,
                  }}
                />
              </div>
              <span className="severity-count">{severityCounts[i]}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="filter-bar">
        <h2>Results</h2>
        <div className="filter-group">
          <label>Severity:</label>
          <select
            value={severityFilter}
            onChange={(e) =>
              setSeverityFilter(e.target.value as SeverityLevel | 'all')
            }
          >
            <option value="all">All</option>
            {SEVERITY_ORDER.map((sev) => (
              <option key={sev} value={sev}>
                {sev.charAt(0).toUpperCase() + sev.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="results-scanner-groups">
        {Object.entries(groupedByScanner).map(([scannerName, scannerResults]) => (
          <div key={scannerName} className="scanner-group">
            <h3>{scannerName}</h3>
            {scannerResults.map((result) => (
              <ResultCard key={result.id} result={result} />
            ))}
          </div>
        ))}
        {filteredResults.length === 0 && (
          <p className="empty-state">No results match the filter</p>
        )}
      </div>

      {scan.ai_reasoning && scan.ai_reasoning.length > 0 && (
        <div className="reasoning-section">
          <h2>AI Reasoning Chain</h2>
          <ol className="reasoning-list">
            {scan.ai_reasoning.map((entry, i) => (
              <li key={i} className="reasoning-entry">
                <small>{entry.timestamp}</small>
                <p>{entry.message}</p>
              </li>
            ))}
          </ol>
        </div>
      )}

      <div className="reports-section">
        <h2>Reports</h2>
        {scan.status === 'completed' && reports.length === 0 && (
          <ReportActions scanId={scan.id} onGenerated={loadData} />
        )}
        {reports.length > 0 && (
          <div className="reports-list">
            {reports.map((report) => (
              <ReportCard key={report.id} report={report} />
            ))}
          </div>
        )}
        {scan.status !== 'completed' && reports.length === 0 && (
          <p className="empty-state">Reports available after scan completes</p>
        )}
      </div>
    </div>
  );
}

function ReportCard({ report }: { report: Report }) {
  return (
    <div className="report-card">
      <div className="report-card-header">
        <Link to={`/reports/${report.id}`} className="report-title">
          {report.title}
        </Link>
        <span className={`report-badge report-${report.status}`}>{report.status}</span>
      </div>
      <div className="report-meta-row">
        <span>Format: {report.format}</span>
        <span>{new Date(report.created_at).toLocaleString()}</span>
      </div>
      <div className="report-actions-row">
        <Link to={`/reports/${report.id}`} className="btn btn-sm btn-primary">
          View
        </Link>
        <a
          href={reportsApi.downloadUrl(report.id, report.format)}
          className="btn btn-sm btn-secondary"
          download
        >
          Download
        </a>
      </div>
    </div>
  );
}

function ReportActions({ scanId, onGenerated }: { scanId: number; onGenerated: () => void }) {
  const [format, setFormat] = useState('html');
  const [generating, setGenerating] = useState(false);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      await reportsApi.generate(scanId, format);
      onGenerated();
    } catch (err: any) {
      alert('Failed to generate report: ' + err.message);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="generate-report">
      <select value={format} onChange={(e) => setFormat(e.target.value)}>
        <option value="html">HTML</option>
        <option value="pdf">PDF</option>
        <option value="json">JSON</option>
        <option value="md">Markdown</option>
        <option value="txt">Plain Text</option>
      </select>
      <button onClick={handleGenerate} disabled={generating} className="btn btn-primary">
        {generating ? 'Generating...' : 'Generate Report'}
      </button>
    </div>
  );
}

function ResultCard({ result }: { result: ScanResult }) {
  return (
    <div className={`result-card severity-${result.severity}`}>
      <div className="result-header">
        <span className="result-severity">{result.severity}</span>
        <h4>{result.title}</h4>
      </div>
      <p className="result-description">{result.description}</p>
      {result.details && Object.keys(result.details).length > 0 && (
        <details className="result-details">
          <summary>Details</summary>
          <pre>{JSON.stringify(result.details, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}
