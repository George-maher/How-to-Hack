import { useEffect, useState, useRef, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ApiError, reportsApi, scansApi } from '../services/api';
import DownloadButton from '../components/DownloadButton';
import type { Report, Scan, ScanResult, SeverityLevel } from '../types';
import { IN_FLIGHT_STATUSES, SCAN_STATUS_LABELS } from '../types';

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
  const [cancelling, setCancelling] = useState(false);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

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
      setError(null);

      // The server decides when a scan is finished; the UI may not guess.
      if (!IN_FLIGHT_STATUSES.includes(scanData.status)) {
        stopPolling();
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'The scan could not be loaded.');
      stopPolling();
    } finally {
      setLoading(false);
    }
  }, [id, stopPolling]);

  useEffect(() => {
    let cancelled = false;

    const tick = async () => {
      if (cancelled) return;
      await loadData();
    };

    void tick();
    pollingRef.current = setInterval(tick, 5000);

    return () => {
      cancelled = true;
      stopPolling();
    };
  }, [loadData, stopPolling]);

  const handleCancel = async () => {
    if (!scan) return;
    setCancelling(true);
    try {
      const result = await scansApi.cancel(scan.id);
      // `cancel_requested` is honest: the scan has not stopped yet.
      if (!result.confirmed) {
        setError('Cancellation requested. The scanner is stopping; the scan will finish shortly.');
      }
      await loadData();
    } catch (err: unknown) {
      // 409 means somebody else already finished it: refresh instead of shouting.
      if (err instanceof ApiError && err.code === 'scan_already_finished') {
        await loadData();
      } else {
        setError(err instanceof Error ? err.message : 'The scan could not be cancelled.');
      }
    } finally {
      setCancelling(false);
    }
  };

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
        <span className={`scan-badge-large scan-${scan.status}`}>
          {SCAN_STATUS_LABELS[scan.status] ?? scan.status}
        </span>
        {(scan.status === 'running' || scan.status === 'queued') && (
          <button className="btn btn-sm btn-danger" onClick={handleCancel} disabled={cancelling}>
            {cancelling ? 'Cancelling…' : 'Cancel scan'}
          </button>
        )}
      </div>

      {scan.status === 'awaiting_approval' && (
        <div className="notice notice-warning" role="status">
          This scan is waiting for approval. It will not run until an operator approves the
          exact target, port set and tool list that were requested.
        </div>
      )}

      {(scan.status === 'failed' || scan.status === 'timed_out' || scan.status === 'cancelled') && (
        <div className="notice notice-error" role="alert">
          <strong>{scan.outcome_label ?? SCAN_STATUS_LABELS[scan.status] ?? scan.status}</strong>
          {scan.failure_detail ? <> — {scan.failure_detail}</> : null}
        </div>
      )}

      {scan.status === 'completed' && scan.degraded && (
        <div className="notice notice-warning" role="status">
          <strong>Partial coverage.</strong>{' '}
          {scan.failure_detail ?? 'Some scanners did not complete, so the absence of findings does not prove the target clean.'}
        </div>
      )}

      <div className="scan-info">
        <div className="info-row">
          <strong>Project:</strong>{' '}
          <Link to={`/projects/${scan.project_id}`}>View Project</Link>
        </div>
        <div className="info-row">
          <strong>Status:</strong> {SCAN_STATUS_LABELS[scan.status] ?? scan.status}
          {scan.outcome_label ? <span className="muted"> — {scan.outcome_label}</span> : null}
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

      {scan.scanner_runs && scan.scanner_runs.length > 0 && (
        <div className="scanner-runs">
          <h2>Scanners</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Scanner</th>
                <th>Mode</th>
                <th>Outcome</th>
                <th>Findings</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {scan.scanner_runs.map((run) => (
                <tr key={run.scanner} className={run.inconclusive ? 'row-warning' : undefined}>
                  <td>{run.scanner}</td>
                  <td>{run.intrusiveness}</td>
                  <td title={run.error ?? undefined}>
                    {run.outcome}
                    {run.inconclusive ? ' (no usable result)' : ''}
                  </td>
                  <td>{run.inconclusive ? '—' : run.findings_count}</td>
                  <td>{run.duration_ms === null ? '—' : `${(run.duration_ms / 1000).toFixed(1)}s`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

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
          <p className="empty-state">
            {severityFilter === 'all'
              ? IN_FLIGHT_STATUSES.includes(scan.status)
                ? 'No findings recorded yet — the scan is still running.'
                : scan.degraded
                  ? 'No findings, but coverage was incomplete: treat this as unproven, not clean.'
                  : scan.status === 'completed'
                    ? 'No findings were recorded for this scan.'
                    : 'This scan produced no findings because it did not complete.'
              : 'No results match the filter'}
          </p>
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
        {scan.status === 'completed' && scan.degraded && (
          <p className="notice notice-warning" role="status">
            Some scanners did not complete. Findings are partial — see the scanner list above.
          </p>
        )}
        {reports.length > 0 && (
          <div className="reports-list">
            {reports.map((report) => (
              <ReportCard key={report.id} report={report} />
            ))}
          </div>
        )}
        {scan.status !== 'completed' && reports.length === 0 && (
          <p className="empty-state">
            {IN_FLIGHT_STATUSES.includes(scan.status)
              ? 'Reports become available once the scan finishes.'
              : 'This scan produced no report because it did not complete.'}
          </p>
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
        <DownloadButton reportId={report.id} format={report.format} />
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
    } catch (err: unknown) {
      alert('Failed to generate report: ' + (err instanceof Error ? err.message : 'Unknown error'));
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
