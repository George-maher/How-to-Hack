import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { reportsApi } from '../services/api';
import DownloadButton from '../components/DownloadButton';
import type { Report } from '../types';

const FORMAT_LABELS: Record<string, string> = {
  html: 'HTML',
  pdf: 'PDF',
  json: 'JSON',
  md: 'Markdown',
  txt: 'Plain Text',
};

export default function ReportDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloadFormat, setDownloadFormat] = useState('html');

  const loadReport = useCallback(async () => {
    try {
      const data = await reportsApi.get(Number(id));
      setReport(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    let cancelled = false;

    // State is set once the request resolves, never synchronously in the
    // effect body.
    const initialLoad = async () => {
      if (cancelled) return;
      await loadReport();
    };

    void initialLoad();

    return () => {
      cancelled = true;
    };
  }, [loadReport]);

  const handleRegenerate = async () => {
    try {
      setLoading(true);
      const result = await reportsApi.regenerate(Number(id), downloadFormat);
      setReport(result.report);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm('Delete this report?')) return;
    try {
      await reportsApi.delete(Number(id));
      navigate(-1);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    }
  };

  if (loading) {
    return (
      <div className="report-detail">
        <div className="skeleton skeleton-text short" style={{ width: '200px' }} />
        <div className="skeleton skeleton-text" />
        <div className="skeleton skeleton-text long" />
      </div>
    );
  }

  if (error) return <div className="error">{error}</div>;
  if (!report) return <div className="error">Report not found</div>;

  return (
    <div className="report-detail">
      <div className="report-header">
        <button onClick={() => navigate(-1)} className="btn-back">&larr; Back</button>
        <h1>{report.title}</h1>
        <span className={`report-status report-${report.status}`}>{report.status}</span>
      </div>

      <div className="report-meta">
        <div className="info-row">
          <strong>Format:</strong> {FORMAT_LABELS[report.format] || report.format}
        </div>
        <div className="info-row">
          <strong>Generated:</strong> {new Date(report.created_at).toLocaleString()}
        </div>
        {report.scan && (
          <div className="info-row">
            <strong>Scan:</strong> #{report.scan.id}
          </div>
        )}
      </div>

      <div className="report-actions">
        <div className="download-group">
          <select
            value={downloadFormat}
            onChange={(e) => setDownloadFormat(e.target.value)}
          >
            {Object.entries(FORMAT_LABELS).map(([val, label]) => (
              <option key={val} value={val}>{label}</option>
            ))}
          </select>
          <DownloadButton
            reportId={report.id}
            format={downloadFormat}
            className="btn btn-primary"
          />
          <button onClick={handleRegenerate} className="btn btn-secondary">
            Regenerate
          </button>
          <button onClick={handleDelete} className="btn btn-danger">
            Delete
          </button>
        </div>
      </div>

      {report.executive_summary && (
        <section className="report-section">
          <h2>Executive Summary</h2>
          <p>{report.executive_summary}</p>
        </section>
      )}

      {report.technical_summary && (
        <section className="report-section">
          <h2>Technical Summary</h2>
          <p>{report.technical_summary}</p>
        </section>
      )}

      {report.recommendations && (
        <section className="report-section">
          <h2>Recommendations</h2>
          <p>{report.recommendations}</p>
        </section>
      )}

      {report.scan_data && (
        <section className="report-section">
          <h2>Scan Data</h2>
          <pre className="scan-data-json">{JSON.stringify(report.scan_data, null, 2)}</pre>
        </section>
      )}
    </div>
  );
}
