import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { reportsApi } from '../services/api';
import type { Report } from '../types';

const FORMAT_LABELS: Record<string, string> = {
  html: 'HTML',
  pdf: 'PDF',
  json: 'JSON',
  md: 'Markdown',
  txt: 'Plain Text',
};

export default function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    reportsApi
      .all()
      .then(setReports)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="reports-page">
        <h1>Reports</h1>
        {[1, 2, 3].map((i) => (
          <div key={i} className="report-card">
            <div className="skeleton skeleton-text short" />
            <div className="skeleton skeleton-text" />
          </div>
        ))}
      </div>
    );
  }

  if (error) return <div className="error">{error}</div>;

  return (
    <div className="reports-page">
      <h1>Reports</h1>
      {reports.length === 0 && (
        <p className="empty-state">
          No reports yet. Run a scan, then generate a report from the scan detail page.
        </p>
      )}
      <div className="reports-list">
        {reports.map((report) => (
          <div key={report.id} className="report-card">
            <div className="report-card-header">
              <Link to={`/reports/${report.id}`} className="report-title">
                {report.title}
              </Link>
              <span className={`report-badge report-${report.status}`}>{report.status}</span>
            </div>
            <div className="report-meta-row">
              <span>Format: {FORMAT_LABELS[report.format] || report.format}</span>
              <span>Scan #{report.scan_id}</span>
              <span>{new Date(report.created_at).toLocaleString()}</span>
            </div>
            {report.scan && (
              <div className="report-meta-row">
                <span>Target: {report.scan.project?.target_url ?? 'N/A'}</span>
              </div>
            )}
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
        ))}
      </div>
    </div>
  );
}
