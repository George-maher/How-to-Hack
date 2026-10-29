import { useEffect, useState, useRef, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ApiError, approvalsApi, projectsApi, scansApi } from '../services/api';
import type { Approval, InitiateScanResponse, Project, Scan } from '../types';
import { IN_FLIGHT_STATUSES, SCAN_STATUS_LABELS } from '../types';

const POLL_INTERVAL_MS = 3000;

/**
 * A project and its scan history.
 *
 * Scan state is owned by the server. The page polls only while a scan is in a
 * non-terminal status, stops as soon as the server says otherwise, and never
 * presents a queued/awaiting-approval/failed scan as running or complete.
 */
export default function ProjectDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [approval, setApproval] = useState<Approval | null>(null);
  const [starting, setStarting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  const loadProject = useCallback(async () => {
    try {
      const projectId = Number(id);
      const [projectData, scansData] = await Promise.all([
        projectsApi.get(projectId),
        scansApi.list(projectId),
      ]);

      setProject(projectData);
      setScans(scansData);
      setError(null);

      const active = scansData.find((scan) => IN_FLIGHT_STATUSES.includes(scan.status));
      if (!active) {
        stopPolling();
        setApproval(null);
        return;
      }

      // Surface the pending approval so the operator can act on it.
      if (active.status === 'awaiting_approval') {
        try {
          const pending = await approvalsApi.list('pending');
          setApproval(pending.find((item) => item.scan_id === active.id) ?? null);
        } catch {
          setApproval(null);
        }
      } else {
        setApproval(null);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'The project could not be loaded.');
      stopPolling();
    } finally {
      setLoading(false);
    }
  }, [id, stopPolling]);

  useEffect(() => {
    let cancelled = false;

    // State is set after the request resolves, never synchronously in the
    // effect body.
    const initialLoad = async () => {
      if (cancelled) return;
      await loadProject();
    };

    void initialLoad();

    return () => {
      cancelled = true;
      stopPolling();
    };
  }, [loadProject, stopPolling]);

  // Poll only while a scan is in flight; the effect re-runs as statuses change.
  const hasActiveScan = scans.some((scan) => IN_FLIGHT_STATUSES.includes(scan.status));

  useEffect(() => {
    if (!hasActiveScan) {
      stopPolling();
      return;
    }

    if (!pollingRef.current) {
      pollingRef.current = setInterval(() => {
        void loadProject();
      }, POLL_INTERVAL_MS);
    }

    return () => {
      stopPolling();
    };
  }, [hasActiveScan, loadProject, stopPolling]);

  const startScan = async () => {
    setStarting(true);
    setError(null);
    setNotice(null);

    try {
      const response: InitiateScanResponse = await projectsApi.scan(Number(id));
      await loadProject();

      // Never say "scanning" when the server is waiting for a human.
      if (response.status === 'awaiting_approval') {
        setNotice('Approval required. Review the target, ports and tools below, then approve.');
      }
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        // The API's own explanation (e.g. "target is not in the allowlist")
        // is preserved verbatim: rewording it would hide the policy reason.
        setError(err.message);
      } else {
        setError('The scan could not be started.');
      }
    } finally {
      setStarting(false);
    }
  };

  if (loading) {
    return (
      <div className="project-detail">
        <div className="project-header">
          <div className="skeleton skeleton-text short" style={{ width: '100px' }} />
          <div className="skeleton skeleton-text long" style={{ height: '28px' }} />
        </div>
        <div className="project-info">
          <div className="skeleton skeleton-text" />
          <div className="skeleton skeleton-text" />
        </div>
        <div className="scans-list">
          {[1, 2].map((i) => (
            <div key={i} className="scan-card">
              <div className="skeleton skeleton-text short" />
              <div className="skeleton skeleton-text" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (error && !project) return <div className="error" role="alert">{error}</div>;
  if (!project) return <div className="error">Project not found</div>;

  return (
    <div className="project-detail">
      <div className="project-header">
        <button onClick={() => navigate('/')} className="btn-back">
          &larr; Back
        </button>
        <h1>{project.name}</h1>
        <button
          onClick={startScan}
          disabled={starting || hasActiveScan}
          className={`btn-scan ${starting || hasActiveScan ? 'btn-disabled' : ''}`}
        >
          {starting ? 'Starting…' : hasActiveScan ? 'Scan in progress' : 'Start Scan'}
        </button>
      </div>

      {error && (
        <div className="notice notice-error" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="notice notice-warning" role="status">
          {notice}
        </div>
      )}

      {approval && (
        <ApprovalPanel
          approval={approval}
          onDecided={async (message) => {
            setNotice(message);
            await loadProject();
          }}
        />
      )}

      <div className="project-info">
        <div className="info-row">
          <strong>Target:</strong> {project.target_url}
        </div>
        {project.description && (
          <div className="info-row">
            <strong>Description:</strong> {project.description}
          </div>
        )}
        <div className="info-row">
          <strong>Status:</strong>{' '}
          <span className={`status-${project.status}`}>{project.status}</span>
        </div>
      </div>

      <h2>Scan History</h2>
      <div className="scans-list">
        {scans.length === 0 && <p className="empty-state">No scans yet</p>}
        {scans.map((scan) => (
          <ScanCard key={scan.id} scan={scan} />
        ))}
      </div>
    </div>
  );
}

function ApprovalPanel({
  approval,
  onDecided,
}: {
  approval: Approval;
  onDecided: (message: string) => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const decide = async (action: 'approve' | 'reject') => {
    setBusy(true);
    setError(null);

    try {
      const result =
        action === 'approve'
          ? await approvalsApi.approve(approval.id)
          : await approvalsApi.reject(approval.id);

      await onDecided(result.message);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'The approval could not be recorded.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="approval-panel" role="region" aria-label="Pending approval">
      <h2>Approve active scan</h2>
      <p>
        The tools below make active requests to the target. Approving authorises exactly this
        target, port set and tool list, until{' '}
        <strong>{approval.expires_at ? new Date(approval.expires_at).toLocaleString() : 'expiry'}</strong>.
        Any change invalidates it.
      </p>

      <dl className="approval-facts">
        <dt>Target</dt>
        <dd>{approval.target_host}</dd>
        <dt>Ports</dt>
        <dd>{approval.target_ports.join(', ') || 'default'}</dd>
        <dt>Tools</dt>
        <dd>{approval.tools.join(', ')}</dd>
        <dt>Scope rule</dt>
        <dd>{approval.scope_rule ?? 'allowlist'}</dd>
      </dl>

      {error && (
        <div className="notice notice-error" role="alert">
          {error}
        </div>
      )}

      <div className="approval-actions">
        <button className="btn btn-primary" onClick={() => void decide('approve')} disabled={busy}>
          {busy ? 'Recording…' : 'Approve'}
        </button>
        <button className="btn btn-secondary" onClick={() => void decide('reject')} disabled={busy}>
          Reject
        </button>
      </div>
    </div>
  );
}

function ScanCard({ scan }: { scan: Scan }) {
  return (
    <Link to={`/scans/${scan.id}`} className="scan-card">
      <div className="scan-card-header">
        <span className={`scan-badge scan-${scan.status}`}>
          {SCAN_STATUS_LABELS[scan.status] ?? scan.status}
        </span>
        <span className="scan-date">
          {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}
        </span>
      </div>
      <div className="scan-meta">
        {scan.status === 'completed' ? (
          <span>
            {scan.results_count} finding(s)
            {scan.degraded ? ' — partial coverage' : ''}
          </span>
        ) : (
          <span>{scan.outcome_label ?? SCAN_STATUS_LABELS[scan.status] ?? scan.status}</span>
        )}
        {scan.completed_scanners && (
          <span>{scan.completed_scanners.length} scanner(s) executed</span>
        )}
      </div>
      {scan.ai_reasoning && scan.ai_reasoning.length > 0 && (
        <details className="reasoning-details">
          <summary>AI Reasoning ({scan.ai_reasoning.length} steps)</summary>
          <ul>
            {scan.ai_reasoning.map((entry, i) => (
              <li key={i}>
                <small>{entry.timestamp}</small>
                <p>{entry.message ?? entry.reason}</p>
              </li>
            ))}
          </ul>
        </details>
      )}
    </Link>
  );
}
