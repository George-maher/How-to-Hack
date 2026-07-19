import { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { projectsApi, scansApi } from '../services/api';
import type { Project, Scan } from '../types';

export default function ProjectDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const scanningRef = useRef(false);

  const loadProject = async () => {
    try {
      const projectId = Number(id);
      const [projectData, scansData] = await Promise.all([
        projectsApi.get(projectId),
        scansApi.list(projectId),
      ]);
      setProject(projectData);
      setScans(scansData);

      const active = scansData.find(
        (s) => s.status === 'running' || s.status === 'pending'
      );
      if (!active && scanningRef.current) {
        scanningRef.current = false;
        setScanning(false);
        if (pollingRef.current) {
          clearInterval(pollingRef.current);
          pollingRef.current = null;
        }
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProject();
    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    };
  }, [id]);

  useEffect(() => {
    if (scanning && !pollingRef.current) {
      scanningRef.current = true;
      pollingRef.current = setInterval(loadProject, 3000);
    }
    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    };
  }, [scanning, id]);

  const startScan = async () => {
    setScanning(true);
    scanningRef.current = true;
    try {
      await projectsApi.scan(Number(id));
      await loadProject();
    } catch (err: any) {
      setError(err.message);
      setScanning(false);
      scanningRef.current = false;
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

  if (error) return <div className="error">{error}</div>;
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
          disabled={scanning}
          className={`btn-scan ${scanning ? 'btn-disabled' : ''}`}
        >
          {scanning ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>

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

function ScanCard({ scan }: { scan: Scan }) {
  return (
    <Link to={`/scans/${scan.id}`} className="scan-card">
      <div className="scan-card-header">
        <span className={`scan-badge scan-${scan.status}`}>{scan.status}</span>
        <span className="scan-date">
          {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}
        </span>
      </div>
      <div className="scan-meta">
        <span>{scan.results_count} finding(s)</span>
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
                <p>{entry.message}</p>
              </li>
            ))}
          </ul>
        </details>
      )}
    </Link>
  );
}
