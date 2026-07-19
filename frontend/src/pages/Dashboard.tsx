import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { projectsApi } from '../services/api';
import type { Project } from '../types';

export default function Dashboard() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    projectsApi
      .list()
      .then(setProjects)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="dashboard">
        <h1>Dashboard</h1>
        <div className="stats-grid">
          {[1, 2, 3].map((i) => (
            <div key={i} className="stat-card skeleton skeleton-stat" />
          ))}
        </div>
        <div className="project-list">
          {[1, 2, 3].map((i) => (
            <div key={i} className="project-card">
              <div className="skeleton skeleton-text short" />
              <div className="skeleton skeleton-text" />
              <div className="skeleton skeleton-text long" />
            </div>
          ))}
        </div>
      </div>
    );
  }
  if (error) return <div className="error">Error: {error}</div>;

  const totalScans = projects.reduce((sum, p) => sum + p.scans_count, 0);
  const activeProjects = projects.filter((p) => p.status === 'active').length;

  return (
    <div className="dashboard">
      <h1>Dashboard</h1>
      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Projects</h3>
          <span className="stat-value">{projects.length}</span>
        </div>
        <div className="stat-card">
          <h3>Active Projects</h3>
          <span className="stat-value">{activeProjects}</span>
        </div>
        <div className="stat-card">
          <h3>Total Scans</h3>
          <span className="stat-value">{totalScans}</span>
        </div>
      </div>

      <div className="recent-projects">
        <h2>Projects</h2>
        <div className="project-list">
          {projects.map((project) => (
            <ProjectCard key={project.id} project={project} />
          ))}
        </div>
      </div>
    </div>
  );
}

function ProjectCard({ project }: { project: Project }) {
  const statusClass = project.status === 'active' ? 'status-active' : 'status-inactive';

  return (
    <Link to={`/projects/${project.id}`} className="project-card">
      <div className="project-card-header">
        <h3>{project.name}</h3>
        <span className={statusClass}>{project.status}</span>
      </div>
      <p className="project-target">{project.target_url}</p>
      <div className="project-meta">
        <span>{project.scans_count} scan(s)</span>
        {project.latest_scan && (
          <span className={`scan-status scan-${project.latest_scan.status}`}>
            {project.latest_scan.status}
          </span>
        )}
      </div>
      </Link>
    );
  }
