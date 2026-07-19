import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { projectsApi } from '../services/api';

export default function CreateProject() {
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [description, setDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const project = await projectsApi.create({
        name,
        target_url: targetUrl,
        description: description || undefined,
      });
      navigate(`/projects/${project.id}`);
    } catch (err: any) {
      setError(err.message);
      setSubmitting(false);
    }
  };

  return (
    <div className="create-project">
      <h1>New Project</h1>
      <form onSubmit={handleSubmit} className="project-form">
        {error && <div className="form-error">{error}</div>}

        <div className="form-group">
          <label htmlFor="name">Project Name</label>
          <input
            id="name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            placeholder="e.g., Company Security Audit"
          />
        </div>

        <div className="form-group">
          <label htmlFor="targetUrl">Target URL</label>
          <input
            id="targetUrl"
            type="url"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            required
            placeholder="e.g., https://example.com"
          />
        </div>

        <div className="form-group">
          <label htmlFor="description">Description (optional)</label>
          <textarea
            id="description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
            placeholder="Brief description of the project"
          />
        </div>

        <div className="form-actions">
          <button type="button" onClick={() => navigate('/')} className="btn-cancel">
            Cancel
          </button>
          <button type="submit" disabled={submitting} className="btn-submit">
            {submitting ? 'Creating...' : 'Create Project'}
          </button>
        </div>
      </form>
    </div>
  );
}
