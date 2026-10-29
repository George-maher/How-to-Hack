import { useState } from 'react';
import { ApiError, reportsApi } from '../services/api';

interface Props {
  reportId: number;
  format: string;
  className?: string;
  label?: string;
}

/**
 * Authenticated report download.
 *
 * Replaces an `<a download href>` that could not send the bearer token (and so
 * always returned 401). Failures are shown to the user with the API's own
 * message instead of silently doing nothing.
 */
export default function DownloadButton({ reportId, format, className = 'btn btn-sm btn-secondary', label = 'Download' }: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleClick = async () => {
    setBusy(true);
    setError(null);

    try {
      await reportsApi.download(reportId, format);
    } catch (err: unknown) {
      // Session expiry navigates away; everything else is reported inline.
      if (err instanceof ApiError && err.isUnauthenticated) return;

      setError(err instanceof Error ? err.message : 'The download failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button type="button" className={className} onClick={handleClick} disabled={busy}>
        {busy ? 'Preparing…' : label}
      </button>
      {error && (
        <span className="inline-error" role="alert" title={error}>
          {error}
        </span>
      )}
    </>
  );
}
