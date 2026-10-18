export default function ScanSummary({ result }) {
  if (!result) return null

  const { scan_id: scanId, status, repository } = result
  const languages = repository.languages || []

  return (
    <section className="ca-summary">
      <h2 className="ca-summary__title">Repository Summary</h2>

      <div className="ca-summary__header">
        <div>
          <p className="ca-summary__repo-name">{repository.name}</p>
          <a
            className="ca-summary__repo-link"
            href={repository.url}
            target="_blank"
            rel="noreferrer"
          >
            {repository.url.replace('https://', '')}
          </a>
        </div>
        <span className={`ca-badge ca-badge--${status}`}>
          {status.charAt(0).toUpperCase() + status.slice(1)}
        </span>
      </div>

      <dl className="ca-summary__grid">
        <div className="ca-summary__item">
          <dt>Owner</dt>
          <dd>{repository.owner}</dd>
        </div>
        <div className="ca-summary__item">
          <dt>Default Branch</dt>
          <dd>{repository.default_branch}</dd>
        </div>
        <div className="ca-summary__item">
          <dt>Total Files</dt>
          <dd>{repository.total_files}</dd>
        </div>
        <div className="ca-summary__item">
          <dt>Source Files</dt>
          <dd>{repository.source_files}</dd>
        </div>
        <div className="ca-summary__item">
          <dt>Languages</dt>
          <dd>{languages.length}</dd>
        </div>
        {typeof repository.js_ts_percent === 'number' && (
          <div className="ca-summary__item">
            <dt>JS/TS Code</dt>
            <dd>{repository.js_ts_percent}%</dd>
          </div>
        )}
        {(repository.reapplied_patches > 0 || repository.skipped_patches > 0) && (
          <div
            className="ca-summary__item"
            title="Accepted patches are re-applied to the fresh GitHub clone before analysis, so fixed findings are not reported again."
          >
            <dt>Accepted Patches</dt>
            <dd>
              {repository.reapplied_patches} re-applied
              {repository.skipped_patches > 0 && ` · ${repository.skipped_patches} skipped`}
            </dd>
          </div>
        )}
      </dl>

      {languages.length > 0 && (
        <div className="ca-summary__languages">
          <h3>Languages</h3>
          <ul>
            {languages.map((language) => (
              <li key={language.name}>
                <span>{language.name}</span>
                <span className="ca-summary__language-count">{language.files}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="ca-summary__scan-id">
        Scan ID: <code>{scanId}</code>
      </p>
    </section>
  )
}
