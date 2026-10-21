import GroundedContext from './GroundedContext.jsx'
import RemediationSuggestion from './RemediationSuggestion.jsx'

function formatCategory(category) {
  if (!category) return '—'
  return String(category).replaceAll('_', ' ')
}

function detectorLabel(source) {
  if (source === 'SEMGREP') return 'Semgrep'
  if (source === 'AST_CODE_QUALITY') return 'AST Code Quality'
  if (source === 'CUSTOM_WEB_SECURITY_RULE') return 'Custom Web Rule'
  return source || '—'
}

/** Details of a single finding (shown inside FindingDrawer). */
export default function FindingDetails({ finding }) {
  if (!finding) return null

  const lineLabel = finding.end_line && finding.end_line !== finding.start_line
    ? `${finding.start_line}–${finding.end_line}`
    : String(finding.start_line)

  return (
    <div className="ca-finding">
      <dl className="ca-detail__grid ca-detail__grid--meta">
        <div>
          <dt>Category</dt>
          <dd>{formatCategory(finding.category)}</dd>
        </div>
        <div>
          <dt>CWE</dt>
          <dd>{(finding.cwe || []).join(', ') || '—'}</dd>
        </div>
        <div>
          <dt>Line</dt>
          <dd>{lineLabel}</dd>
        </div>
        <div>
          <dt>Detected By</dt>
          <dd>{detectorLabel(finding.source)}</dd>
        </div>
      </dl>

      {finding.metric && (
        <div className="ca-detail__section">
          <h4>Metric</h4>
          <p>
            {finding.metric.name}: {finding.metric.value} (threshold:{' '}
            {finding.metric.threshold})
          </p>
        </div>
      )}

      <div className="ca-detail__section">
        <h4>Description</h4>
        <p>{finding.description}</p>
      </div>

      <div className="ca-detail__section">
        <h4>Rule</h4>
        <code className="ca-detail__rule">{finding.rule_id}</code>
      </div>

      {finding.code_snippet && (
        <div className="ca-detail__section">
          <h4>Code</h4>
          <pre className="ca-detail__code">{finding.code_snippet}</pre>
        </div>
      )}

      {finding.ast_context && (
        <div className="ca-detail__section">
          <h4>Code Context</h4>
          <dl className="ca-detail__grid ca-context">
            {finding.ast_context.context_level === 'FUNCTION' && (
              <>
                <div>
                  <dt>Function</dt>
                  <dd>{finding.ast_context.function_name}</dd>
                </div>
                <div>
                  <dt>Lines</dt>
                  <dd>
                    {finding.ast_context.function_start_line}–
                    {finding.ast_context.function_end_line}
                  </dd>
                </div>
                <div>
                  <dt>Parameters</dt>
                  <dd>{finding.ast_context.parameter_count}</dd>
                </div>
                <div>
                  <dt>Function Length</dt>
                  <dd>{finding.ast_context.function_length}</dd>
                </div>
                <div>
                  <dt>Nesting Depth</dt>
                  <dd>{finding.ast_context.max_nesting_depth}</dd>
                </div>
              </>
            )}
            {finding.ast_context.context_level === 'CLASS' && (
              <div>
                <dt>Class</dt>
                <dd>{finding.ast_context.class_name}</dd>
              </div>
            )}
            <div>
              <dt>Context Level</dt>
              <dd>{finding.ast_context.context_level}</dd>
            </div>
          </dl>
          {finding.ast_context.calls?.length > 0 && (
            <div className="ca-context__calls">
              <h5 className="ca-context__calls-title">
                Calls
                <span className="ca-context__calls-count">{finding.ast_context.calls.length}</span>
              </h5>
              <ul className="ca-context__calls-list">
                {finding.ast_context.calls.map((call, index) => (
                  <li key={`${call}-${index}`} className="ca-context__call" title={call}>
                    <code>{call}</code>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {finding.context_id && <GroundedContext findingId={finding.finding_id} />}

      {finding.context_id ? (
        <RemediationSuggestion key={finding.finding_id} findingId={finding.finding_id} />
      ) : (
        <p className="ca-detail__note">
          AI remediation is available for security findings with grounded repository context.
        </p>
      )}
    </div>
  )
}
