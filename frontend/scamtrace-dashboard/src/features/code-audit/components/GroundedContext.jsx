import { useEffect, useState } from 'react'
import { getGroundedContext } from '../api/codeAuditApi.js'

const NODE_LABELS = {
  ROUTE: 'Route',
  CONTROLLER: 'Controller',
  FUNCTION: 'Function',
  SERVICE: 'Service',
  SINK: 'Sink',
}

const STEP_LABELS = {
  SOURCE: 'Source',
  ASSIGNMENT: 'Assignment',
  CALL_ARGUMENT: 'Call argument',
  PARAMETER: 'Parameter',
  SINK: 'Sink',
}

function location(file, line) {
  if (!file) return line ? `line ${line}` : null
  return line ? `${file}:${line}` : file
}

function ConfidenceBadge({ value }) {
  if (!value) return null
  return <span className={`ca-ground__conf ca-ground__conf--${value.toLowerCase()}`}>{value}</span>
}

function RelationshipChain({ chain }) {
  return (
    <ol className="ca-ground__chain">
      {chain.map((node, index) => (
        <li key={`${node.kind}-${index}`} className={`ca-ground__node ca-ground__node--${node.kind.toLowerCase()}`}>
          <span className="ca-ground__node-kind">{NODE_LABELS[node.kind] || node.kind}</span>
          <code className="ca-ground__node-label" title={node.label}>{node.label}</code>
          {location(node.file, node.line) && (
            <span className="ca-ground__node-loc">{location(node.file, node.line)}</span>
          )}
        </li>
      ))}
    </ol>
  )
}

function DataFlowView({ flow }) {
  return (
    <div className="ca-ground__block">
      <h5 className="ca-ground__subtitle">
        Source → Sink Data Flow <ConfidenceBadge value={flow.confidence} />
      </h5>
      <ol className="ca-ground__flow">
        {flow.steps.map((step, index) => (
          <li key={index} className={`ca-ground__step ca-ground__step--${step.type.toLowerCase()}`}>
            <span className="ca-ground__step-type">{STEP_LABELS[step.type] || step.type}</span>
            <code>{step.expression || [step.from, step.to].filter(Boolean).join(' → ')}</code>
            <span className="ca-ground__node-loc">{location(step.file, step.line)}</span>
          </li>
        ))}
      </ol>
      {(!flow.traced || flow.crosses_files || flow.stopped_at_boundary) && (
        <p className="ca-detail__note">
          {!flow.traced && 'Source and sink are co-located; the link between them was not traced. '}
          {flow.crosses_files && 'Flow crosses files. '}
          {flow.stopped_at_boundary && 'Trace stopped at an analysis boundary (bounded depth).'}
        </p>
      )}
    </div>
  )
}

function EvidenceList({ title, items, render }) {
  if (!items?.length) return null
  return (
    <div className="ca-ground__block">
      <h5 className="ca-ground__subtitle">{title}</h5>
      <ul className="ca-ground__list">
        {items.map((item, index) => <li key={index}>{render(item)}</li>)}
      </ul>
    </div>
  )
}

/** Remount per finding so no context leaks between findings. */
export default function GroundedContext({ findingId }) {
  if (!findingId) return null
  return <GroundedContextView key={findingId} findingId={findingId} />
}

function GroundedContextView({ findingId }) {
  const [context, setContext] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let active = true
    getGroundedContext(findingId)
      .then((data) => active && setContext(data.context))
      .catch((err) => active && setError(err.message))
    return () => {
      active = false
    }
  }, [findingId])

  if (error) {
    return (
      <div className="ca-detail__section">
        <h4>Repository Context Grounding</h4>
        <p className="ca-detail__note">Grounded context unavailable. {error}</p>
      </div>
    )
  }
  if (!context) {
    return (
      <div className="ca-detail__section">
        <h4>Repository Context Grounding</h4>
        <p className="ca-loading">Loading grounded context…</p>
      </div>
    )
  }

  const { scope, repository_relationships: relationships, data_flow: flow } = context
  const route = relationships.route

  return (
    <div className="ca-detail__section ca-ground">
      <h4>
        Repository Context Grounding{' '}
        <span className={`ca-ground__completeness ca-ground__completeness--${context.completeness.toLowerCase()}`}>
          {context.completeness}
        </span>
      </h4>
      <p className="ca-detail__note ca-ground__intro">
        Static evidence linking this finding to the real repository — this is what the LLM
        receives instead of only the vulnerable snippet.
      </p>

      {relationships.chain?.length > 0 && (
        <div className="ca-ground__block">
          <h5 className="ca-ground__subtitle">Identified Path</h5>
          <RelationshipChain chain={relationships.chain} />
        </div>
      )}

      <dl className="ca-detail__grid ca-ground__facts">
        <div>
          <dt>Scope</dt>
          <dd>
            {scope.function_name || scope.class_name || 'File level'}{' '}
            <ConfidenceBadge value={context.confidence.function_match} />
          </dd>
        </div>
        <div>
          <dt>Location</dt>
          <dd>
            {scope.file_path}
            {scope.start_line && `:${scope.start_line}–${scope.end_line}`}
          </dd>
        </div>
        {route && (
          <div>
            <dt>Route</dt>
            <dd>
              <code>{route.method} {route.full_path}</code>{' '}
              <ConfidenceBadge value={route.confidence} />
              {route.middleware?.length > 0 && (
                <span className="ca-ground__middleware">middleware: {route.middleware.join(', ')}</span>
              )}
            </dd>
          </div>
        )}
        {relationships.controller && (
          <div>
            <dt>Controller</dt>
            <dd>
              {relationships.controller.function}{' '}
              <ConfidenceBadge value={relationships.controller.confidence} />
            </dd>
          </div>
        )}
      </dl>

      {scope.source_excerpt && (
        <details className="ca-ground__snippets">
          <summary>
            Grounded source ({scope.file_path}:{scope.source_excerpt.start_line}–{scope.source_excerpt.end_line}
            {scope.source_excerpt.truncated && ', truncated'})
          </summary>
          <pre className="ca-detail__code">{scope.source_excerpt.code}</pre>
        </details>
      )}

      {flow && <DataFlowView flow={flow} />}

      <EvidenceList
        title="User-Controlled Inputs"
        items={context.user_controlled_inputs}
        render={(input) => (
          <>
            <code>{input.expression}</code>
            {input.assigned_to && <> → <code>{input.assigned_to}</code></>}{' '}
            <span className="ca-ground__node-loc">line {input.line}</span>
          </>
        )}
      />
      <EvidenceList
        title="Sensitive Sinks"
        items={context.sensitive_sinks}
        render={(sink) => (
          <>
            <code>{sink.expression}</code> <span className="ca-ground__tag">{sink.sink_type}</span>{' '}
            <span className="ca-ground__node-loc">line {sink.line}</span>
          </>
        )}
      />
      <EvidenceList
        title="Hardcoded Values (masked)"
        items={context.hardcoded_values}
        render={(value) => (
          <>
            <code>{value.name}</code> = <code>{value.masked_value}</code>{' '}
            <span className="ca-ground__node-loc">line {value.line}</span>
          </>
        )}
      />
      <EvidenceList
        title="Services Called"
        items={relationships.services}
        render={(service) => (
          <>
            <code>{service.called_function}</code>
            {service.file && <span className="ca-ground__node-loc"> {location(service.file, service.line)}</span>}{' '}
            <ConfidenceBadge value={service.confidence} />
          </>
        )}
      />

      {context.security_constraint?.constraint && (
        <div className="ca-remediation__note ca-ground__constraint" role="note">
          <span className="ca-remediation__note-label">Constraint</span>
          <p>{context.security_constraint.constraint}</p>
        </div>
      )}

      {context.related_snippets?.length > 0 && (
        <details className="ca-ground__snippets">
          <summary>Related code ({context.related_snippets.length})</summary>
          {context.related_snippets.map((snippet, index) => (
            <div key={index} className="ca-ground__snippet">
              <p className="ca-ground__snippet-head">
                <span className="ca-ground__tag">{snippet.relationship.replaceAll('_', ' ')}</span>{' '}
                <code>{snippet.symbol}</code>{' '}
                <span className="ca-ground__node-loc">
                  {snippet.file}:{snippet.start_line}–{snippet.end_line}
                </span>
              </p>
              <pre className="ca-detail__code">{snippet.code}</pre>
            </div>
          ))}
        </details>
      )}
    </div>
  )
}
