export function DetailPanel({ finding }) {
  if (!finding) {
    return (
      <section className="detail-panel">
        <h2>Details</h2>
        <p className="placeholder">Select a violation to view details</p>
      </section>
    )
  }

  const code = finding.code_snippet || finding.line_content
  const remediation = finding.remediation || finding.recommendation

  return (
    <section className="detail-panel">
      <h2>Violation Details</h2>
      <div className="detail-content">
        <div className="detail-row">
          <span className="label">Description</span>
          <span className="value">{finding.description || 'N/A'}</span>
        </div>
        <div className="detail-row">
          <span className="label">Severity</span>
          <span className={`badge severity-${(finding.severity || 'info').toLowerCase()}`}>
            {finding.severity || 'N/A'} {finding.severity_score != null && `(${finding.severity_score})`}
          </span>
        </div>
        <div className="detail-row">
          <span className="label">OWASP</span>
          <span className="value">{finding.owasp_category_full || finding.owasp_category || 'N/A'}</span>
        </div>
        <div className="detail-row">
          <span className="label">File</span>
          <span className="value mono">{finding.file_path || 'N/A'}</span>
        </div>
        <div className="detail-row">
          <span className="label">Line</span>
          <span className="value">{finding.line_number ?? 'N/A'}</span>
        </div>
        <div className="detail-row">
          <span className="label">Rule ID</span>
          <span className="value">{finding.rule_id || 'N/A'}</span>
        </div>
        <div className="detail-row">
          <span className="label">Scan type</span>
          <span className="value">{finding.scan_type || 'SAST'}</span>
        </div>
        {finding.ml_confidence != null && (
          <div className="detail-row">
            <span className="label">ML confidence</span>
            <span className="value">
              {(Math.min(1, Math.max(0, Number(finding.ml_confidence))) * 100).toFixed(1)}%
            </span>
          </div>
        )}
        {finding.cve_id && (
          <>
            <div className="detail-row">
              <span className="label">CVE</span>
              <span className="value">{finding.cve_id}</span>
            </div>
            {finding.package && (
              <div className="detail-row">
                <span className="label">Package</span>
                <span className="value">{finding.package}</span>
              </div>
            )}
            {finding.version && (
              <div className="detail-row">
                <span className="label">Version</span>
                <span className="value">{finding.version}</span>
              </div>
            )}
          </>
        )}
        {code && (
          <div className="detail-block">
            <span className="label">Code</span>
            <pre className="code-snippet">{code}</pre>
          </div>
        )}
        {remediation && (
          <div className="detail-block">
            <span className="label">Remediation</span>
            <pre className="remediation">{remediation}</pre>
          </div>
        )}
      </div>
    </section>
  )
}
