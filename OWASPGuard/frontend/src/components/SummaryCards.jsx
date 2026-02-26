const counts = (findings) => {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  for (const f of findings) {
    const s = (f.severity || 'INFO').toUpperCase()
    if (c[s] !== undefined) c[s]++
  }
  return c
}

export function SummaryCards({ findings }) {
  const c = counts(findings)
  const total = findings.length

  return (
    <div className="summary-cards">
      <div className="card card-total">
        <span className="card-label">Total</span>
        <span className="card-value">{total}</span>
      </div>
      <div className="card card-critical">
        <span className="card-label">Critical</span>
        <span className="card-value">{c.CRITICAL}</span>
      </div>
      <div className="card card-high">
        <span className="card-label">High</span>
        <span className="card-value">{c.HIGH}</span>
      </div>
      <div className="card card-medium">
        <span className="card-label">Medium</span>
        <span className="card-value">{c.MEDIUM}</span>
      </div>
      <div className="card card-low">
        <span className="card-label">Low</span>
        <span className="card-value">{c.LOW}</span>
      </div>
    </div>
  )
}
