const severityClass = (sev) => {
  const s = (sev || '').toUpperCase()
  return `severity-${s.toLowerCase()}`
}

export function ViolationsPanel({ findings, selected, onSelect }) {
  return (
    <section className="violations-panel">
      <header>
        <h2>Violations</h2>
        <span className="caption">
          {findings.length === 0
            ? 'No data. Run a scan to see results.'
            : `${findings.length} violation${findings.length === 1 ? '' : 's'} shown`}
        </span>
      </header>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>OWASP</th>
              <th>File</th>
              <th>Line</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => {
              const isSelected = selected && selected === f
              return (
                <tr
                  key={i}
                  className={isSelected ? 'selected' : ''}
                  onClick={() => onSelect(f)}
                >
                  <td>
                    <span className={`badge ${severityClass(f.severity)}`}>
                      {f.severity || 'N/A'}
                    </span>
                  </td>
                  <td>{f.owasp_category || 'N/A'}</td>
                  <td className="file-cell">
                    {(f.file_path || '').split(/[/\\]/).pop() || 'N/A'}
                  </td>
                  <td>{f.line_number ?? 'N/A'}</td>
                  <td className="desc-cell">
                    {((f.description || '').length > 80
                      ? (f.description || '').slice(0, 80) + '…'
                      : f.description || 'N/A')}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </section>
  )
}
