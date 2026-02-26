import { useState } from 'react'

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const OWASP = ['ALL', 'A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10']

export function Sidebar({ onScan, loading, filters, onFiltersChange }) {
  const [mode, setMode] = useState('github')
  const [repoUrl, setRepoUrl] = useState('')
  const [projectPath, setProjectPath] = useState('')
  const [branch, setBranch] = useState('')
  const [languages, setLanguages] = useState({ python: true, javascript: true })
  const [maxWorkers, setMaxWorkers] = useState(4)
  const [useOnlineCve, setUseOnlineCve] = useState(true)

  const handleSubmit = (e) => {
    e.preventDefault()
    onScan({
      mode,
      repoUrl: mode === 'github' ? repoUrl : null,
      projectPath: mode === 'local' ? projectPath : null,
      branch: mode === 'github' ? branch || undefined : undefined,
      languages: Object.entries(languages).filter(([, v]) => v).map(([k]) => k),
      maxWorkers,
      useOnlineCve,
    })
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-section">
        <h2>Scan Source</h2>
        <form onSubmit={handleSubmit}>
          <div className="mode-tabs">
            <button
              type="button"
              className={mode === 'github' ? 'active' : ''}
              onClick={() => setMode('github')}
            >
              GitHub
            </button>
            <button
              type="button"
              className={mode === 'local' ? 'active' : ''}
              onClick={() => setMode('local')}
            >
              Local Path
            </button>
          </div>

          {mode === 'github' ? (
            <>
              <label>
                <span>Repository URL</span>
                <input
                  type="text"
                  placeholder="https://github.com/owner/repo"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  disabled={loading}
                />
              </label>
              <label>
                <span>Branch (optional)</span>
                <input
                  type="text"
                  placeholder="main"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  disabled={loading}
                />
              </label>
            </>
          ) : (
            <label>
              <span>Project path</span>
              <input
                type="text"
                placeholder="/path/to/project"
                value={projectPath}
                onChange={(e) => setProjectPath(e.target.value)}
                disabled={loading}
              />
            </label>
          )}

          <div className="field-row">
            <label className="checkbox">
              <input
                type="checkbox"
                checked={languages.python}
                onChange={(e) => setLanguages((p) => ({ ...p, python: e.target.checked }))}
                disabled={loading}
              />
              Python
            </label>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={languages.javascript}
                onChange={(e) => setLanguages((p) => ({ ...p, javascript: e.target.checked }))}
                disabled={loading}
              />
              JavaScript
            </label>
          </div>

          <label>
            <span>Max workers</span>
            <input
              type="number"
              min={1}
              max={32}
              value={maxWorkers}
              onChange={(e) => setMaxWorkers(Number(e.target.value))}
              disabled={loading}
            />
          </label>

          <label className="checkbox">
            <input
              type="checkbox"
              checked={useOnlineCve}
              onChange={(e) => setUseOnlineCve(e.target.checked)}
              disabled={loading}
            />
            Use online CVE sources
          </label>

          <button type="submit" className="scan-button" disabled={loading}>
            {loading ? 'Scanning…' : 'Run Scan'}
          </button>
        </form>
      </div>

      <div className="sidebar-section">
        <h2>Filters</h2>
        <label>
          <span>Severity</span>
          <select
            value={filters.severity}
            onChange={(e) => onFiltersChange((p) => ({ ...p, severity: e.target.value }))}
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </label>
        <label>
          <span>OWASP</span>
          <select
            value={filters.owasp}
            onChange={(e) => onFiltersChange((p) => ({ ...p, owasp: e.target.value }))}
          >
            {OWASP.map((o) => (
              <option key={o} value={o}>{o}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Search</span>
          <input
            type="text"
            placeholder="File or description…"
            value={filters.search}
            onChange={(e) => onFiltersChange((p) => ({ ...p, search: e.target.value }))}
          />
        </label>
      </div>
    </aside>
  )
}
