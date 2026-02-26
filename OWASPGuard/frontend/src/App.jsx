import { useState, useCallback, useEffect } from 'react'
import './App.css'
import { Sidebar } from './components/Sidebar'
import { ViolationsPanel } from './components/ViolationsPanel'
import { DetailPanel } from './components/DetailPanel'
import { SummaryCards } from './components/SummaryCards'
import { runScan } from './api'

function App() {
  const [findings, setFindings] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selectedFinding, setSelectedFinding] = useState(null)
  const [filters, setFilters] = useState({ severity: 'ALL', owasp: 'ALL', search: '' })
  const [apiConnected, setApiConnected] = useState(null)

  useEffect(() => {
    fetch(`${window.location.origin}/api/health`)
      .then((r) => (r.ok ? setApiConnected(true) : setApiConnected(false)))
      .catch(() => setApiConnected(false))
  }, [])

  const handleScan = useCallback(async (options) => {
    setLoading(true)
    setError(null)
    setFindings([])
    setStats(null)
    setSelectedFinding(null)
    try {
      const result = await runScan(undefined, options)
      setFindings(result.findings || [])
      setStats(result.stats || {})
    } catch (err) {
      setError(err.message || 'Scan failed')
    } finally {
      setLoading(false)
    }
  }, [])

  const filteredFindings = findings.filter((f) => {
    const sev = (f.severity || '').toUpperCase()
    const owasp = (f.owasp_category || '').toUpperCase()
    const file = (f.file_path || '').toLowerCase()
    const desc = (f.description || '').toLowerCase()
    const search = (filters.search || '').trim().toLowerCase()
    if (filters.severity !== 'ALL' && sev !== filters.severity) return false
    if (filters.owasp !== 'ALL' && owasp !== filters.owasp) return false
    if (search && !file.includes(search) && !desc.includes(search)) return false
    return true
  })

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-brand">
          <span className="logo-icon">🛡️</span>
          <span className="logo-text">OWASPGuard</span>
          <span className="logo-sub">Violations</span>
        </div>
      </header>

      {apiConnected === false && (
        <div className="error-banner">
          Cannot reach API. Ensure the backend is running (e.g. ./OWASPGuard/start_server.sh) and you are on the same origin.
        </div>
      )}
      <div className="app-body">
        <Sidebar
          onScan={handleScan}
          loading={loading}
          filters={filters}
          onFiltersChange={setFilters}
        />
        <main className="main-content">
          {error && (
            <div className="error-banner">
              {error}
            </div>
          )}
          <SummaryCards findings={findings} />
          {stats && (
            <div className="stats-bar">
              <span className="stat">Files scanned: <strong>{stats.files_scanned ?? 0}</strong></span>
              <span className="stat">Duration: <strong>{stats.scan_duration?.toFixed(1) ?? 0}s</strong></span>
              <span className="stat">Source: <strong>{stats.source === 'github' ? 'GitHub' : stats.repo_url || 'Local'}</strong></span>
            </div>
          )}
          <ViolationsPanel
            findings={filteredFindings}
            selected={selectedFinding}
            onSelect={setSelectedFinding}
          />
          <DetailPanel finding={selectedFinding} />
        </main>
      </div>
    </div>
  )
}

export default App
