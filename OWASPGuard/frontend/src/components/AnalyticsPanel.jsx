import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts'

const SEVERITY_COLORS = {
  CRITICAL: '#E53E3E',
  HIGH: '#DD6B20',
  MEDIUM: '#D69E2E',
  LOW: '#38A169',
  INFO: '#718096',
}

const OWASP_LABELS = {
  A01: 'A01 - Access Control',
  A02: 'A02 - Crypto Failures',
  A03: 'A03 - Injection',
  A04: 'A04 - Insecure Design',
  A05: 'A05 - Misconfig',
  A06: 'A06 - Components',
  A07: 'A07 - Auth Failures',
  A08: 'A08 - Integrity',
  A09: 'A09 - Logging',
  A10: 'A10 - SSRF',
}

function buildSeverityData(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  for (const f of findings) {
    const s = (f.severity || 'INFO').toUpperCase()
    if (counts[s] != null) counts[s]++
  }
  return Object.entries(counts).map(([name, value]) => ({ name, value }))
}

function buildOwaspData(findings) {
  const counts = {}
  for (const f of findings) {
    const c = (f.owasp_category || 'OTHER').toUpperCase()
    counts[c] = (counts[c] || 0) + 1
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, value]) => ({
      name: OWASP_LABELS[cat] || cat,
      value,
    }))
}

function buildFileData(findings, limit = 8) {
  const counts = {}
  for (const f of findings) {
    const file = (f.file_path || 'unknown').split(/[/\\]/).pop()
    counts[file] = (counts[file] || 0) + 1
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([name, value]) => ({ name, value }))
}

function buildMlConfidenceData(findings) {
  const buckets = {
    '0–20%': 0,
    '20–40%': 0,
    '40–60%': 0,
    '60–80%': 0,
    '80–100%': 0,
  }
  let total = 0
  let sum = 0

  for (const f of findings) {
    if (f.ml_confidence == null) continue
    const raw = Number(f.ml_confidence)
    if (Number.isNaN(raw)) continue
    const v = Math.min(1, Math.max(0, raw))
    sum += v
    total++
    const pct = v * 100
    if (pct < 20) buckets['0–20%']++
    else if (pct < 40) buckets['20–40%']++
    else if (pct < 60) buckets['40–60%']++
    else if (pct < 80) buckets['60–80%']++
    else buckets['80–100%']++
  }

  const data = Object.entries(buckets).map(([name, value]) => ({ name, value }))
  const avg = total ? (sum / total) * 100 : null

  return { data, avg, total }
}

export function AnalyticsPanel({ findings }) {
  if (!findings.length) {
    return null
  }

  const severityData = buildSeverityData(findings)
  const owaspData = buildOwaspData(findings)
  const fileData = buildFileData(findings)
  const ml = buildMlConfidenceData(findings)

  return (
    <section className="analytics-panel">
      <div className="analytics-header">
        <h2>Analytics</h2>
        <span className="caption">Deeper insights from the current scan</span>
      </div>

      <div className="analytics-grid">
        {/* Severity distribution */}
        <div className="analytics-card">
          <h3>Severity distribution</h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={severityData}
                dataKey="value"
                nameKey="name"
                outerRadius={70}
                label
              >
                {severityData.map((entry) => (
                  <Cell
                    key={entry.name}
                    fill={SEVERITY_COLORS[entry.name] || '#4A5568'}
                  />
                ))}
              </Pie>
              <Legend />
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Findings by OWASP category */}
        <div className="analytics-card">
          <h3>Findings by OWASP category</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={owaspData} margin={{ left: -20 }}>
              <XAxis dataKey="name" tick={{ fontSize: 10 }} interval={0} angle={-30} textAnchor="end" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="value" fill="#3182CE" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top files by findings */}
        <div className="analytics-card">
          <h3>Top files by findings</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={fileData}>
              <XAxis dataKey="name" tick={{ fontSize: 10 }} interval={0} angle={-30} textAnchor="end" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="value" fill="#805AD5" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* ML confidence distribution */}
        <div className="analytics-card">
          <h3>ML confidence distribution</h3>
          <div className="ml-summary">
            <div>
              <span className="label">Average confidence</span>
              <span className="value">
                {ml.avg != null ? `${ml.avg.toFixed(1)}%` : 'N/A'}
              </span>
            </div>
            <div>
              <span className="label">Findings with ML signal</span>
              <span className="value">{ml.total}</span>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={ml.data}>
              <XAxis dataKey="name" tick={{ fontSize: 10 }} />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="value" fill="#2F855A" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </section>
  )
}

