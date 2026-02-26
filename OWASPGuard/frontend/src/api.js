/**
 * Resolve API base URL - works when served from same origin or Vite dev with proxy.
 * VITE_API_BASE can be set in .env (e.g. http://localhost:8000/api) for dev.
 */
function getApiBase() {
  if (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE) {
    return import.meta.env.VITE_API_BASE.replace(/\/$/, '')
  }
  return `${window.location.origin}/api`
}

const runScan = async (apiBase, options) => {
  const base = apiBase || getApiBase()
  const { mode, projectPath, repoUrl, branch, languages, maxWorkers, useOnlineCve } = options

  const payload = {
    languages: languages || ['python', 'javascript'],
    max_workers: maxWorkers ?? 4,
    use_online_cve: useOnlineCve !== false,
  }

  let url = `${base}/scan`
  if (mode === 'github' && repoUrl) {
    url = `${base}/scan/github`
    payload.repo_url = repoUrl.trim()
    if (branch) payload.branch = branch.trim()
  } else if (projectPath) {
    payload.project_path = projectPath.trim()
  } else {
    throw new Error(mode === 'github' ? 'Enter a GitHub repository URL' : 'Enter a project path')
  }

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })

  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const msg = typeof data.detail === 'string' ? data.detail : data.message || `Scan failed (${res.status})`
    throw new Error(msg)
  }
  return data
}

export { runScan, getApiBase }
