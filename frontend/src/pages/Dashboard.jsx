import { useState, useEffect, useMemo } from 'react'
import {
  Shield, CheckCircle2, Globe, Code2, Copy, Check,
  Play, RefreshCw, ChevronDown, ChevronUp, Download,
  Layers, AlertCircle, FileText, ExternalLink, Trash2
} from 'lucide-react'

const DEFAULT_DEMO_ALERTS = [
  {
    alert: 'SQL Injection',
    url: 'http://localhost:5000/api/orders?id=1',
    method: 'GET',
    param: 'id',
    attack: "1' OR '1'='1",
    evidence: 'syntax error near SELECT',
    cweid: '89'
  },
  {
    alert: 'Cross Site Scripting (Reflected)',
    url: 'http://localhost:5000/api/search?q=<script>alert(1)</script>',
    method: 'GET',
    param: 'q',
    attack: '<script>alert(1)</script>',
    evidence: '<script>alert(1)</script>',
    cweid: '79'
  }
]

const PYGOAT_DEMO_ALERTS = [
  {
    alert: 'Remote OS Command Injection',
    url: 'http://localhost:5000/lab1',
    method: 'POST',
    param: 'domain',
    attack: '; id',
    evidence: 'uid=0(root) gid=0(root)',
    cweid: '78'
  },
  {
    alert: 'Code Injection',
    url: 'http://localhost:5000/lab2',
    method: 'POST',
    param: 'val',
    attack: '__import__("os").system("id")',
    evidence: '0',
    cweid: '94'
  },
  {
    alert: 'SQL Injection',
    url: 'http://localhost:5000/lab',
    method: 'POST',
    param: 'username',
    attack: "admin' OR '1'='1",
    evidence: 'syntax error',
    cweid: '89'
  }
]

const Dashboard = () => {
  // Config & Health State
  const [config, setConfig] = useState(null)

  // Scan Input State
  const [targetDir, setTargetDir] = useState('data/samples')
  const [targetUrl, setTargetUrl] = useState('http://localhost:5000')
  const [includeDemoAlerts, setIncludeDemoAlerts] = useState(true)

  // Scan Execution State
  const [isScanning, setIsScanning] = useState(false)
  const [scanStep, setScanStep] = useState('')
  const [error, setError] = useState(null)
  const [scanData, setScanData] = useState(null)

  // Filtering & View State
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [showRoutes, setShowRoutes] = useState(false)
  const [expandedIssueId, setExpandedIssueId] = useState(null)
  const [copiedId, setCopiedId] = useState(null)

  // Load system configuration on mount
  useEffect(() => {
    fetch('/api/config')
      .then(res => res.json())
      .then(data => setConfig(data))
      .catch(() => {})
  }, [])

  // Clear current results and reset backend scan store
  const handleClearResults = async () => {
    try {
      await fetch('/api/issues/clear', { method: 'POST' })
    } catch (e) {
      console.error(e)
    }
    setScanData(null)
    setError(null)
    setExpandedIssueId(null)
  }

  // Execute correlation scan
  const executeScan = async (isDemo = false) => {
    setIsScanning(true)
    setError(null)
    setScanData(null)
    setExpandedIssueId(null)
    setScanStep('Running Semgrep SAST & AST Scanner...')

    // If Run Demo Scan was clicked, reset to demo folder & enable demo alerts
    let folder = targetDir.trim() || 'data/samples'
    let useAlerts = includeDemoAlerts
    if (isDemo) {
      folder = 'data/samples'
      useAlerts = true
      setTargetDir('data/samples')
      setIncludeDemoAlerts(true)
    }

    try {
      const stepTimer1 = setTimeout(() => setScanStep('Extracting Python AST Route Map...'), 700)
      const stepTimer2 = setTimeout(() => setScanStep('Ingesting OWASP ZAP DAST Runtime Proof...'), 1500)
      const stepTimer3 = setTimeout(() => setScanStep('Correlating SAST line numbers with DAST endpoints...'), 2400)
      const stepTimer4 = setTimeout(() => setScanStep('Generating Sandboxed LLM Remediation (temp=0.0)...'), 3200)

      const demoAlertsToUse = folder.toLowerCase().includes('pygoat') ? PYGOAT_DEMO_ALERTS : DEFAULT_DEMO_ALERTS
      const payload = {
        source_folder: folder,
        target_url: targetUrl.trim() || undefined,
        raw_zap_alerts: useAlerts ? demoAlertsToUse : undefined,
        generate_fixes: true
      }

      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      clearTimeout(stepTimer1)
      clearTimeout(stepTimer2)
      clearTimeout(stepTimer3)
      clearTimeout(stepTimer4)

      const data = await res.json()
      if (!res.ok) {
        throw new Error(data.detail || 'Scan execution failed')
      }

      setScanData(data)
      const firstConfirmed = data.issues?.find(i => i.status_label === 'Confirmed')
      if (firstConfirmed) {
        setExpandedIssueId(firstConfirmed.id)
      } else if (data.issues?.length > 0) {
        setExpandedIssueId(data.issues[0].id)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setIsScanning(false)
      setScanStep('')
    }
  }

  // Filter issues
  const filteredIssues = useMemo(() => {
    if (!scanData?.issues) return []
    return scanData.issues.filter(issue => {
      if (statusFilter !== 'ALL' && issue.status_label !== statusFilter) return false
      if (severityFilter !== 'ALL' && issue.severity !== severityFilter) return false
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const matchCwe = (issue.cwe_id || '').toLowerCase().includes(q)
        const matchType = (issue.vulnerability_type || '').toLowerCase().includes(q)
        const matchFile = (issue.file || '').toLowerCase().includes(q)
        const matchRoute = (issue.url_path || '').toLowerCase().includes(q)
        if (!matchCwe && !matchType && !matchFile && !matchRoute) return false
      }
      return true
    })
  }, [scanData, statusFilter, severityFilter, searchQuery])

  // Copy code helper
  const handleCopyCode = async (code, id) => {
    try {
      await navigator.clipboard.writeText(code)
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 2000)
    } catch (err) {
      console.error(err)
    }
  }

  // Export JSON
  const exportJSON = () => {
    if (!scanData) return
    const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scan-report-${scanData.scan_id || 'export'}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Export Markdown
  const exportMarkdown = () => {
    if (!scanData?.issues) return
    let md = `# SAST + DAST Correlation Report\n\n`
    md += `Scan ID: ${scanData.scan_id}\n`
    md += `Total Issues: ${scanData.total_issues} (Confirmed: ${scanData.confirmed_count}, Runtime only: ${scanData.runtime_only_count}, Code only: ${scanData.code_only_count})\n\n`
    scanData.issues.forEach(iss => {
      md += `## [${iss.status_label}] #${iss.priority_rank}: ${iss.cwe_id} - ${iss.vulnerability_type}\n`
      md += `- Severity: ${iss.severity} | Risk Score: ${iss.risk_score}/100\n`
      if (iss.file) md += `- Code Location: ${iss.file}:${iss.line}\n`
      if (iss.url_path) md += `- Runtime Endpoint: ${iss.http_method || 'GET'} ${iss.url_path}\n`
      if (iss.fix_suggestion) md += `- Fix Suggestion: ${iss.fix_suggestion}\n`
      if (iss.fixed_code) md += `\n\`\`\`python\n${iss.fixed_code}\n\`\`\`\n`
      md += `\n---\n\n`
    })
    const blob = new Blob([md], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scan-report-${scanData.scan_id || 'export'}.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      {/* Simple Clean Header */}
      <header className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 mb-6 border-b border-gray-200 gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-600" />
            <h1 className="text-xl font-bold text-gray-900 tracking-tight">Cyber-Forge</h1>
            <span className="text-xs font-medium px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
              SAST + DAST Correlation Prototype
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Deterministic route-to-code correlation engine (FR-1 through FR-10)
          </p>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <div className="px-2.5 py-1 rounded bg-gray-100 text-gray-700 font-mono border border-gray-200">
            LLM: <span className="font-semibold">{config?.llm_mode?.toUpperCase() || 'GROQ'}</span> ({config?.model || 'llama-3.3-70b-versatile'})
          </div>
          <a
            href="/docs"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1 text-gray-600 hover:text-blue-600 font-medium"
          >
            API Docs
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </header>

      {/* Scan Input Box */}
      <section className="bg-white border border-gray-200 rounded-lg p-5 shadow-xs mb-6">
        <h2 className="text-sm font-semibold text-gray-800 mb-3">Scan Targets</h2>
        
        <div className="grid sm:grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              Source Code Target Folder
            </label>
            <input
              type="text"
              value={targetDir}
              onChange={(e) => setTargetDir(e.target.value)}
              placeholder="e.g. data/samples"
              className="w-full text-xs font-mono px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 bg-gray-50"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              Dynamic Runtime URL (DAST)
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="e.g. http://localhost:5000"
              className="w-full text-xs font-mono px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 bg-gray-50"
            />
          </div>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-gray-100">
          <label className="flex items-center gap-2 text-xs text-gray-600 cursor-pointer">
            <input
              type="checkbox"
              checked={includeDemoAlerts}
              onChange={(e) => setIncludeDemoAlerts(e.target.checked)}
              className="rounded text-blue-600 focus:ring-0"
            />
            <span>
              Include demo OWASP ZAP alerts for correlation ({targetDir.toLowerCase().includes('pygoat') ? '`/lab1` Cmd Injection, `/lab2` Code Injection, `/lab` SQLi' : '`/api/orders` SQLi & `/api/search` XSS'})
            </span>
          </label>

          <div className="flex items-center gap-2">
            {scanData && (
              <button
                onClick={handleClearResults}
                disabled={isScanning}
                className="px-3 py-2 rounded-md border border-gray-300 bg-white hover:bg-gray-100 text-gray-600 text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
                title="Clear current scan results"
              >
                <Trash2 className="w-3.5 h-3.5 text-gray-500" />
                Clear
              </button>
            )}

            <button
              onClick={() => executeScan(true)}
              disabled={isScanning}
              className="px-3 py-2 rounded-md border border-gray-300 bg-gray-50 hover:bg-gray-100 text-gray-700 text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
              Run Demo Scan
            </button>

            <button
              onClick={() => executeScan(false)}
              disabled={isScanning}
              className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-white" />
              {isScanning ? 'Correlating...' : 'Run Correlation Scan'}
            </button>
          </div>
        </div>
      </section>

      {/* Scanning Status */}
      {isScanning && (
        <div className="bg-blue-50 border border-blue-200 text-blue-800 rounded-lg p-4 text-xs flex items-center gap-3 mb-6">
          <div className="w-4 h-4 border-2 border-blue-600 border-t-transparent rounded-full animate-spin flex-shrink-0" />
          <div>
            <p className="font-semibold">{scanStep || 'Executing correlation pipeline...'}</p>
            <p className="text-[11px] text-blue-600 mt-0.5">Semgrep SAST ──► AST Routes ──► DAST Alerts ──► Deduplication ──► LLM Remediation</p>
          </div>
        </div>
      )}

      {/* Error Banner */}
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4 text-xs flex items-center gap-2 mb-6">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Metric Summary Cards */}
      {scanData && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          {/* Confirmed */}
          <div
            onClick={() => setStatusFilter(statusFilter === 'Confirmed' ? 'ALL' : 'Confirmed')}
            className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
              statusFilter === 'Confirmed'
                ? 'bg-green-100/60 border-green-400 ring-2 ring-green-400/20'
                : 'bg-white border-green-200 hover:bg-green-50/50'
            }`}
          >
            <div className="text-[11px] font-medium text-green-700">Rank #1 • Confirmed</div>
            <div className="text-2xl font-bold text-green-800 mt-1">{scanData.confirmed_count}</div>
            <div className="text-[11px] text-green-600 mt-0.5">Proven in Code & Runtime</div>
          </div>

          {/* Runtime only */}
          <div
            onClick={() => setStatusFilter(statusFilter === 'Runtime only' ? 'ALL' : 'Runtime only')}
            className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
              statusFilter === 'Runtime only'
                ? 'bg-amber-100/60 border-amber-400 ring-2 ring-amber-400/20'
                : 'bg-white border-amber-200 hover:bg-amber-50/50'
            }`}
          >
            <div className="text-[11px] font-medium text-amber-700">Rank #2 • Runtime only</div>
            <div className="text-2xl font-bold text-amber-800 mt-1">{scanData.runtime_only_count}</div>
            <div className="text-[11px] text-amber-600 mt-0.5">DAST only (no code match)</div>
          </div>

          {/* Code only */}
          <div
            onClick={() => setStatusFilter(statusFilter === 'Code only' ? 'ALL' : 'Code only')}
            className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
              statusFilter === 'Code only'
                ? 'bg-blue-100/60 border-blue-400 ring-2 ring-blue-400/20'
                : 'bg-white border-blue-200 hover:bg-blue-50/50'
            }`}
          >
            <div className="text-[11px] font-medium text-blue-700">Rank #3 • Code only</div>
            <div className="text-2xl font-bold text-blue-800 mt-1">{scanData.code_only_count}</div>
            <div className="text-[11px] text-blue-600 mt-0.5">SAST only (theoretical)</div>
          </div>

          {/* Routes */}
          <div
            onClick={() => setShowRoutes(!showRoutes)}
            className="p-3.5 rounded-lg bg-white border border-gray-200 hover:bg-gray-50 cursor-pointer transition-all"
          >
            <div className="text-[11px] font-medium text-gray-500">AST Route Map</div>
            <div className="text-2xl font-bold text-gray-800 mt-1">{scanData.route_map?.length || 0}</div>
            <div className="text-[11px] text-gray-500 mt-0.5">{showRoutes ? 'Click to hide' : 'Click to view'}</div>
          </div>
        </div>
      )}

      {/* No DAST findings notice */}
      {scanData && scanData.confirmed_count === 0 && scanData.runtime_only_count === 0 && targetUrl && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 mb-6 text-xs text-amber-900 flex items-start gap-3">
          <AlertCircle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p className="font-semibold text-amber-950">
              No DAST findings returned ({targetUrl})
            </p>
            <p className="text-amber-800 leading-relaxed">
              SAST found <strong>{scanData.code_only_count} code-only findings</strong> across <strong>{scanData.route_map?.length || 0} AST routes</strong>. The DAST scan returned no runtime alerts for this run.
              This does not necessarily mean the target is offline; ZAP may have reached it without finding an alert on the scanned pages.
            </p>
            <p className="text-amber-800 leading-relaxed">
              Cyber-Forge reports runtime findings only when a scanner or supplied report provides evidence. To check the correlation flow, you can:
            </p>
            <ul className="list-disc list-inside text-amber-800 pl-1 space-y-0.5 text-[11px]">
              <li>Confirm the target URL and the routes reached by the scan.</li>
              <li>Enable <strong>&quot;Include demo OWASP ZAP alerts for correlation&quot;</strong> to exercise the correlation flow with demo evidence.</li>
            </ul>
          </div>
        </div>
      )}

      {/* AST Route Map Drawer (FR-4) */}
      {showRoutes && scanData?.route_map && (
        <section className="bg-white border border-gray-200 rounded-lg p-4 mb-6 shadow-xs">
          <div className="flex items-center justify-between pb-2 mb-3 border-b border-gray-100">
            <h3 className="text-xs font-bold text-gray-800 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-blue-600" />
              Statically Extracted AST Routes ({scanData.route_map.length})
            </h3>
            <span className="text-[11px] text-gray-500">Extracted from source code line spans</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-gray-200 text-gray-500 text-[11px]">
                  <th className="py-1.5 px-2">Method</th>
                  <th className="py-1.5 px-2">URL Route Path</th>
                  <th className="py-1.5 px-2">Handler Function</th>
                  <th className="py-1.5 px-2">File & Line Bounds</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {scanData.route_map.map((r, i) => (
                  <tr key={i} className="hover:bg-gray-50">
                    <td className="py-1.5 px-2">
                      <span className="px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 font-bold text-[10px]">
                        {Array.isArray(r.http_method) ? r.http_method.join('/') : r.http_method}
                      </span>
                    </td>
                    <td className="py-1.5 px-2 font-semibold text-gray-900">{r.url_path}</td>
                    <td className="py-1.5 px-2 text-purple-700">{r.handler_function}()</td>
                    <td className="py-1.5 px-2 text-gray-500">{r.file} (lines {r.start_line}–{r.end_line})</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Prioritized Issues Section (FR-7 & FR-9) */}
      {scanData && (
        <section>
          {/* Controls Bar: Filter, Search, Export */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 bg-white border border-gray-200 rounded-lg p-3 shadow-xs text-xs">
            {/* Status Tabs */}
            <div className="flex items-center gap-1 flex-wrap">
              <span className="text-gray-500 text-[11px] mr-1">Status:</span>
              {['ALL', 'Confirmed', 'Runtime only', 'Code only'].map((st) => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                    statusFilter === st
                      ? 'bg-gray-900 text-white font-semibold'
                      : 'text-gray-600 hover:bg-gray-100'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>

            {/* Severity, Search, Export */}
            <div className="flex items-center gap-2 flex-wrap">
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="border border-gray-300 rounded px-2 py-1 text-xs text-gray-700 bg-white"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>

              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search CWE / type..."
                className="border border-gray-300 rounded px-2.5 py-1 text-xs text-gray-700 placeholder-gray-400 w-36 sm:w-44"
              />

              <button
                onClick={exportJSON}
                className="p-1.5 border border-gray-200 rounded text-gray-600 hover:bg-gray-50"
                title="Export JSON"
              >
                <Download className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={exportMarkdown}
                className="p-1.5 border border-gray-200 rounded text-gray-600 hover:bg-gray-50"
                title="Export Markdown"
              >
                <FileText className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Issues Count */}
          <div className="text-xs text-gray-500 mb-2 px-1 flex justify-between">
            <span>Showing {filteredIssues.length} of {scanData.total_issues} issues</span>
            <span>Ordered by Priority Rank (Confirmed first, then Runtime, then Code)</span>
          </div>

          {/* Issues List */}
          <div className="space-y-2.5">
            {filteredIssues.map((issue) => {
              const isExpanded = expandedIssueId === issue.id
              const isConfirmed = issue.status_label === 'Confirmed'

              return (
                <div
                  key={issue.id}
                  className={`bg-white border rounded-lg shadow-2xs transition-colors ${
                    isConfirmed ? 'border-green-300 bg-green-50/20' : 'border-gray-200'
                  }`}
                >
                  {/* Card Header Row */}
                  <div
                    onClick={() => setExpandedIssueId(isExpanded ? null : issue.id)}
                    className="p-3.5 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-2.5"
                  >
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="text-xs font-mono font-bold text-gray-400">
                        #{issue.priority_rank}
                      </span>

                      {/* Status Badge */}
                      {issue.status_label === 'Confirmed' ? (
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-green-100 text-green-800 border border-green-200 flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3 text-green-700" />
                          Confirmed
                        </span>
                      ) : issue.status_label === 'Runtime only' ? (
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-100 text-amber-800 border border-amber-200 flex items-center gap-1">
                          <Globe className="w-3 h-3 text-amber-700" />
                          Runtime only
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-100 text-blue-800 border border-blue-200 flex items-center gap-1">
                          <Code2 className="w-3 h-3 text-blue-700" />
                          Code only
                        </span>
                      )}

                      {/* Severity Badge */}
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        issue.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                        issue.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                        issue.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' : 'bg-gray-100 text-gray-700'
                      }`}>
                        {issue.severity}
                      </span>

                      {/* Title & CWE */}
                      <span className="text-sm font-semibold text-gray-900">{issue.vulnerability_type}</span>
                      <span className="text-xs font-mono text-gray-500">({issue.cwe_id})</span>

                      {/* Location snippet */}
                      <span className="text-xs text-gray-500 font-mono">
                        {issue.file ? `${issue.file}:${issue.line}` : ''}
                        {issue.url_path ? ` • ${issue.http_method || 'GET'} ${issue.url_path}` : ''}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 self-end sm:self-auto text-xs">
                      <div className="font-mono text-gray-500">
                        Risk: <span className="font-bold text-gray-900">{issue.risk_score}</span>/100
                      </div>
                      <button className="text-gray-400 hover:text-gray-600">
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Expanded Detail View */}
                  {isExpanded && (
                    <div className="px-4 pb-4 pt-2 border-t border-gray-100 text-xs space-y-3 bg-gray-50/50 rounded-b-lg">
                      {/* Confirmed Match Proof */}
                      {isConfirmed && (
                        <div className="p-2.5 rounded bg-green-50 border border-green-200 text-green-800 flex items-center gap-2">
                          <CheckCircle2 className="w-4 h-4 text-green-600 flex-shrink-0" />
                          <div>
                            <span className="font-bold">Correlation Verified: </span>
                            DAST on <code className="font-mono font-bold bg-green-100 px-1 py-0.5 rounded">{issue.http_method} {issue.url_path}</code> matches AST route handler <code className="font-mono font-bold bg-green-100 px-1 py-0.5 rounded">{issue.handler_function}()</code> at line <code className="font-mono font-bold bg-green-100 px-1 py-0.5 rounded">{issue.line}</code> of <code className="font-mono">{issue.file}</code>.
                          </div>
                        </div>
                      )}

                      {/* Dual Evidence: Static vs Dynamic */}
                      <div className="grid sm:grid-cols-2 gap-3">
                        {/* SAST Evidence */}
                        <div className="bg-white border border-gray-200 rounded p-3">
                          <div className="text-[11px] font-bold text-gray-700 uppercase mb-1.5 flex items-center gap-1">
                            <Code2 className="w-3 h-3 text-blue-600" />
                            SAST Code Location
                          </div>
                          <div className="text-gray-600 space-y-0.5 font-mono text-[11px] mb-2">
                            <div>File: <span className="text-gray-900 font-semibold">{issue.file || 'Unmapped'}</span></div>
                            <div>Line: <span className="text-gray-900 font-semibold">{issue.line || 'N/A'}</span></div>
                            <div>Handler: <span className="text-purple-700">{issue.handler_function || 'global'}()</span></div>
                          </div>
                          {issue.code_snippet && (
                            <pre className="p-2 rounded bg-gray-900 text-red-300 font-mono text-[11px] overflow-x-auto">
                              <code>{issue.code_snippet}</code>
                            </pre>
                          )}
                        </div>

                        {/* DAST Evidence */}
                        <div className="bg-white border border-gray-200 rounded p-3">
                          <div className="text-[11px] font-bold text-gray-700 uppercase mb-1.5 flex items-center gap-1">
                            <Globe className="w-3 h-3 text-purple-600" />
                            DAST Runtime Proof
                          </div>
                          <div className="text-gray-600 space-y-0.5 font-mono text-[11px] mb-2">
                            <div>Endpoint: <span className="text-gray-900 font-semibold">{issue.http_method || 'GET'} {issue.url_path || 'N/A'}</span></div>
                            <div>Parameter: <span className="text-amber-700 font-semibold">{issue.parameter || 'N/A'}</span></div>
                            <div>Supporting: <span className="text-gray-900">{(issue.supporting_scanners || ['SAST']).join(', ')}</span></div>
                          </div>
                          {issue.payload && (
                            <div className="p-1.5 rounded bg-gray-100 border border-gray-200 font-mono text-[11px] text-gray-800 mb-1">
                              Payload: <code>{issue.payload}</code>
                            </div>
                          )}
                          {issue.evidence && (
                            <div className="p-1.5 rounded bg-gray-100 border border-gray-200 font-mono text-[11px] text-gray-700">
                              Evidence: <code>{issue.evidence}</code>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* AI Remediation */}
                      {(issue.fix_suggestion || issue.fixed_code) && (
                        <div className="bg-white border border-gray-200 rounded p-3">
                          <div className="flex items-center justify-between mb-1.5">
                            <div className="text-[11px] font-bold text-blue-800 uppercase">
                              Remediation (Groq / Ollama temp=0.0)
                            </div>
                            {issue.fixed_code && (
                              <button
                                onClick={() => handleCopyCode(issue.fixed_code, issue.id)}
                                className="px-2 py-0.5 rounded bg-gray-100 hover:bg-gray-200 text-gray-700 text-[11px] flex items-center gap-1"
                              >
                                {copiedId === issue.id ? <Check className="w-3 h-3 text-green-600" /> : <Copy className="w-3 h-3" />}
                                {copiedId === issue.id ? 'Copied' : 'Copy Fix'}
                              </button>
                            )}
                          </div>

                          {issue.fix_suggestion && (
                            <p className="text-gray-700 text-xs mb-2 leading-relaxed">
                              {issue.fix_suggestion}
                            </p>
                          )}

                          {issue.fixed_code && (
                            <pre className="p-2.5 rounded bg-gray-900 text-green-400 font-mono text-[11px] overflow-x-auto">
                              <code>{issue.fixed_code}</code>
                            </pre>
                          )}
                        </div>
                      )}

                      {/* Deduplication Footnote */}
                      <div className="text-[10px] text-gray-400 flex items-center justify-between pt-1">
                        <span>Hash: {issue.issue_hash?.substring(0, 16)}...</span>
                        <span>Merged {issue.merged_count || 1} scanner findings idempotently</span>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </section>
      )}

      {/* Empty State */}
      {!scanData && !isScanning && (
        <div className="bg-white border border-gray-200 rounded-lg p-12 text-center shadow-xs">
          <Shield className="w-10 h-10 text-gray-300 mx-auto mb-2" />
          <h3 className="text-sm font-semibold text-gray-800">No scan results yet</h3>
          <p className="text-xs text-gray-500 max-w-sm mx-auto mt-1 mb-4">
            Click &quot;Run Correlation Scan&quot; or &quot;Run Demo Scan&quot; above to scan source code and correlate with dynamic runtime alerts.
          </p>
          <button
            onClick={() => executeScan(true)}
            className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold inline-flex items-center gap-1.5 shadow-xs"
          >
            <Play className="w-3.5 h-3.5 fill-white" />
            Run Demo Scan Now
          </button>
        </div>
      )}
    </div>
  )
}

export default Dashboard
