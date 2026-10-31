import { useState, useMemo, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, Play, Trash2, FileCode, Download, Upload, Zap, FileJson, FileText, File, FolderOpen } from 'lucide-react'
import { Link } from 'react-router-dom'
import CodeEditor from '../components/CodeEditor'
import ResultsPanel from '../components/ResultsPanel'
import GlowButton from '../components/GlowButton'
import FileUpload from '../components/FileUpload'
import MultiFileResults from '../components/MultiFileResults'

const SAMPLE_CODE = `# Example vulnerable Python code
import os
import pickle
import sqlite3

def get_user(user_id):
    # SQL Injection vulnerability
    conn = sqlite3.connect('users.db')
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    result = conn.execute(query)
    return result.fetchone()

def run_command(cmd):
    # Command injection vulnerability
    os.system("echo " + cmd)

def process_data(data):
    # Insecure deserialization
    obj = pickle.loads(data)
    return obj

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"

def dangerous_eval(user_input):
    # Arbitrary code execution
    result = eval(user_input)
    return result
`

const Dashboard = () => {
  const [code, setCode] = useState('')
  const [language, setLanguage] = useState('python')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisStage, setAnalysisStage] = useState('')
  const [results, setResults] = useState(null)
  const [error, setError] = useState(null)
  const [showExportMenu, setShowExportMenu] = useState(false)
  
  // Multi-file mode
  const [mode, setMode] = useState('single') // 'single' or 'multi'
  const [uploadedFiles, setUploadedFiles] = useState([])
  const [multiFileResults, setMultiFileResults] = useState(null)

  // Extract highlighted lines from vulnerabilities
  const highlightedLines = useMemo(() => {
    if (!results?.vulnerabilities) return []
    const lines = []
    results.vulnerabilities.forEach(vuln => {
      if (vuln.line_numbers) {
        vuln.line_numbers.forEach(lineNum => {
          lines.push({ line: lineNum, severity: vuln.severity })
        })
      }
    })
    // Also add static findings
    if (results.static_findings) {
      results.static_findings.forEach(finding => {
        if (finding.line && !lines.find(l => l.line === finding.line)) {
          lines.push({ line: finding.line, severity: finding.severity })
        }
      })
    }
    return lines
  }, [results])

  const analyzeCode = async () => {
    if (!code.trim()) {
      setError('Please enter some code to analyze')
      return
    }

    setIsAnalyzing(true)
    setError(null)
    setResults(null)
    setAnalysisStage('Running static analysis...')

    try {
      setTimeout(() => setAnalysisStage('Scanning for vulnerabilities...'), 500)
      setTimeout(() => setAnalysisStage('AI analyzing code patterns...'), 1500)
      setTimeout(() => setAnalysisStage('Generating recommendations...'), 3000)
      
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, language })
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || 'Analysis failed')
      }

      if (!data.success) {
        throw new Error(data.error || 'Analysis failed')
      }

      setResults(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setIsAnalyzing(false)
      setAnalysisStage('')
    }
  }

  const loadSample = () => {
    setCode(SAMPLE_CODE)
    setLanguage('python')
    setResults(null)
    setError(null)
    setMode('single')
  }

  const clearAll = () => {
    setCode('')
    setResults(null)
    setError(null)
    setUploadedFiles([])
    setMultiFileResults(null)
  }

  // Handle file upload
  const handleFilesSelected = (files) => {
    setUploadedFiles(files)
    setMultiFileResults(null)
    setError(null)
  }

  // Analyze multiple files
  const analyzeMultipleFiles = async () => {
    if (uploadedFiles.length === 0) {
      setError('Please upload files first')
      return
    }

    setIsAnalyzing(true)
    setError(null)
    setMultiFileResults(null)
    setAnalysisStage('Preparing files for analysis...')

    try {
      const filesPayload = uploadedFiles.map(f => ({
        filename: f.filename,
        content: f.content,
        language: f.language
      }))

      setAnalysisStage(`Analyzing ${filesPayload.length} files...`)
      
      const response = await fetch('/api/analyze-multiple', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files: filesPayload })
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || 'Multi-file analysis failed')
      }

      if (!data.success) {
        throw new Error(data.error || 'Multi-file analysis failed')
      }

      setMultiFileResults(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setIsAnalyzing(false)
      setAnalysisStage('')
    }
  }

  // Export as JSON
  const exportJSON = () => {
    const data = mode === 'multi' ? multiFileResults : results
    if (!data) return
    const report = JSON.stringify(data, null, 2)
    downloadFile(report, 'security-report.json', 'application/json')
    setShowExportMenu(false)
  }

  // Export as Markdown
  const exportMarkdown = () => {
    if (mode === 'multi') {
      if (!multiFileResults) return
      const md = generateMultiFileMarkdownReport(multiFileResults)
      downloadFile(md, 'security-report.md', 'text/markdown')
    } else {
      if (!results) return
      const md = generateMarkdownReport(results, code)
      downloadFile(md, 'security-report.md', 'text/markdown')
    }
    setShowExportMenu(false)
  }

  // Export as PDF
  const exportPDF = useCallback(async () => {
    const data = mode === 'multi' ? multiFileResults : results
    if (!data) return
    
    setShowExportMenu(false)
    
    try {
      // Dynamic import for code splitting
      const html2pdf = (await import('html2pdf.js')).default
      
      const content = mode === 'multi' 
        ? generateMultiFileHTMLReport(data)
        : generateHTMLReport(data, code)
      
      // Create a wrapper element with visible styles
      const element = document.createElement('div')
      element.innerHTML = `
        <div style="width: 100%; padding: 20px; background: white; color: black; font-family: Arial, Helvetica, sans-serif; font-size: 14px; line-height: 1.6;">
          ${content}
        </div>
      `
      
      // Append to body (visible for html2canvas to capture)
      document.body.appendChild(element)
      
      // Give browser time to render
      await new Promise(resolve => setTimeout(resolve, 100))
      
      // Generate PDF with options
      const opt = {
        margin: 10,
        filename: 'security-report.pdf',
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { 
          scale: 2,
          useCORS: true,
          logging: false,
          backgroundColor: '#ffffff',
          windowWidth: 800
        },
        jsPDF: { 
          unit: 'mm', 
          format: 'a4', 
          orientation: 'portrait' 
        }
      }
      
      await html2pdf().set(opt).from(element).save()
      
      // Cleanup
      document.body.removeChild(element)
      
    } catch (err) {
      console.error('PDF export failed:', err)
      alert('PDF export failed: ' + err.message)
    }
  }, [mode, multiFileResults, results, code])

  const downloadFile = (content, filename, type) => {
    const blob = new Blob([content], { type })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  const generateMarkdownReport = (data, _sourceCode) => {
    let md = `# Security Analysis Report\n\n`
    md += `**Generated:** ${new Date().toLocaleString()}\n\n`
    md += `## Summary\n\n`
    md += `- **Language:** ${data.language}\n`
    md += `- **Risk Score:** ${data.risk_score}/100\n`
    md += `- **Summary:** ${data.summary}\n\n`

    if (data.vulnerabilities?.length > 0) {
      md += `## Vulnerabilities (${data.vulnerabilities.length})\n\n`
      data.vulnerabilities.forEach((vuln, i) => {
        md += `### ${i + 1}. ${vuln.type}\n\n`
        md += `- **Severity:** ${vuln.severity?.toUpperCase()}\n`
        md += `- **Line(s):** ${vuln.line_numbers?.join(', ') || 'N/A'}\n`
        md += `- **Description:** ${vuln.description}\n\n`
        if (vuln.vulnerable_code) {
          md += `**Vulnerable Code:**\n\`\`\`\n${vuln.vulnerable_code}\n\`\`\`\n\n`
        }
        if (vuln.fix_suggestion) {
          md += `**Fix Suggestion:** ${vuln.fix_suggestion}\n\n`
        }
        if (vuln.fixed_code) {
          md += `**Fixed Code:**\n\`\`\`\n${vuln.fixed_code}\n\`\`\`\n\n`
        }
      })
    }

    if (data.attack_surfaces?.length > 0) {
      md += `## Attack Surfaces\n\n`
      data.attack_surfaces.forEach(surface => {
        md += `- **${surface.name}** (${surface.risk_level}): ${surface.description}\n`
      })
      md += `\n`
    }

    if (data.recommendations?.length > 0) {
      md += `## Recommendations\n\n`
      data.recommendations.forEach(rec => {
        md += `- ${rec}\n`
      })
    }

    md += `\n---\n*Generated by LLM Code Analyser*\n`
    return md
  }

  const generateHTMLReport = (data, _sourceCode) => {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 100%; margin: 0; padding: 0; color: #000000; background: #ffffff;">
        <h1 style="color: #1a1a2e; border-bottom: 3px solid #0ea5e9; padding-bottom: 10px; margin-bottom: 20px; font-size: 24px;">Security Analysis Report</h1>
        <p style="color: #333333; margin-bottom: 20px;"><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
        
        <h2 style="color: #1a1a2e; font-size: 18px; margin-top: 25px;">Summary</h2>
        <ul style="color: #333333; padding-left: 20px;">
          <li style="margin-bottom: 8px;"><strong>Language:</strong> ${data.language || 'Unknown'}</li>
          <li style="margin-bottom: 8px;"><strong>Risk Score:</strong> <span style="color: ${data.risk_score > 70 ? '#ef4444' : data.risk_score > 40 ? '#f97316' : '#22c55e'}; font-weight: bold;">${data.risk_score}/100</span></li>
          <li style="margin-bottom: 8px;"><strong>Summary:</strong> ${data.summary || 'No summary available'}</li>
        </ul>
        
        ${data.vulnerabilities?.length > 0 ? `
          <h2 style="color: #1a1a2e; font-size: 18px; margin-top: 25px;">Vulnerabilities (${data.vulnerabilities.length})</h2>
          ${data.vulnerabilities.map((vuln, i) => `
            <div style="background: #f8f9fa; padding: 15px; margin: 15px 0; border-left: 4px solid ${
              vuln.severity === 'critical' ? '#ef4444' : 
              vuln.severity === 'high' ? '#f97316' : 
              vuln.severity === 'medium' ? '#eab308' : '#3b82f6'
            }; border-radius: 4px;">
              <h3 style="margin: 0 0 10px 0; color: #1a1a2e; font-size: 16px;">${i + 1}. ${vuln.type} <span style="color: ${
                vuln.severity === 'critical' ? '#ef4444' : 
                vuln.severity === 'high' ? '#f97316' : 
                vuln.severity === 'medium' ? '#eab308' : '#3b82f6'
              }; font-weight: bold;">[${(vuln.severity || 'unknown').toUpperCase()}]</span></h3>
              <p style="margin: 5px 0; color: #333333;"><strong>Line(s):</strong> ${vuln.line_numbers?.join(', ') || 'N/A'}</p>
              <p style="margin: 5px 0; color: #333333;">${vuln.description || 'No description'}</p>
              ${vuln.fix_suggestion ? `<p style="margin: 10px 0 0 0; color: #166534; background: #dcfce7; padding: 10px; border-radius: 4px;"><strong>Fix:</strong> ${vuln.fix_suggestion}</p>` : ''}
            </div>
          `).join('')}
        ` : '<p style="color: #22c55e; font-weight: bold;">No vulnerabilities found! ✓</p>'}
        
        ${data.recommendations?.length > 0 ? `
          <h2 style="color: #1a1a2e; font-size: 18px; margin-top: 25px;">Recommendations</h2>
          <ul style="color: #333333; padding-left: 20px;">
            ${data.recommendations.map(rec => `<li style="margin-bottom: 8px;">${rec}</li>`).join('')}
          </ul>
        ` : ''}
        
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0 15px 0;">
        <p style="color: #9ca3af; font-size: 12px; text-align: center;">Generated by LLM Code Analyser</p>
      </div>
    `
  }

  // Multi-file markdown report
  const generateMultiFileMarkdownReport = (data) => {
    let md = `# Multi-File Security Analysis Report\n\n`
    md += `**Generated:** ${new Date().toLocaleString()}\n\n`
    md += `## Summary\n\n`
    md += `- **Total Files:** ${data.total_files}\n`
    md += `- **Total Vulnerabilities:** ${data.total_vulnerabilities}\n`
    md += `- **Overall Risk Score:** ${data.overall_risk_score}/100\n`
    md += `- **Summary:** ${data.summary}\n\n`

    md += `## Files Analyzed\n\n`
    data.results?.forEach((fileResult, i) => {
      const { filename, analysis } = fileResult
      md += `### ${i + 1}. ${filename}\n\n`
      md += `- **Risk Score:** ${analysis.risk_score}/100\n`
      md += `- **Vulnerabilities:** ${analysis.vulnerabilities?.length || 0}\n\n`
      
      if (analysis.vulnerabilities?.length > 0) {
        analysis.vulnerabilities.forEach(vuln => {
          md += `  - **${vuln.type}** (${vuln.severity}): ${vuln.description}\n`
        })
        md += `\n`
      }
    })

    md += `\n---\n*Generated by LLM Code Analyser*\n`
    return md
  }

  // Multi-file HTML report
  const generateMultiFileHTMLReport = (data) => {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto;">
        <h1 style="color: #1a1a2e; border-bottom: 3px solid #0ea5e9; padding-bottom: 10px; margin-bottom: 20px; font-size: 24px;">Multi-File Security Analysis Report</h1>
        <p style="color: #333333; margin-bottom: 20px;"><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
        
        <h2 style="color: #1a1a2e; font-size: 18px; margin-top: 25px;">Summary</h2>
        <ul style="color: #333333; padding-left: 20px;">
          <li style="margin-bottom: 8px;"><strong>Total Files:</strong> ${data.total_files || 0}</li>
          <li style="margin-bottom: 8px;"><strong>Total Vulnerabilities:</strong> ${data.total_vulnerabilities || 0}</li>
          <li style="margin-bottom: 8px;"><strong>Overall Risk Score:</strong> <span style="color: ${data.overall_risk_score > 70 ? '#ef4444' : data.overall_risk_score > 40 ? '#f97316' : '#22c55e'}; font-weight: bold;">${data.overall_risk_score}/100</span></li>
        </ul>
        
        <h2 style="color: #1a1a2e; font-size: 18px; margin-top: 25px;">Files Analyzed</h2>
        ${data.results?.map((fileResult, i) => {
          const { filename, analysis } = fileResult
          return `
            <div style="background: #f8f9fa; padding: 15px; margin: 15px 0; border-left: 4px solid ${
              analysis.risk_score >= 70 ? '#ef4444' : 
              analysis.risk_score >= 40 ? '#f97316' : '#22c55e'
            }; border-radius: 4px;">
              <h3 style="margin: 0 0 10px 0; color: #1a1a2e; font-size: 16px;">${i + 1}. ${filename}</h3>
              <p style="margin: 5px 0; color: #333333;"><strong>Risk Score:</strong> ${analysis.risk_score}/100</p>
              <p style="margin: 5px 0; color: #333333;"><strong>Vulnerabilities:</strong> ${analysis.vulnerabilities?.length || 0}</p>
              ${analysis.vulnerabilities?.length > 0 ? `
                <ul style="color: #333333; padding-left: 20px; margin-top: 10px;">
                  ${analysis.vulnerabilities.map(v => `<li style="margin-bottom: 5px;"><strong>${v.type}</strong> (${v.severity}): ${v.description}</li>`).join('')}
                </ul>
              ` : '<p style="color: #22c55e; font-weight: bold; margin-top: 10px;">No vulnerabilities found ✓</p>'}
            </div>
          `
        }).join('')}
        
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0 15px 0;">
        <p style="color: #9ca3af; font-size: 12px; text-align: center;">Generated by LLM Code Analyser</p>
      </div>
    `
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f]">
      {/* Background Effects */}
      <div className="fixed inset-0 bg-grid opacity-30" />
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/5 rounded-full blur-3xl" />
      </div>

      {/* Header */}
      <motion.header
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        className="relative z-10 glass border-b border-white/10"
      >
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3">
              <div className="relative">
                <Shield className="w-8 h-8 text-cyan-400" />
                <Zap className="w-4 h-4 text-purple-400 absolute -bottom-1 -right-1" />
              </div>
              <span className="text-xl font-bold text-gradient">LLM Code Analyser</span>
            </Link>

            <div className="flex items-center gap-4">
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-gray-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="python">Python</option>
                <option value="javascript">JavaScript</option>
                <option value="java">Java</option>
                <option value="c">C/C++</option>
                <option value="php">PHP</option>
                <option value="auto">Auto-detect</option>
              </select>

              <Link
                to="/"
                className="text-gray-400 hover:text-white transition-colors"
              >
                Home
              </Link>
            </div>
          </div>
        </div>
      </motion.header>

      {/* Main Content */}
      <main className="relative z-10 max-w-7xl mx-auto px-6 py-8">
        {/* Mode Toggle */}
        <div className="flex items-center justify-center mb-6">
          <div className="glass rounded-xl p-1 flex gap-1">
            <button
              onClick={() => setMode('single')}
              className={`px-6 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${
                mode === 'single' 
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' 
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <FileCode className="w-4 h-4" />
              Single File
            </button>
            <button
              onClick={() => setMode('multi')}
              className={`px-6 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${
                mode === 'multi' 
                  ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' 
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <FolderOpen className="w-4 h-4" />
              Multi-File
            </button>
          </div>
        </div>

        <div className="grid lg:grid-cols-2 gap-8">
          {/* Left Panel - Code Editor or File Upload */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 }}
            className="space-y-4"
          >
            <AnimatePresence mode="wait">
              {mode === 'single' ? (
                <motion.div
                  key="single"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="space-y-4"
                >
                  <div className="flex items-center justify-between">
                    <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                      <FileCode className="w-5 h-5 text-cyan-400" />
                      Code Input
                    </h2>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={loadSample}
                        className="px-3 py-1.5 text-sm text-gray-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors flex items-center gap-1"
                      >
                        <Upload className="w-4 h-4" />
                        Load Sample
                      </button>
                      <button
                        onClick={clearAll}
                        className="px-3 py-1.5 text-sm text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors flex items-center gap-1"
                      >
                        <Trash2 className="w-4 h-4" />
                        Clear
                      </button>
                    </div>
                  </div>

                  <CodeEditor
                    value={code}
                    onChange={setCode}
                    language={language}
                    highlightedLines={highlightedLines}
                  />

                  {/* Action Buttons */}
                  <div className="flex items-center gap-4">
                    <GlowButton
                      onClick={analyzeCode}
                      loading={isAnalyzing}
                      disabled={!code.trim()}
                      className="flex-1"
                    >
                      <Play className="w-5 h-5" />
                      {isAnalyzing ? 'Analyzing...' : 'Analyze Code'}
                    </GlowButton>

                    {results && (
                      <div className="relative">
                        <motion.button
                          initial={{ opacity: 0, scale: 0.9 }}
                          animate={{ opacity: 1, scale: 1 }}
                          onClick={() => setShowExportMenu(!showExportMenu)}
                          className="px-4 py-3 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl transition-colors flex items-center gap-2 text-gray-300"
                        >
                          <Download className="w-5 h-5" />
                          Export
                        </motion.button>
                        
                        {/* Export Dropdown Menu - opens upward to avoid clipping */}
                        {showExportMenu && (
                          <motion.div
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="absolute right-0 bottom-full mb-2 w-48 glass rounded-xl border border-white/10 py-2 z-[100] shadow-xl"
                          >
                            <button
                              onClick={exportJSON}
                              className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-white/10 flex items-center gap-2"
                            >
                              <FileJson className="w-4 h-4 text-yellow-400" />
                              Export as JSON
                            </button>
                            <button
                              onClick={exportMarkdown}
                              className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-white/10 flex items-center gap-2"
                            >
                              <FileText className="w-4 h-4 text-blue-400" />
                              Export as Markdown
                            </button>
                            <button
                              onClick={exportPDF}
                              className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-white/10 flex items-center gap-2"
                            >
                              <File className="w-4 h-4 text-red-400" />
                              Export as PDF
                            </button>
                          </motion.div>
                        )}
                      </div>
                    )}
                  </div>
                </motion.div>
              ) : (
                <motion.div
                  key="multi"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="space-y-4"
                >
                  <div className="flex items-center justify-between">
                    <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                      <FolderOpen className="w-5 h-5 text-purple-400" />
                      Multi-File Upload
                    </h2>
                    <button
                      onClick={clearAll}
                      className="px-3 py-1.5 text-sm text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors flex items-center gap-1"
                    >
                      <Trash2 className="w-4 h-4" />
                      Clear
                    </button>
                  </div>

                  <div className="glass rounded-xl p-6">
                    <FileUpload onFilesSelected={handleFilesSelected} maxFiles={50} />
                  </div>

                  {/* Action Buttons */}
                  <div className="flex items-center gap-4">
                    <GlowButton
                      onClick={analyzeMultipleFiles}
                      loading={isAnalyzing}
                      disabled={uploadedFiles.length === 0}
                      className="flex-1"
                    >
                      <Play className="w-5 h-5" />
                      {isAnalyzing ? `Analyzing ${uploadedFiles.length} files...` : `Analyze ${uploadedFiles.length} Files`}
                    </GlowButton>

                    {multiFileResults && (
                      <div className="relative">
                        <motion.button
                          initial={{ opacity: 0, scale: 0.9 }}
                          animate={{ opacity: 1, scale: 1 }}
                          onClick={() => setShowExportMenu(!showExportMenu)}
                          className="px-4 py-3 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl transition-colors flex items-center gap-2 text-gray-300"
                        >
                          <Download className="w-5 h-5" />
                          Export
                        </motion.button>
                        
                        {/* Export Dropdown Menu - opens upward to avoid clipping */}
                        {showExportMenu && (
                          <motion.div
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="absolute right-0 bottom-full mb-2 w-48 glass rounded-xl border border-white/10 py-2 z-[100] shadow-xl"
                          >
                            <button
                              onClick={exportJSON}
                              className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-white/10 flex items-center gap-2"
                            >
                              <FileJson className="w-4 h-4 text-yellow-400" />
                              Export as JSON
                            </button>
                            <button
                              onClick={exportMarkdown}
                              className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-white/10 flex items-center gap-2"
                            >
                              <FileText className="w-4 h-4 text-blue-400" />
                              Export as Markdown
                            </button>
                            <button
                              onClick={exportPDF}
                              className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-white/10 flex items-center gap-2"
                            >
                              <File className="w-4 h-4 text-red-400" />
                              Export as PDF
                            </button>
                          </motion.div>
                        )}
                      </div>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Error Display */}
            {error && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-red-500/10 border border-red-500/30 rounded-xl p-4"
              >
                <p className="text-red-400">⚠️ {error}</p>
              </motion.div>
            )}
          </motion.div>

          {/* Right Panel - Results */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
          >
            {mode === 'single' ? (
              // Single file results
              !results && !isAnalyzing ? (
                <div className="glass rounded-xl p-12 text-center h-full flex flex-col items-center justify-center">
                  <motion.div
                    animate={{ 
                      scale: [1, 1.1, 1],
                      rotate: [0, 5, -5, 0]
                    }}
                    transition={{ duration: 4, repeat: Infinity }}
                    className="w-24 h-24 mb-6 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 flex items-center justify-center"
                  >
                    <Shield className="w-12 h-12 text-cyan-400" />
                  </motion.div>
                  <h3 className="text-xl font-semibold text-white mb-2">
                    Ready to Analyze
                  </h3>
                  <p className="text-gray-400 max-w-sm">
                    Paste your code in the editor and click "Analyze Code" to detect security vulnerabilities.
                  </p>
                  <div className="mt-6 flex flex-wrap gap-2 justify-center">
                    {['SQL Injection', 'XSS', 'Command Injection', 'Hardcoded Secrets'].map((tag) => (
                      <span key={tag} className="px-3 py-1 bg-white/5 text-gray-500 rounded-full text-sm">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              ) : (
                <ResultsPanel results={results} isLoading={isAnalyzing} />
              )
            ) : (
              // Multi-file results
              !multiFileResults && !isAnalyzing ? (
                <div className="glass rounded-xl p-12 text-center h-full flex flex-col items-center justify-center">
                  <motion.div
                    animate={{ 
                      scale: [1, 1.1, 1],
                      rotate: [0, 5, -5, 0]
                    }}
                    transition={{ duration: 4, repeat: Infinity }}
                    className="w-24 h-24 mb-6 rounded-2xl bg-gradient-to-br from-purple-500/20 to-cyan-500/20 flex items-center justify-center"
                  >
                    <FolderOpen className="w-12 h-12 text-purple-400" />
                  </motion.div>
                  <h3 className="text-xl font-semibold text-white mb-2">
                    Multi-File Analysis
                  </h3>
                  <p className="text-gray-400 max-w-sm">
                    Upload multiple code files or a ZIP archive to analyze your entire project for security vulnerabilities.
                  </p>
                  <div className="mt-6 flex flex-wrap gap-2 justify-center">
                    {['.py', '.js', '.java', '.c', '.php', '.zip'].map((ext) => (
                      <span key={ext} className="px-3 py-1 bg-white/5 text-gray-500 rounded-full text-sm">
                        {ext}
                      </span>
                    ))}
                  </div>
                </div>
              ) : (
                <MultiFileResults results={multiFileResults} isLoading={isAnalyzing} />
              )
            )}
          </motion.div>
        </div>

        {/* Scanning Animation Overlay */}
        {isAnalyzing && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 pointer-events-none z-50"
          >
            <motion.div
              className="absolute left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-cyan-500 to-transparent"
              animate={{ top: ['0%', '100%'] }}
              transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
            />
            {/* Analysis stage indicator */}
            <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 pointer-events-auto">
              <motion.div 
                initial={{ y: 20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                className="glass px-6 py-3 rounded-full border border-cyan-500/30 flex items-center gap-3"
              >
                <motion.div 
                  className="w-2 h-2 rounded-full bg-cyan-400"
                  animate={{ scale: [1, 1.5, 1], opacity: [1, 0.5, 1] }}
                  transition={{ duration: 1, repeat: Infinity }}
                />
                <span className="text-cyan-400 text-sm font-medium">{analysisStage}</span>
              </motion.div>
            </div>
          </motion.div>
        )}
      </main>

      {/* Footer */}
      <footer className="relative z-10 border-t border-white/10 mt-12 py-6 px-6">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-gray-500">
          <p>LLM Code Analyser — AI-Powered Code Security Analysis</p>
          <p>Hybrid Analysis: LLM + Static Rules</p>
        </div>
      </footer>
    </div>
  )
}

export default Dashboard
