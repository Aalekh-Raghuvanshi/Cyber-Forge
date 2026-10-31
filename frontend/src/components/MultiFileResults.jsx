import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { FileCode, ChevronDown, ChevronRight, AlertTriangle, CheckCircle, XCircle, Shield } from 'lucide-react'
import ResultsPanel from './ResultsPanel'

const MultiFileResults = ({ results, isLoading }) => {
  const [expandedFile, setExpandedFile] = useState(null)

  if (isLoading) {
    return (
      <div className="glass rounded-xl p-8 h-full flex flex-col items-center justify-center">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
          className="w-16 h-16 border-3 border-cyan-400 border-t-transparent rounded-full mb-4"
        />
        <p className="text-gray-400">Analyzing multiple files...</p>
      </div>
    )
  }

  if (!results) return null

  const { total_files, total_vulnerabilities, overall_risk_score, summary, results: fileResults } = results

  // Sort files by risk score (highest first)
  const sortedResults = [...fileResults].sort((a, b) => 
    (b.analysis?.risk_score || 0) - (a.analysis?.risk_score || 0)
  )

  const getRiskColor = (score) => {
    if (score >= 70) return 'text-red-400'
    if (score >= 40) return 'text-orange-400'
    if (score >= 20) return 'text-yellow-400'
    return 'text-green-400'
  }

  const getRiskBg = (score) => {
    if (score >= 70) return 'bg-red-500/20 border-red-500/30'
    if (score >= 40) return 'bg-orange-500/20 border-orange-500/30'
    if (score >= 20) return 'bg-yellow-500/20 border-yellow-500/30'
    return 'bg-green-500/20 border-green-500/30'
  }

  return (
    <div className="glass rounded-xl overflow-hidden h-full flex flex-col">
      {/* Summary Header */}
      <div className="p-4 border-b border-white/10">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            Multi-File Analysis
          </h3>
          <div className={`px-3 py-1 rounded-full text-sm font-medium ${getRiskBg(overall_risk_score)}`}>
            <span className={getRiskColor(overall_risk_score)}>
              Risk: {overall_risk_score}/100
            </span>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-white/5 rounded-lg p-3 text-center">
            <p className="text-2xl font-bold text-cyan-400">{total_files}</p>
            <p className="text-xs text-gray-500">Files</p>
          </div>
          <div className="bg-white/5 rounded-lg p-3 text-center">
            <p className={`text-2xl font-bold ${total_vulnerabilities > 0 ? 'text-red-400' : 'text-green-400'}`}>
              {total_vulnerabilities}
            </p>
            <p className="text-xs text-gray-500">Issues</p>
          </div>
          <div className="bg-white/5 rounded-lg p-3 text-center">
            <p className={`text-2xl font-bold ${getRiskColor(overall_risk_score)}`}>
              {overall_risk_score >= 70 ? 'High' : overall_risk_score >= 40 ? 'Medium' : 'Low'}
            </p>
            <p className="text-xs text-gray-500">Risk Level</p>
          </div>
        </div>

        <p className="text-sm text-gray-400 mt-3">{summary}</p>
      </div>

      {/* File List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2">
        {sortedResults.map((fileResult, index) => {
          const { filename, analysis } = fileResult
          const isExpanded = expandedFile === index
          const vulnCount = analysis?.vulnerabilities?.length || 0
          const riskScore = analysis?.risk_score || 0
          const hasError = !analysis?.success

          return (
            <motion.div
              key={`${filename}-${index}`}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
              className="rounded-lg overflow-hidden"
            >
              {/* File Header */}
              <button
                onClick={() => setExpandedFile(isExpanded ? null : index)}
                className={`w-full p-3 flex items-center justify-between transition-colors ${
                  isExpanded ? 'bg-white/10' : 'bg-white/5 hover:bg-white/10'
                }`}
              >
                <div className="flex items-center gap-3 min-w-0">
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0" />
                  )}
                  <FileCode className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                  <span className="text-sm text-gray-300 truncate" title={filename}>
                    {filename}
                  </span>
                </div>

                <div className="flex items-center gap-3 flex-shrink-0">
                  {hasError ? (
                    <XCircle className="w-4 h-4 text-red-400" />
                  ) : vulnCount > 0 ? (
                    <span className="flex items-center gap-1 text-xs">
                      <AlertTriangle className="w-3 h-3 text-orange-400" />
                      <span className="text-orange-400">{vulnCount}</span>
                    </span>
                  ) : (
                    <CheckCircle className="w-4 h-4 text-green-400" />
                  )}
                  
                  <div className={`px-2 py-0.5 rounded text-xs font-medium ${
                    riskScore >= 70 ? 'bg-red-500/20 text-red-400' :
                    riskScore >= 40 ? 'bg-orange-500/20 text-orange-400' :
                    riskScore >= 20 ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-green-500/20 text-green-400'
                  }`}>
                    {riskScore}
                  </div>
                </div>
              </button>

              {/* Expanded Details */}
              <AnimatePresence>
                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="overflow-hidden"
                  >
                    <div className="p-3 bg-black/20 border-t border-white/5">
                      {hasError ? (
                        <div className="text-sm text-red-400">
                          {analysis?.error || analysis?.summary || 'Analysis failed'}
                        </div>
                      ) : (
                        <ResultsPanel results={analysis} isLoading={false} compact />
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}

export default MultiFileResults
