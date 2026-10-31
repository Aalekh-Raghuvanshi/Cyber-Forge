import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle, Shield, GitBranch, CheckCircle, ChevronDown, ChevronUp, Copy, Check } from 'lucide-react'
import { useState } from 'react'

const ResultsPanel = ({ results, isLoading, compact = false }) => {
  const [expandedVuln, setExpandedVuln] = useState(null)
  const [activeTab, setActiveTab] = useState('vulnerabilities')
  const [copiedIdx, setCopiedIdx] = useState(null)

  const copyToClipboard = async (text, idx) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedIdx(idx)
      setTimeout(() => setCopiedIdx(null), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  if (isLoading) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="glass rounded-xl p-8"
      >
        <div className="flex flex-col items-center justify-center py-12">
          <div className="relative">
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
              className="w-16 h-16 border-4 border-cyan-500/30 border-t-cyan-500 rounded-full"
            />
            <Shield className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <motion.p
            animate={{ opacity: [1, 0.5, 1] }}
            transition={{ duration: 1.5, repeat: Infinity }}
            className="mt-6 text-gray-400"
          >
            Scanning code for vulnerabilities...
          </motion.p>
        </div>
      </motion.div>
    )
  }

  if (!results) return null

  const severityColors = {
    critical: { bg: 'bg-red-500/20', border: 'border-red-500', text: 'text-red-400', badge: 'bg-red-500' },
    high: { bg: 'bg-orange-500/20', border: 'border-orange-500', text: 'text-orange-400', badge: 'bg-orange-500' },
    medium: { bg: 'bg-yellow-500/20', border: 'border-yellow-500', text: 'text-yellow-400', badge: 'bg-yellow-500' },
    low: { bg: 'bg-green-500/20', border: 'border-green-500', text: 'text-green-400', badge: 'bg-green-500' }
  }

  const getRiskColor = (score) => {
    if (score >= 75) return 'text-red-400'
    if (score >= 50) return 'text-orange-400'
    if (score >= 25) return 'text-yellow-400'
    return 'text-green-400'
  }

  // Compact mode for multi-file view - show only vulnerabilities summary
  if (compact) {
    return (
      <div className="space-y-2">
        {results.vulnerabilities?.length === 0 ? (
          <div className="flex items-center gap-2 text-green-400 text-sm">
            <CheckCircle className="w-4 h-4" />
            No vulnerabilities detected
          </div>
        ) : (
          <div className="space-y-2">
            {results.vulnerabilities?.slice(0, 3).map((vuln, idx) => {
              const colors = severityColors[vuln.severity] || severityColors.medium
              return (
                <div
                  key={idx}
                  className={`text-sm p-2 rounded border-l-2 ${colors.border} ${colors.bg}`}
                >
                  <div className="flex items-center gap-2">
                    <span className={`${colors.text} font-medium`}>{vuln.type}</span>
                    {vuln.line_numbers?.length > 0 && (
                      <span className="text-gray-500 text-xs">L{vuln.line_numbers[0]}</span>
                    )}
                  </div>
                </div>
              )
            })}
            {results.vulnerabilities?.length > 3 && (
              <p className="text-xs text-gray-500">
                +{results.vulnerabilities.length - 3} more issues
              </p>
            )}
          </div>
        )}
        {results.recommendations?.length > 0 && (
          <p className="text-xs text-gray-500 mt-2">
            {results.recommendations.length} recommendation{results.recommendations.length > 1 ? 's' : ''}
          </p>
        )}
      </div>
    )
  }

  const tabs = [
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: AlertTriangle, count: results.vulnerabilities?.length || 0 },
    { id: 'attack_surfaces', label: 'Attack Surfaces', icon: Shield, count: results.attack_surfaces?.length || 0 },
    { id: 'trust_boundaries', label: 'Trust Boundaries', icon: GitBranch, count: results.trust_boundaries?.length || 0 },
    { id: 'recommendations', label: 'Recommendations', icon: CheckCircle, count: results.recommendations?.length || 0 }
  ]

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass rounded-xl overflow-hidden"
    >
      {/* Header */}
      <div className="p-6 border-b border-white/10">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xl font-semibold text-white">Analysis Results</h3>
            <p className="text-gray-400 text-sm mt-1">{results.summary}</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-sm text-gray-500">Risk Score</p>
              <p className={`text-3xl font-bold ${getRiskColor(results.risk_score)}`}>
                {results.risk_score}
              </p>
            </div>
            <div className={`w-16 h-16 rounded-xl ${
              results.risk_score >= 50 ? 'bg-red-500/20' : 'bg-green-500/20'
            } flex items-center justify-center`}>
              {results.risk_score >= 50 ? (
                <AlertTriangle className="w-8 h-8 text-red-400" />
              ) : (
                <CheckCircle className="w-8 h-8 text-green-400" />
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-white/10 overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-6 py-4 text-sm font-medium transition-all whitespace-nowrap ${
              activeTab === tab.id
                ? 'text-cyan-400 border-b-2 border-cyan-400 bg-cyan-500/5'
                : 'text-gray-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
            {tab.count > 0 && (
              <span className={`px-2 py-0.5 rounded-full text-xs ${
                activeTab === tab.id ? 'bg-cyan-500/20' : 'bg-white/10'
              }`}>
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="p-6 max-h-[500px] overflow-y-auto">
        <AnimatePresence mode="wait">
          {activeTab === 'vulnerabilities' && (
            <motion.div
              key="vulnerabilities"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="space-y-4"
            >
              {results.vulnerabilities?.length === 0 ? (
                <div className="text-center py-8">
                  <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-4" />
                  <p className="text-green-400 font-medium">No vulnerabilities detected!</p>
                </div>
              ) : (
                results.vulnerabilities?.map((vuln, idx) => {
                  const colors = severityColors[vuln.severity] || severityColors.medium
                  const isExpanded = expandedVuln === idx

                  return (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: idx * 0.1 }}
                      className={`rounded-xl border ${colors.border} ${colors.bg} overflow-hidden`}
                    >
                      <button
                        onClick={() => setExpandedVuln(isExpanded ? null : idx)}
                        className="w-full p-4 flex items-center justify-between text-left"
                      >
                        <div className="flex items-center gap-3">
                          <span className={`px-2 py-1 rounded text-xs font-bold uppercase ${colors.badge} text-white`}>
                            {vuln.severity}
                          </span>
                          <span className="font-medium text-white">{vuln.type}</span>
                          {vuln.line_numbers?.length > 0 && (
                            <span className="text-sm text-gray-500">
                              Line {vuln.line_numbers.join(', ')}
                            </span>
                          )}
                        </div>
                        {isExpanded ? (
                          <ChevronUp className="w-5 h-5 text-gray-400" />
                        ) : (
                          <ChevronDown className="w-5 h-5 text-gray-400" />
                        )}
                      </button>

                      <AnimatePresence>
                        {isExpanded && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="border-t border-white/10"
                          >
                            <div className="p-4 space-y-4">
                              <p className="text-gray-300">{vuln.description}</p>

                              {vuln.vulnerable_code && (
                                <div>
                                  <p className="text-sm text-gray-500 mb-2">Vulnerable Code:</p>
                                  <pre className="bg-black/30 p-3 rounded-lg text-red-300 text-sm font-mono overflow-x-auto">
                                    {vuln.vulnerable_code}
                                  </pre>
                                </div>
                              )}

                              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                                <p className="text-green-400 font-medium mb-2">💡 Fix Suggestion:</p>
                                <p className="text-gray-300 text-sm">{vuln.fix_suggestion}</p>
                              </div>

                              {vuln.fixed_code && (
                                <div>
                                  <div className="flex items-center justify-between mb-2">
                                    <p className="text-sm text-gray-500">Fixed Code:</p>
                                    <button
                                      onClick={() => copyToClipboard(vuln.fixed_code, `fixed-${idx}`)}
                                      className="flex items-center gap-1.5 px-2 py-1 text-xs bg-green-500/20 hover:bg-green-500/30 text-green-400 rounded transition-colors"
                                    >
                                      {copiedIdx === `fixed-${idx}` ? (
                                        <>
                                          <Check className="w-3 h-3" />
                                          Copied!
                                        </>
                                      ) : (
                                        <>
                                          <Copy className="w-3 h-3" />
                                          Copy Fix
                                        </>
                                      )}
                                    </button>
                                  </div>
                                  <pre className="bg-black/30 p-3 rounded-lg text-green-300 text-sm font-mono overflow-x-auto">
                                    {vuln.fixed_code}
                                  </pre>
                                </div>
                              )}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  )
                })
              )}
            </motion.div>
          )}

          {activeTab === 'attack_surfaces' && (
            <motion.div
              key="attack_surfaces"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="space-y-4"
            >
              {results.attack_surfaces?.map((surface, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.1 }}
                  className="bg-white/5 rounded-xl p-4 border border-white/10"
                >
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-medium text-white">{surface.name}</h4>
                    <span className={`px-2 py-1 rounded text-xs ${
                      surface.risk_level === 'high' ? 'bg-red-500/20 text-red-400' :
                      surface.risk_level === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      {surface.risk_level}
                    </span>
                  </div>
                  <p className="text-sm text-cyan-400 mb-2">{surface.type}</p>
                  <p className="text-gray-400 text-sm">{surface.description}</p>
                </motion.div>
              ))}
            </motion.div>
          )}

          {activeTab === 'trust_boundaries' && (
            <motion.div
              key="trust_boundaries"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="space-y-4"
            >
              {results.trust_boundaries?.map((boundary, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.1 }}
                  className="bg-white/5 rounded-xl p-4 border border-purple-500/30"
                >
                  <h4 className="font-medium text-white mb-2">{boundary.name}</h4>
                  <p className="text-gray-400 text-sm mb-3">{boundary.description}</p>
                  {boundary.components?.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {boundary.components.map((comp, i) => (
                        <span key={i} className="px-2 py-1 bg-purple-500/20 text-purple-300 rounded text-xs">
                          {comp}
                        </span>
                      ))}
                    </div>
                  )}
                </motion.div>
              ))}
            </motion.div>
          )}

          {activeTab === 'recommendations' && (
            <motion.div
              key="recommendations"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="space-y-3"
            >
              {results.recommendations?.map((rec, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.1 }}
                  className="flex items-start gap-3 bg-white/5 rounded-xl p-4 border border-white/10"
                >
                  <CheckCircle className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <p className="text-gray-300">{rec}</p>
                </motion.div>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  )
}

export default ResultsPanel
