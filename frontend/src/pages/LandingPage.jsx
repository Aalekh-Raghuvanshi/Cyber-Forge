import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { Shield, GitCompare, Code2, Globe, Sparkles, ArrowRight, CheckCircle2, Zap, Layers } from 'lucide-react'
import Navbar from '../components/Navbar'
import GlowButton from '../components/GlowButton'

const LandingPage = () => {
  const pillars = [
    {
      icon: Code2,
      title: 'Deterministic SAST',
      description: 'Semgrep CLI engine & Python AST patterns covering canonical CWE-89, CWE-79, CWE-22, CWE-78, CWE-798, and CWE-328.',
      tag: 'FR-1 Code Analysis'
    },
    {
      icon: Globe,
      title: 'OWASP ZAP DAST Ingestion',
      description: 'Mode A live daemon integration or Mode B JSON/SARIF ingestion to verify exploitability on active endpoints.',
      tag: 'FR-2 Runtime Proof'
    },
    {
      icon: GitCompare,
      title: 'AST Route-to-Code Correlation',
      description: 'Extracts exact handler lines and maps URL paths to source code. Merges duplicates and ranks Confirmed issues first.',
      tag: 'FR-4 & FR-5 Core Engine'
    },
    {
      icon: Sparkles,
      title: 'Sandboxed LLM Remediation',
      description: 'Strict temperature=0.0 Groq (Llama-3.3-70B) or Ollama (CodeLlama) remediation generator with deterministic template fallbacks.',
      tag: 'Zero-Hallucination AI'
    }
  ]

  const metrics = [
    { label: 'Confirmed Issues', value: 'Rank #1', desc: 'Matched across SAST & DAST' },
    { label: 'Correlation Logic', value: 'Deterministic', desc: 'Zero LLM guesswork or hallucinations' },
    { label: 'LLM Execution', value: 'Groq / Ollama', desc: 'Online cloud & offline local modes' },
    { label: 'Storage Layer', value: 'SQLite Upsert', desc: 'Idempotent deduplication via issue hash' }
  ]

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white overflow-hidden">
      {/* Background Grid & Glows */}
      <div className="fixed inset-0 bg-grid opacity-30 pointer-events-none" />
      <div className="fixed top-1/4 left-1/3 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="fixed bottom-1/4 right-1/3 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl pointer-events-none" />

      <Navbar />

      {/* Hero Section */}
      <section className="relative pt-32 pb-16 px-6 max-w-6xl mx-auto text-center">
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-xs font-mono text-cyan-300 mb-6"
        >
          <Zap className="w-3.5 h-3.5 text-cyan-400" />
          <span>Next-Gen AppSec: SAST + DAST Correlation Engine</span>
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="text-4xl sm:text-6xl font-extrabold tracking-tight mb-6 max-w-4xl mx-auto leading-tight"
        >
          Bridge Static Code & Runtime Flaws into <span className="text-gradient">Confirmed Exploits</span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="text-base sm:text-lg text-gray-400 max-w-2xl mx-auto mb-8 leading-relaxed"
        >
          Eliminate alert fatigue. Cyber-Forge uses Python AST route mapping to tie OWASP ZAP dynamic runtime alerts directly to physical source code line numbers, deduplicating alerts and ranking confirmed vulnerabilities first.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="flex flex-wrap items-center justify-center gap-4"
        >
          <Link to="/dashboard">
            <GlowButton size="lg">
              Launch Correlation Studio
              <ArrowRight className="w-4 h-4 ml-1" />
            </GlowButton>
          </Link>
          <a
            href="/docs"
            target="_blank"
            rel="noreferrer"
            className="px-6 py-3 rounded-xl border border-white/10 hover:border-white/20 bg-white/5 text-gray-300 hover:text-white transition-all text-sm font-semibold font-mono"
          >
            Explore REST API
          </a>
        </motion.div>

        {/* Metrics Strip */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-16 text-left"
        >
          {metrics.map((m, idx) => (
            <div key={idx} className="p-4 rounded-xl bg-white/[0.03] border border-white/10 font-mono">
              <div className="text-xl font-bold text-white mb-1">{m.value}</div>
              <div className="text-xs text-cyan-400 font-semibold mb-1">{m.label}</div>
              <div className="text-[11px] text-gray-500">{m.desc}</div>
            </div>
          ))}
        </motion.div>
      </section>

      {/* Core Architectural Pillars */}
      <section className="relative py-12 px-6 max-w-6xl mx-auto">
        <div className="text-center mb-10">
          <h2 className="text-2xl font-bold text-white tracking-tight mb-2">Engine Architecture</h2>
          <p className="text-sm text-gray-400 font-mono">Deterministic correlation pipeline built for AppSec teams</p>
        </div>

        <div className="grid md:grid-cols-2 gap-5">
          {pillars.map((p, idx) => {
            const Icon = p.icon
            return (
              <div
                key={idx}
                className="p-6 rounded-2xl bg-white/[0.02] border border-white/10 hover:border-cyan-500/30 transition-all group"
              >
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                    <Icon className="w-5 h-5" />
                  </div>
                  <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-white/5 border border-white/10 text-gray-400">
                    {p.tag}
                  </span>
                </div>
                <h3 className="text-lg font-bold text-white mb-2 group-hover:text-cyan-300 transition-colors">
                  {p.title}
                </h3>
                <p className="text-sm text-gray-400 leading-relaxed">
                  {p.description}
                </p>
              </div>
            )
          })}
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 border-t border-white/5 text-center text-xs text-gray-500 font-mono">
        Cyber-Forge Engine • Deterministic SAST + DAST Correlation • Zero-Hallucination AppSec
      </footer>
    </div>
  )
}

export default LandingPage
