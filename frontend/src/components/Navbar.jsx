import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Link, useLocation } from 'react-router-dom'
import { Shield, Cpu, Activity, ExternalLink } from 'lucide-react'

const Navbar = () => {
  const location = useLocation()
  const [config, setConfig] = useState(null)
  const [health, setHealth] = useState('online')

  useEffect(() => {
    // Fetch engine config & health
    fetch('/api/config')
      .then(res => res.json())
      .then(data => setConfig(data))
      .catch(() => setConfig(null))

    fetch('/api/health')
      .then(res => res.json())
      .then(data => setHealth(data.status === 'healthy' ? 'online' : 'degraded'))
      .catch(() => setHealth('offline'))
  }, [])

  return (
    <motion.nav
      initial={{ y: -50, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.4 }}
      className="fixed top-0 left-0 right-0 z-50 bg-[#0a0a0f]/80 backdrop-blur-md border-b border-white/10"
    >
      <div className="max-w-7xl mx-auto px-6 py-3.5">
        <div className="flex items-center justify-between">
          {/* Logo & Brand */}
          <Link to="/" className="flex items-center gap-3 group">
            <div className="relative p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 group-hover:border-cyan-500/50 transition-colors">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold tracking-tight text-white">Cyber-Forge</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                  SAST + DAST
                </span>
              </div>
              <p className="text-[11px] text-gray-400 font-mono">Correlation & Prioritization</p>
            </div>
          </Link>

          {/* Engine Status & Links */}
          <div className="flex items-center gap-5">
            {/* LLM Engine Badge */}
            <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-xs font-mono">
              <Cpu className="w-3.5 h-3.5 text-purple-400" />
              <span className="text-gray-400">LLM:</span>
              <span className="text-purple-300 font-semibold uppercase">
                {config?.llm_mode || 'GROQ'}
              </span>
              <span className="text-gray-500">|</span>
              <span className="text-gray-400 truncate max-w-[130px]">
                {config?.model || 'llama-3.3-70b'}
              </span>
              <span className={`w-2 h-2 rounded-full ${health === 'online' ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            </div>

            {/* Navigation Links */}
            <div className="flex items-center gap-2 font-mono text-xs">
              <Link
                to="/"
                className={`px-3 py-1.5 rounded-lg transition-colors ${
                  location.pathname === '/' ? 'bg-white/10 text-white' : 'text-gray-400 hover:text-white'
                }`}
              >
                Overview
              </Link>
              <Link
                to="/dashboard"
                className={`px-3 py-1.5 rounded-lg transition-colors ${
                  location.pathname === '/dashboard' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-gray-400 hover:text-white'
                }`}
              >
                Correlation Studio
              </Link>
              <a
                href="/docs"
                target="_blank"
                rel="noreferrer"
                className="hidden md:flex items-center gap-1 px-3 py-1.5 rounded-lg text-gray-400 hover:text-white transition-colors"
              >
                API Docs
                <ExternalLink className="w-3 h-3 opacity-60" />
              </a>
            </div>
          </div>
        </div>
      </div>
    </motion.nav>
  )
}

export default Navbar
