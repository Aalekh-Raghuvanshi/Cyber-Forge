import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { Shield, Zap } from 'lucide-react'

const Navbar = () => {
  return (
    <motion.nav
      initial={{ y: -100, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6 }}
      className="fixed top-0 left-0 right-0 z-50 glass"
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

          <div className="flex items-center gap-6">
            <Link
              to="/"
              className="text-gray-400 hover:text-white transition-colors"
            >
              Home
            </Link>
            <Link
              to="/dashboard"
              className="text-gray-400 hover:text-white transition-colors"
            >
              Analyzer
            </Link>
          </div>
        </div>
      </div>
    </motion.nav>
  )
}

export default Navbar
