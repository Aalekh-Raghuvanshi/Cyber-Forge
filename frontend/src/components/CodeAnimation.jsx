import { motion } from 'framer-motion'
import { useState, useEffect, useMemo } from 'react'

const CodeAnimation = () => {
  const [currentLine, setCurrentLine] = useState(0)
  
  const codeLines = useMemo(() => [
    'def process_user_input(data):',
    '    query = "SELECT * FROM users"',
    '    query += " WHERE id = " + data',
    '    return db.execute(query)',
    '',
    'def run_command(cmd):',
    '    os.system(cmd)  # Danger!',
    '    return result'
  ], [])

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentLine((prev) => (prev + 1) % codeLines.length)
    }, 800)
    return () => clearInterval(interval)
  }, [codeLines.length])

  return (
    <div className="relative w-full max-w-lg">
      {/* Main Code Block */}
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.8 }}
        className="glass rounded-xl p-6 font-mono text-sm relative overflow-hidden"
      >
        {/* Scan Line */}
        <motion.div
          className="absolute left-0 right-0 h-8 bg-gradient-to-b from-cyan-500/20 to-transparent pointer-events-none"
          animate={{ top: ['0%', '100%'] }}
          transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
        />
        
        {/* Code Lines */}
        <div className="relative z-10">
          {codeLines.map((line, idx) => (
            <motion.div
              key={idx}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: idx * 0.1 }}
              className={`
                py-1 px-2 rounded transition-all duration-300
                ${currentLine === idx ? 'bg-red-500/20 text-red-400' : 'text-gray-400'}
                ${line.includes('Danger') || line.includes('+ data') ? 'border-l-2 border-red-500' : ''}
              `}
            >
              <span className="text-gray-600 mr-4">{idx + 1}</span>
              <span className={line.includes('#') ? 'text-gray-500' : ''}>
                {line || '\u00A0'}
              </span>
            </motion.div>
          ))}
        </div>

        {/* Vulnerability Badge */}
        <motion.div
          initial={{ opacity: 0, scale: 0 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 1, type: 'spring' }}
          className="absolute top-4 right-4 px-3 py-1 bg-red-500/20 border border-red-500 rounded-full text-red-400 text-xs font-semibold"
        >
          🚨 3 Vulnerabilities
        </motion.div>
      </motion.div>

      {/* Floating Elements */}
      <motion.div
        animate={{ 
          y: [0, -10, 0],
          rotate: [0, 5, 0]
        }}
        transition={{ duration: 4, repeat: Infinity }}
        className="absolute -top-8 -right-8 w-16 h-16 bg-gradient-to-br from-purple-500/30 to-pink-500/30 rounded-full blur-xl"
      />
      <motion.div
        animate={{ 
          y: [0, 10, 0],
          rotate: [0, -5, 0]
        }}
        transition={{ duration: 3, repeat: Infinity }}
        className="absolute -bottom-8 -left-8 w-20 h-20 bg-gradient-to-br from-cyan-500/30 to-blue-500/30 rounded-full blur-xl"
      />

      {/* Shield Icon */}
      <motion.div
        initial={{ opacity: 0, scale: 0 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 1.5, type: 'spring' }}
        className="absolute -right-12 top-1/2 -translate-y-1/2"
      >
        <motion.div
          animate={{ scale: [1, 1.1, 1] }}
          transition={{ duration: 2, repeat: Infinity }}
          className="w-24 h-24 bg-gradient-to-br from-cyan-500 to-purple-500 rounded-2xl flex items-center justify-center neon-glow-blue"
        >
          <svg className="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </motion.div>
      </motion.div>
    </div>
  )
}

export default CodeAnimation
