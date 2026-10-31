import { motion } from 'framer-motion'

const GlassCard = ({ 
  children, 
  className = '', 
  hover = true,
  glow = null,
  delay = 0 
}) => {
  const glowClasses = {
    blue: 'hover:neon-glow-blue',
    purple: 'hover:neon-glow-purple',
    green: 'hover:neon-glow-green'
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.5, delay }}
      whileHover={hover ? { y: -5, scale: 1.02 } : {}}
      className={`
        glass rounded-2xl p-6
        transition-all duration-300
        ${glow ? glowClasses[glow] : ''}
        ${className}
      `}
    >
      {children}
    </motion.div>
  )
}

export default GlassCard
