import { motion } from 'framer-motion'

// eslint-disable-next-line no-unused-vars
const FeatureCard = ({ icon: IconComponent, title, description, color, delay = 0 }) => {
  const colorClasses = {
    cyan: {
      bg: 'from-cyan-500/20 to-cyan-500/5',
      border: 'border-cyan-500/30',
      icon: 'text-cyan-400',
      glow: 'group-hover:neon-glow-blue'
    },
    purple: {
      bg: 'from-purple-500/20 to-purple-500/5',
      border: 'border-purple-500/30',
      icon: 'text-purple-400',
      glow: 'group-hover:neon-glow-purple'
    },
    green: {
      bg: 'from-green-500/20 to-green-500/5',
      border: 'border-green-500/30',
      icon: 'text-green-400',
      glow: 'group-hover:neon-glow-green'
    },
    pink: {
      bg: 'from-pink-500/20 to-pink-500/5',
      border: 'border-pink-500/30',
      icon: 'text-pink-400',
      glow: ''
    }
  }

  const colors = colorClasses[color] || colorClasses.cyan

  return (
    <motion.div
      initial={{ opacity: 0, y: 30 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.5, delay }}
      whileHover={{ y: -8, scale: 1.02 }}
      className={`group glass rounded-2xl p-6 border ${colors.border} ${colors.glow} transition-all duration-300 cursor-pointer`}
    >
      <div className={`w-14 h-14 rounded-xl bg-gradient-to-br ${colors.bg} flex items-center justify-center mb-4`}>
        <IconComponent className={`w-7 h-7 ${colors.icon}`} />
      </div>
      
      <h3 className="text-xl font-semibold text-white mb-2">
        {title}
      </h3>
      
      <p className="text-gray-400 leading-relaxed">
        {description}
      </p>

      <motion.div
        initial={{ width: 0 }}
        whileHover={{ width: '100%' }}
        className={`h-0.5 bg-gradient-to-r ${colors.bg.replace('/20', '')} mt-4 rounded-full`}
      />
    </motion.div>
  )
}

export default FeatureCard
