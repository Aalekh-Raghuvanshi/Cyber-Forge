import { motion } from 'framer-motion'

const GlowButton = ({ 
  children, 
  onClick, 
  variant = 'primary', 
  size = 'md',
  loading = false,
  disabled = false,
  className = ''
}) => {
  const variants = {
    primary: 'from-cyan-500 to-purple-500 hover:from-cyan-400 hover:to-purple-400',
    secondary: 'from-gray-700 to-gray-600 hover:from-gray-600 hover:to-gray-500',
    danger: 'from-red-500 to-orange-500 hover:from-red-400 hover:to-orange-400',
    success: 'from-green-500 to-emerald-500 hover:from-green-400 hover:to-emerald-400'
  }

  const sizes = {
    sm: 'px-4 py-2 text-sm',
    md: 'px-6 py-3 text-base',
    lg: 'px-8 py-4 text-lg'
  }

  return (
    <motion.button
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      disabled={disabled || loading}
      className={`
        relative bg-gradient-to-r ${variants[variant]} ${sizes[size]}
        rounded-xl font-semibold text-white
        shadow-lg transition-all duration-300
        disabled:opacity-50 disabled:cursor-not-allowed
        btn-ripple overflow-hidden
        ${variant === 'primary' ? 'neon-glow-blue' : ''}
        ${className}
      `}
    >
      <span className={`flex items-center justify-center gap-2 ${loading ? 'opacity-0' : ''}`}>
        {children}
      </span>
      {loading && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full spinner" />
        </div>
      )}
    </motion.button>
  )
}

export default GlowButton
