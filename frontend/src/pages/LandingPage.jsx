import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { Shield, Target, GitBranch, AlertTriangle, Sparkles, ArrowRight, Code, Lock, Zap } from 'lucide-react'
import Navbar from '../components/Navbar'
import FeatureCard from '../components/FeatureCard'
import CodeAnimation from '../components/CodeAnimation'
import GlowButton from '../components/GlowButton'

const LandingPage = () => {
  const features = [
    {
      icon: Target,
      title: 'Attack Surface Detection',
      description: 'Automatically identify all entry points where external data enters your application, from API endpoints to user inputs.',
      color: 'cyan'
    },
    {
      icon: GitBranch,
      title: 'Trust Boundary Analysis',
      description: 'Map data flows across security boundaries to understand where untrusted data interacts with sensitive systems.',
      color: 'purple'
    },
    {
      icon: AlertTriangle,
      title: 'Vulnerability Detection',
      description: 'Deep analysis using AI to find SQL injection, XSS, command injection, and 20+ other vulnerability types.',
      color: 'pink'
    },
    {
      icon: Sparkles,
      title: 'Auto Fix Suggestions',
      description: 'Get AI-generated secure code patches with explanations, ready to implement in your codebase.',
      color: 'green'
    }
  ]

  const stats = [
    { value: '50+', label: 'Vulnerability Types' },
    { value: '99%', label: 'Detection Rate' },
    { value: '<5s', label: 'Analysis Time' },
    { value: '24/7', label: 'Available' }
  ]

  return (
    <div className="min-h-screen bg-[#0a0a0f] overflow-hidden">
      {/* Background Effects */}
      <div className="fixed inset-0 bg-grid opacity-50" />
      <div className="fixed inset-0">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl" />
      </div>

      <Navbar />

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            {/* Left Content */}
            <motion.div
              initial={{ opacity: 0, x: -50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8 }}
            >
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-white/5 border border-white/10 mb-6"
              >
                <Zap className="w-4 h-4 text-yellow-400" />
                <span className="text-sm text-gray-300">Powered by Advanced AI</span>
              </motion.div>

              <motion.h1
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="text-5xl lg:text-7xl font-bold mb-6"
              >
                <span className="text-gradient">LLM Code</span>
                <span className="text-white">Analyser</span>
              </motion.h1>

              <motion.p
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
                className="text-xl text-gray-400 mb-8 leading-relaxed"
              >
                AI-powered code vulnerability detection and secure code generation. 
                Find security flaws before hackers do, with intelligent analysis 
                that understands your code's context.
              </motion.p>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5 }}
                className="flex flex-wrap gap-4"
              >
                <Link to="/dashboard">
                  <GlowButton size="lg">
                    Start Analysis
                    <ArrowRight className="w-5 h-5" />
                  </GlowButton>
                </Link>
                <GlowButton variant="secondary" size="lg">
                  <Code className="w-5 h-5" />
                  View Demo
                </GlowButton>
              </motion.div>

              {/* Stats */}
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.7 }}
                className="grid grid-cols-4 gap-6 mt-12 pt-8 border-t border-white/10"
              >
                {stats.map((stat, idx) => (
                  <div key={idx} className="text-center">
                    <div className="text-2xl font-bold text-gradient">{stat.value}</div>
                    <div className="text-sm text-gray-500">{stat.label}</div>
                  </div>
                ))}
              </motion.div>
            </motion.div>

            {/* Right Content - Code Animation */}
            <motion.div
              initial={{ opacity: 0, x: 50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8, delay: 0.3 }}
              className="relative hidden lg:block"
            >
              <CodeAnimation />
            </motion.div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="relative py-20 px-6">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-white mb-4">
              Comprehensive Security Analysis
            </h2>
            <p className="text-gray-400 max-w-2xl mx-auto">
              Our AI-powered engine performs deep analysis of your code, combining 
              static analysis with large language model intelligence.
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {features.map((feature, idx) => (
              <FeatureCard
                key={idx}
                icon={feature.icon}
                title={feature.title}
                description={feature.description}
                color={feature.color}
                delay={idx * 0.1}
              />
            ))}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section className="relative py-20 px-6">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-white mb-4">
              How It Works
            </h2>
            <p className="text-gray-400 max-w-2xl mx-auto">
              Three simple steps to secure your code
            </p>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-8">
            {[
              { step: '01', title: 'Paste Your Code', desc: 'Drop your source code into our secure editor', icon: Code },
              { step: '02', title: 'AI Analysis', desc: 'Our AI scans for vulnerabilities and attack vectors', icon: Shield },
              { step: '03', title: 'Get Fixes', desc: 'Receive detailed reports with secure code patches', icon: Lock }
            ].map((item, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: idx * 0.2 }}
                className="relative"
              >
                <div className="glass rounded-2xl p-8 text-center relative overflow-hidden group hover:neon-glow-blue transition-all duration-300">
                  <div className="absolute top-4 right-4 text-6xl font-bold text-white/5 group-hover:text-cyan-500/10 transition-colors">
                    {item.step}
                  </div>
                  <div className="w-16 h-16 mx-auto mb-6 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 flex items-center justify-center">
                    <item.icon className="w-8 h-8 text-cyan-400" />
                  </div>
                  <h3 className="text-xl font-semibold text-white mb-3">{item.title}</h3>
                  <p className="text-gray-400">{item.desc}</p>
                </div>
                {idx < 2 && (
                  <div className="hidden md:block absolute top-1/2 -right-4 transform -translate-y-1/2">
                    <ArrowRight className="w-8 h-8 text-gray-600" />
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="relative py-20 px-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          className="max-w-4xl mx-auto"
        >
          <div className="glass rounded-3xl p-12 text-center relative overflow-hidden neon-glow-purple">
            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/10 via-purple-500/10 to-pink-500/10" />
            <div className="relative z-10">
              <h2 className="text-4xl font-bold text-white mb-4">
                Ready to Secure Your Code?
              </h2>
              <p className="text-gray-400 mb-8 max-w-xl mx-auto">
                Start analyzing your code for vulnerabilities today. 
                No signup required for basic analysis.
              </p>
              <Link to="/dashboard">
                <GlowButton size="lg">
                  Launch Analyzer
                  <ArrowRight className="w-5 h-5" />
                </GlowButton>
              </Link>
            </div>
          </div>
        </motion.div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/10 py-8 px-6">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyan-400" />
            <span className="font-semibold text-gradient">LLM Code Analyser</span>
          </div>
          <p className="text-gray-500 text-sm">
            © 2024 LLM Code Analyser. Powered by LLM + Static Analysis.
          </p>
        </div>
      </footer>
    </div>
  )
}

export default LandingPage
