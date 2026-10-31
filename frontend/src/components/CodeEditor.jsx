import { useRef, useMemo } from 'react'
import { motion } from 'framer-motion'
import Prism from 'prismjs'
import 'prismjs/themes/prism-tomorrow.css'
import 'prismjs/components/prism-python'
import 'prismjs/components/prism-javascript'
import 'prismjs/components/prism-java'
import 'prismjs/components/prism-c'
import 'prismjs/components/prism-cpp'
import 'prismjs/components/prism-php'
import 'prismjs/components/prism-go'
import 'prismjs/components/prism-rust'

const CodeEditor = ({ value, onChange, language = 'python', readOnly = false, highlightedLines = [] }) => {
  const textareaRef = useRef(null)
  const lineNumbersRef = useRef(null)
  const highlightRef = useRef(null)
  const vulnHighlightRef = useRef(null)
  
  const lines = useMemo(() => (value || '').split('\n'), [value])
  const lineCount = useMemo(() => Math.max(lines.length, 20), [lines])

  // Map language names to Prism language keys
  const prismLanguage = useMemo(() => {
    const langMap = {
      'python': 'python',
      'javascript': 'javascript',
      'js': 'javascript',
      'java': 'java',
      'c': 'c',
      'cpp': 'cpp',
      'c++': 'cpp',
      'php': 'php',
      'go': 'go',
      'rust': 'rust'
    }
    return langMap[language.toLowerCase()] || 'python'
  }, [language])

  // Highlight code with Prism
  const highlightedCode = useMemo(() => {
    if (!value) return ''
    try {
      return Prism.highlight(value, Prism.languages[prismLanguage] || Prism.languages.python, prismLanguage)
    } catch {
      return value
    }
  }, [value, prismLanguage])

  const handleKeyDown = (e) => {
    if (e.key === 'Tab') {
      e.preventDefault()
      const start = e.target.selectionStart
      const end = e.target.selectionEnd
      const newValue = value.substring(0, start) + '  ' + value.substring(end)
      onChange(newValue)
      setTimeout(() => {
        e.target.selectionStart = e.target.selectionEnd = start + 2
      }, 0)
    }
  }

  const handleScroll = (e) => {
    const scrollTop = e.target.scrollTop
    if (lineNumbersRef.current) {
      lineNumbersRef.current.scrollTop = scrollTop
    }
    if (highlightRef.current) {
      highlightRef.current.scrollTop = scrollTop
      highlightRef.current.scrollLeft = e.target.scrollLeft
    }
    if (vulnHighlightRef.current) {
      vulnHighlightRef.current.scrollTop = scrollTop
    }
  }

  // Get line severity for highlighting
  const getLineSeverity = (lineNum) => {
    const line = highlightedLines.find(l => l.line === lineNum)
    return line?.severity || null
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="relative glass rounded-xl overflow-hidden"
    >
      {/* Editor Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/10">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <div className="w-3 h-3 rounded-full bg-green-500" />
          </div>
          <span className="text-sm text-gray-500 ml-3">code.{language}</span>
        </div>
        <div className="flex items-center gap-3">
          {highlightedLines.length > 0 && (
            <span className="text-xs text-red-400 font-mono">
              {highlightedLines.length} issue{highlightedLines.length > 1 ? 's' : ''} found
            </span>
          )}
          <span className="text-xs text-gray-500 font-mono">
            {language.toUpperCase()}
          </span>
        </div>
      </div>

      {/* Editor Body */}
      <div className="flex relative h-[500px]">
        {/* Line Numbers */}
        <div 
          ref={lineNumbersRef}
          className="flex flex-col items-end py-4 px-3 bg-black/20 text-gray-600 font-mono text-sm select-none border-r border-white/5 overflow-hidden"
        >
          {Array.from({ length: lineCount }, (_, i) => {
            const severity = getLineSeverity(i + 1)
            return (
              <div 
                key={i + 1} 
                className={`leading-6 h-6 flex-shrink-0 px-1 rounded-sm transition-colors ${
                  severity === 'critical' ? 'bg-red-500/30 text-red-400' :
                  severity === 'high' ? 'bg-orange-500/30 text-orange-400' :
                  severity === 'medium' ? 'bg-yellow-500/30 text-yellow-400' :
                  severity === 'low' ? 'bg-blue-500/30 text-blue-400' : ''
                }`}
              >
                {i + 1}
              </div>
            )
          })}
        </div>

        {/* Code Area with Syntax Highlighting */}
        <div className="flex-1 relative overflow-hidden">
          {/* Syntax highlighted overlay */}
          <pre
            ref={highlightRef}
            className="absolute inset-0 p-4 font-mono text-sm leading-6 overflow-auto pointer-events-none m-0 bg-transparent"
            style={{ tabSize: 2 }}
            aria-hidden="true"
          >
            <code 
              className={`language-${prismLanguage}`}
              dangerouslySetInnerHTML={{ __html: highlightedCode || '&nbsp;' }}
            />
          </pre>

          {/* Actual textarea (invisible text, handles input) */}
          <textarea
            ref={textareaRef}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={handleKeyDown}
            onScroll={handleScroll}
            readOnly={readOnly}
            placeholder="// Paste your code here for security analysis..."
            spellCheck={false}
            className={`
              w-full h-full p-4 bg-transparent text-transparent caret-cyan-400
              font-mono text-sm leading-6 resize-none
              focus:outline-none placeholder:text-gray-600
              overflow-auto relative z-10
              ${readOnly ? 'cursor-default' : ''}
            `}
            style={{ tabSize: 2, caretColor: '#22d3ee' }}
          />
          
          {/* Vulnerability line highlights - positioned absolutely based on line number */}
          <div 
            ref={vulnHighlightRef}
            className="absolute inset-0 pointer-events-none overflow-hidden"
            style={{ padding: '16px 0' }}
          >
            <div style={{ position: 'relative', minHeight: `${lines.length * 24}px` }}>
              {highlightedLines.map((item, idx) => {
                const lineIndex = item.line - 1
                if (lineIndex < 0 || lineIndex >= lines.length) return null
                return (
                  <div
                    key={`highlight-${item.line}-${idx}`}
                    className={`absolute left-0 right-0 h-6 ${
                      item.severity === 'critical' ? 'bg-red-500/25 border-l-4 border-red-500' :
                      item.severity === 'high' ? 'bg-orange-500/20 border-l-4 border-orange-500' :
                      item.severity === 'medium' ? 'bg-yellow-500/15 border-l-4 border-yellow-500' :
                      'bg-blue-500/15 border-l-4 border-blue-500'
                    }`}
                    style={{ top: `${lineIndex * 24}px` }}
                  />
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  )
}

export default CodeEditor
