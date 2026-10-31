import { useState, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Upload, X, FileCode, FolderOpen, Archive, AlertCircle } from 'lucide-react'
import JSZip from 'jszip'

// Supported file extensions for code analysis
const SUPPORTED_EXTENSIONS = [
  '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.c', '.cpp', '.h', '.hpp',
  '.php', '.go', '.rs', '.rb', '.swift', '.kt', '.scala', '.cs', '.vb',
  '.html', '.css', '.sql', '.sh', '.bash', '.ps1', '.yaml', '.yml', '.json'
]

const FileUpload = ({ onFilesSelected, maxFiles = 50 }) => {
  const [isDragging, setIsDragging] = useState(false)
  const [files, setFiles] = useState([])
  const [error, setError] = useState(null)
  const [isProcessing, setIsProcessing] = useState(false)
  const fileInputRef = useRef(null)

  const getLanguageFromExtension = (filename) => {
    const ext = filename.toLowerCase().split('.').pop()
    const langMap = {
      'py': 'python',
      'js': 'javascript',
      'jsx': 'javascript',
      'ts': 'javascript',
      'tsx': 'javascript',
      'java': 'java',
      'c': 'c',
      'cpp': 'cpp',
      'h': 'c',
      'hpp': 'cpp',
      'php': 'php',
      'go': 'go',
      'rs': 'rust',
      'rb': 'ruby',
      'swift': 'swift',
      'kt': 'kotlin',
      'scala': 'scala',
      'cs': 'csharp',
      'vb': 'vbnet',
      'html': 'html',
      'css': 'css',
      'sql': 'sql',
      'sh': 'bash',
      'bash': 'bash',
      'ps1': 'powershell',
      'yaml': 'yaml',
      'yml': 'yaml',
      'json': 'json'
    }
    return langMap[ext] || 'auto'
  }

  const isValidCodeFile = (filename) => {
    const ext = '.' + filename.toLowerCase().split('.').pop()
    return SUPPORTED_EXTENSIONS.includes(ext)
  }

  const processFile = async (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = (e) => {
        resolve({
          filename: file.name,
          content: e.target.result,
          language: getLanguageFromExtension(file.name),
          size: file.size
        })
      }
      reader.onerror = () => reject(new Error(`Failed to read ${file.name}`))
      reader.readAsText(file)
    })
  }

  const processZipFile = async (file) => {
    const zip = new JSZip()
    const contents = await zip.loadAsync(file)
    const filePromises = []

    contents.forEach((relativePath, zipEntry) => {
      // Skip directories and non-code files
      if (zipEntry.dir) return
      if (!isValidCodeFile(relativePath)) return
      // Skip hidden files and common non-essential paths
      if (relativePath.startsWith('.') || 
          relativePath.includes('__pycache__') ||
          relativePath.includes('node_modules') ||
          relativePath.includes('.git')) return

      filePromises.push(
        zipEntry.async('string').then(content => ({
          filename: relativePath,
          content,
          language: getLanguageFromExtension(relativePath),
          size: content.length
        }))
      )
    })

    return Promise.all(filePromises)
  }

  const handleFiles = useCallback(async (fileList) => {
    setIsProcessing(true)
    setError(null)

    try {
      const processedFiles = []

      for (const file of fileList) {
        // Handle ZIP files
        if (file.name.endsWith('.zip')) {
          const zipFiles = await processZipFile(file)
          processedFiles.push(...zipFiles)
        } 
        // Handle regular code files
        else if (isValidCodeFile(file.name)) {
          const processed = await processFile(file)
          processedFiles.push(processed)
        }
      }

      if (processedFiles.length === 0) {
        setError('No valid code files found. Supported: .py, .js, .java, .c, .cpp, .php, .go, etc.')
        setIsProcessing(false)
        return
      }

      if (processedFiles.length > maxFiles) {
        setError(`Too many files (${processedFiles.length}). Maximum ${maxFiles} files allowed.`)
        processedFiles.length = maxFiles
      }

      setFiles(processedFiles)
      onFilesSelected(processedFiles)
    } catch (err) {
      setError(`Error processing files: ${err.message}`)
    }

    setIsProcessing(false)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onFilesSelected, maxFiles])

  const handleDragOver = (e) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    setIsDragging(false)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setIsDragging(false)
    
    const droppedFiles = Array.from(e.dataTransfer.files)
    handleFiles(droppedFiles)
  }

  const handleFileSelect = (e) => {
    const selectedFiles = Array.from(e.target.files)
    handleFiles(selectedFiles)
  }

  const removeFile = (index) => {
    const newFiles = files.filter((_, i) => i !== index)
    setFiles(newFiles)
    onFilesSelected(newFiles)
  }

  const clearAll = () => {
    setFiles([])
    setError(null)
    onFilesSelected([])
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  return (
    <div className="space-y-4">
      {/* Drop Zone */}
      <motion.div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`
          relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer
          transition-all duration-200
          ${isDragging 
            ? 'border-cyan-400 bg-cyan-500/10' 
            : 'border-white/20 hover:border-white/40 hover:bg-white/5'
          }
        `}
        whileHover={{ scale: 1.01 }}
        whileTap={{ scale: 0.99 }}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept={SUPPORTED_EXTENSIONS.join(',') + ',.zip'}
          onChange={handleFileSelect}
          className="hidden"
        />

        <motion.div
          animate={isDragging ? { scale: 1.1 } : { scale: 1 }}
          className="flex flex-col items-center gap-3"
        >
          {isProcessing ? (
            <>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                className="w-12 h-12 border-2 border-cyan-400 border-t-transparent rounded-full"
              />
              <p className="text-gray-400">Processing files...</p>
            </>
          ) : (
            <>
              <div className="flex items-center gap-3">
                <Upload className={`w-8 h-8 ${isDragging ? 'text-cyan-400' : 'text-gray-500'}`} />
                <FolderOpen className={`w-8 h-8 ${isDragging ? 'text-cyan-400' : 'text-gray-500'}`} />
                <Archive className={`w-8 h-8 ${isDragging ? 'text-cyan-400' : 'text-gray-500'}`} />
              </div>
              <div>
                <p className={`font-medium ${isDragging ? 'text-cyan-400' : 'text-gray-300'}`}>
                  {isDragging ? 'Drop files here' : 'Click to upload or drag & drop'}
                </p>
                <p className="text-sm text-gray-500 mt-1">
                  Upload code files, folders, or ZIP archives
                </p>
              </div>
            </>
          )}
        </motion.div>
      </motion.div>

      {/* Error Display */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg"
          >
            <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <p className="text-sm text-red-400">{error}</p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* File List */}
      <AnimatePresence>
        {files.length > 0 && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="space-y-2"
          >
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-400">
                {files.length} file{files.length > 1 ? 's' : ''} selected
              </p>
              <button
                onClick={clearAll}
                className="text-sm text-red-400 hover:text-red-300 transition-colors"
              >
                Clear all
              </button>
            </div>

            <div className="max-h-48 overflow-y-auto space-y-1.5 pr-2 scrollbar-thin">
              {files.map((file, index) => (
                <motion.div
                  key={`${file.filename}-${index}`}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 10 }}
                  transition={{ delay: index * 0.02 }}
                  className="flex items-center justify-between p-2 bg-white/5 rounded-lg group"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <FileCode className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                    <span className="text-sm text-gray-300 truncate" title={file.filename}>
                      {file.filename}
                    </span>
                    <span className="text-xs text-gray-600 flex-shrink-0">
                      {file.language}
                    </span>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      removeFile(index)
                    }}
                    className="p-1 text-gray-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default FileUpload
