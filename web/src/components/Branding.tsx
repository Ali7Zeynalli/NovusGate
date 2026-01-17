import { Github, Linkedin } from 'lucide-react'
import type React from 'react'

export const Branding: React.FC<{ className?: string }> = ({ className = '' }) => {
  return (
    <div className={`flex flex-col items-center justify-center p-4 text-center ${className}`}>
      <span className="text-xs text-gray-500 dark:text-gray-400 mb-2">Developed by</span>
      <a
        href="https://github.com/Ali7Zeynalli/NovusGate"
        target="_blank"
        rel="noopener noreferrer"
        className="font-medium text-sm text-gray-800 dark:text-gray-200 hover:text-blue-600 dark:hover:text-blue-400 transition-colors mb-2"
      >
        Ali Zeynalli
      </a>
      <div className="flex gap-3">
        <a
          href="https://github.com/Ali7Zeynalli/NovusGate"
          target="_blank"
          rel="noopener noreferrer"
          className="text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
          title="GitHub Config"
        >
          <Github className="w-4 h-4" />
        </a>
        <a
          href="https://www.linkedin.com/in/ali7zeynalli/"
          target="_blank"
          rel="noopener noreferrer"
          className="text-gray-400 hover:text-[#0077b5] transition-colors"
          title="LinkedIn Profile"
        >
          <Linkedin className="w-4 h-4" />
        </a>
      </div>
    </div>
  )
}
