import { clsx } from 'clsx'
import {
  Activity,
  ChevronDown,
  Flame,
  LogOut,
  Menu,
  Network,
  Server,
  Settings,
  Shield,
  X,
} from 'lucide-react'
import type React from 'react'
import { useEffect } from 'react'
import { Link, Outlet, useLocation } from 'react-router-dom'
import { useNetworks } from '../api/client'
import { useAppStore, useSidebarOpen } from '../store'
import { Branding } from './Branding'

interface NavItem {
  name: string
  href: string
  icon: React.ReactNode
}

const navigation: NavItem[] = [
  { name: 'Overview', href: '/dashboard', icon: <Activity className="w-5 h-5" /> },
  { name: 'Networks', href: '/networks', icon: <Network className="w-5 h-5" /> },
  { name: 'Nodes', href: '/nodes', icon: <Server className="w-5 h-5" /> },
  { name: 'Firewall', href: '/firewall', icon: <Flame className="w-5 h-5" /> },
  { name: 'Fail2Ban', href: '/fail2ban', icon: <Shield className="w-5 h-5" /> },
  { name: 'Settings', href: '/settings', icon: <Settings className="w-5 h-5" /> },
]

export const Layout = () => {
  const location = useLocation()
  const sidebarOpen = useSidebarOpen()
  const { toggleSidebar, currentNetworkId, setCurrentNetworkId } = useAppStore()
  const { data: networks } = useNetworks()

  // Auto-select first network if none selected
  useEffect(() => {
    if (!currentNetworkId && networks && networks.length > 0) {
      setCurrentNetworkId(networks[0].id)
    }
  }, [currentNetworkId, networks, setCurrentNetworkId])

  const currentNetwork = networks?.find((n) => n.id === currentNetworkId)

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <div className="fixed inset-0 z-40 bg-black/50 lg:hidden" onClick={toggleSidebar} />
      )}

      {/* Sidebar */}
      <aside
        className={clsx(
          'fixed inset-y-0 left-0 z-50 w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 transform transition-transform duration-200 ease-in-out lg:translate-x-0 flex flex-col',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        {/* Logo */}
        <div className="flex items-center justify-between h-16 px-4 border-b dark:border-gray-700">
          <Link to="/" className="flex items-center gap-2">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <Network className="w-5 h-5 text-white" />
            </div>
            <span className="text-lg font-semibold text-gray-900 dark:text-white">NovusGate</span>
          </Link>
          <button onClick={toggleSidebar} className="lg:hidden text-gray-500">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Network selector */}
        <div className="p-4 border-b dark:border-gray-700">
          <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
            Network
          </label>
          <div className="relative">
            <select
              value={currentNetworkId || ''}
              onChange={(e) => setCurrentNetworkId(e.target.value || null)}
              className="w-full appearance-none bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 pr-8 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select network...</option>
              {networks?.map((network) => (
                <option key={network.id} value={network.id}>
                  {network.name}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
          </div>
          {currentNetwork && (
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              CIDR: {currentNetwork.cidr}
            </p>
          )}
        </div>

        {/* Navigation */}
        <nav className="p-4 space-y-1 flex-1 overflow-y-auto">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href
            return (
              <Link
                key={item.name}
                to={item.href}
                className={clsx(
                  'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400'
                    : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                )}
              >
                {item.icon}
                {item.name}
              </Link>
            )
          })}
        </nav>

        {/* Footer Actions */}
        <div className="p-4 border-t dark:border-gray-700">
          <Branding className="mb-4" />
          <button
            type="button"
            onClick={() => {
              if (confirm('Are you sure you want to log out?')) {
                localStorage.removeItem('auth_token')
                localStorage.removeItem('auth_username')
                window.location.href = '/login'
              }
            }}
            className="flex items-center gap-3 px-3 py-2 w-full rounded-lg text-sm font-medium text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20 transition-colors"
          >
            <LogOut className="w-5 h-5" />
            Log Out
          </button>
        </div>

        {/* Version */}
        <div className="px-4 pb-4">
          <p className="text-xs text-gray-500 dark:text-gray-400">NovusGate v0.1.0</p>
        </div>
      </aside>

      {/* Main content */}
      <div className={clsx('transition-all duration-200', sidebarOpen ? 'lg:ml-64' : '')}>
        {/* Top bar */}
        <header className="sticky top-0 z-30 h-16 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between h-full px-4">
            <button
              type="button"
              onClick={toggleSidebar}
              className="lg:hidden text-gray-500 hover:text-gray-700"
            >
              <Menu className="w-6 h-6" />
            </button>

            <div className="flex items-center gap-4">
              {/* VPN Status Indicator */}
              {(() => {
                const isVpnSecure = window.location.hostname === '10.99.0.1'
                const isLocalhost =
                  window.location.hostname === 'localhost' ||
                  window.location.hostname === '127.0.0.1'

                if (isVpnSecure) {
                  return (
                    <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 text-xs font-medium">
                      <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                      VPN Connected
                    </div>
                  )
                } else if (isLocalhost) {
                  return (
                    <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 text-xs font-medium">
                      Dev Mode
                    </div>
                  )
                } else {
                  return (
                    <div
                      className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 text-xs font-medium"
                      title="You are accessing via Public IP. This is insecure."
                    >
                      <div className="w-2 h-2 rounded-full bg-red-500" />
                      Insecure Connection
                    </div>
                  )
                }
              })()}

              <div className="flex items-center gap-2">
                <div className="w-8 h-8 bg-gray-300 dark:bg-gray-600 rounded-full" />
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

// Page header component
interface PageHeaderProps {
  title: string
  description?: string
  actions?: React.ReactNode
}

export const PageHeader: React.FC<PageHeaderProps> = ({ title, description, actions }) => {
  return (
    <div className="mb-6 flex items-center justify-between">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{title}</h1>
        {description && (
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{description}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-3">{actions}</div>}
    </div>
  )
}
