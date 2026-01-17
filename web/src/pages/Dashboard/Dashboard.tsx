import {
  AlertTriangle,
  ArrowDownToLine,
  ArrowUpFromLine,
  ChevronRight,
  Clock,
  Cpu,
  Globe,
  HardDrive,
  MemoryStick,
  Network,
  Server,
  Wifi,
  WifiOff,
} from 'lucide-react'
import type React from 'react'
import { useNavigate } from 'react-router-dom'
import { useStatsOverview, useSystemInfo } from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { Badge, Button, Card, EmptyState } from '@/components/ui'
import { ProgressBar } from '@/components/ProgressBar'

// Format bytes to human readable
const formatBytes = (bytes: number = 0): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`
}

// Format uptime
const formatUptime = (seconds: number): string => {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const mins = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${mins}m`
  return `${mins}m`
}

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate()
  const { data: stats, isLoading: statsLoading } = useStatsOverview()
  const { data: systemInfo, isLoading: sysLoading } = useSystemInfo()

  if (statsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Dashboard" description="Overview of your NovusGate infrastructure" />

      {/* Server Info Card */}
      {systemInfo && (
        <Card className="bg-gradient-to-r from-blue-600 to-purple-600 text-white border-0">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Server className="w-5 h-5" />
              <h2 className="text-lg font-semibold">Server Status</h2>
            </div>
            <Badge variant="success" size="md">
              <span className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse" />
              Online
            </Badge>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {/* CPU */}
            <div className="p-3 bg-white/10 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Cpu className="w-4 h-4" />
                <span className="text-sm opacity-80">CPU</span>
              </div>
              <p className="text-xl font-bold">{systemInfo.cpu_cores} Cores</p>
              <p className="text-xs opacity-70 truncate">{systemInfo.cpu_model || 'Unknown'}</p>
              {systemInfo.load_1m && <p className="text-xs mt-1">Load: {systemInfo.load_1m}</p>}
            </div>

            {/* Memory */}
            <div className="p-3 bg-white/10 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <MemoryStick className="w-4 h-4" />
                <span className="text-sm opacity-80">Memory</span>
              </div>
              <p className="text-xl font-bold">{formatBytes(systemInfo.memory_used)}</p>
              <p className="text-xs opacity-70">of {formatBytes(systemInfo.memory_total)}</p>
              <div className="mt-2">
                <ProgressBar
                  value={systemInfo.memory_used}
                  max={systemInfo.memory_total}
                  color="bg-white/50"
                />
              </div>
            </div>

            {/* Disk */}
            <div className="p-3 bg-white/10 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <HardDrive className="w-4 h-4" />
                <span className="text-sm opacity-80">Disk</span>
              </div>
              <p className="text-xl font-bold">{formatBytes(systemInfo.disk_used)}</p>
              <p className="text-xs opacity-70">of {formatBytes(systemInfo.disk_total)}</p>
              <div className="mt-2">
                <ProgressBar
                  value={systemInfo.disk_used}
                  max={systemInfo.disk_total}
                  color="bg-white/50"
                />
              </div>
            </div>

            {/* Uptime */}
            <div className="p-3 bg-white/10 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Clock className="w-4 h-4" />
                <span className="text-sm opacity-80">Uptime</span>
              </div>
              <p className="text-xl font-bold">{formatUptime(systemInfo.uptime_seconds)}</p>
              <p className="text-xs opacity-70">{systemInfo.hostname}</p>
            </div>
          </div>
        </Card>
      )}

      {/* Main Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Networks</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white">
                {stats?.total_networks || 0}
              </p>
            </div>
            <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-xl">
              <Globe className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-purple-500 to-purple-600" />
        </Card>

        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Nodes</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white">
                {stats?.total_nodes || 0}
              </p>
            </div>
            <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-xl">
              <Server className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-blue-500 to-blue-600" />
        </Card>

        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Online</p>
              <p className="text-3xl font-bold text-green-600">{stats?.online_nodes || 0}</p>
            </div>
            <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-xl">
              <Wifi className="w-6 h-6 text-green-600 dark:text-green-400" />
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-green-500 to-green-600" />
        </Card>

        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Offline</p>
              <p className="text-3xl font-bold text-gray-400">{stats?.offline_nodes || 0}</p>
            </div>
            <div className="p-3 bg-gray-100 dark:bg-gray-700 rounded-xl">
              <WifiOff className="w-6 h-6 text-gray-400" />
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-gray-400 to-gray-500" />
        </Card>

        <Card className="relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Pending</p>
              <p className="text-3xl font-bold text-orange-500">{stats?.pending_nodes || 0}</p>
            </div>
            <div className="p-3 bg-orange-100 dark:bg-orange-900/30 rounded-xl">
              <Clock className="w-6 h-6 text-orange-500" />
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-orange-400 to-orange-500" />
        </Card>
      </div>

      {/* Traffic Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
              <ArrowDownToLine className="w-5 h-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Download</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {formatBytes(stats?.total_rx || 0)}
              </p>
            </div>
          </div>
          <p className="text-xs text-gray-500">Across all networks</p>
        </Card>

        <Card>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-green-100 dark:bg-green-900/30 rounded-lg">
              <ArrowUpFromLine className="w-5 h-5 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Upload</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {formatBytes(stats?.total_tx || 0)}
              </p>
            </div>
          </div>
          <p className="text-xs text-gray-500">Across all networks</p>
        </Card>
      </div>

      {/* Networks List */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Network className="w-5 h-5 text-blue-600" />
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Networks</h2>
          </div>
          <Button variant="ghost" size="sm" onClick={() => navigate('/networks')}>
            View all <ChevronRight className="w-4 h-4 ml-1" />
          </Button>
        </div>

        {stats?.networks && stats.networks.length > 0 ? (
          <div className="space-y-3">
            {stats.networks.map((network) => (
              <div
                key={network.id}
                className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer transition-colors"
                onClick={() => navigate('/nodes')}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                      <Network className="w-5 h-5 text-blue-600" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-900 dark:text-white">
                        {network.name}
                      </h3>
                      <p className="text-xs text-gray-500 font-mono">
                        {network.cidr} • {network.interface}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-semibold text-gray-900 dark:text-white">
                      {network.total_nodes} nodes
                    </p>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-green-600">{network.online_nodes} online</span>
                      <span className="text-gray-400">•</span>
                      <span className="text-gray-500">{network.offline_nodes} offline</span>
                    </div>
                  </div>
                </div>

                {/* Network Stats Bar */}
                <div className="grid grid-cols-4 gap-2 text-xs">
                  <div className="flex items-center gap-1">
                    <span className="w-2 h-2 bg-green-500 rounded-full" />
                    <span className="text-gray-600 dark:text-gray-400">
                      Online: {network.online_nodes}
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="w-2 h-2 bg-gray-400 rounded-full" />
                    <span className="text-gray-600 dark:text-gray-400">
                      Offline: {network.offline_nodes}
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="w-2 h-2 bg-orange-500 rounded-full" />
                    <span className="text-gray-600 dark:text-gray-400">
                      Pending: {network.pending_nodes}
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="w-2 h-2 bg-red-500 rounded-full" />
                    <span className="text-gray-600 dark:text-gray-400">
                      Expired: {network.expired_nodes}
                    </span>
                  </div>
                </div>

                {/* Traffic */}
                <div className="flex items-center gap-4 mt-3 pt-3 border-t border-gray-200 dark:border-gray-600 text-xs">
                  <div className="flex items-center gap-1 text-blue-600">
                    <ArrowDownToLine className="w-3 h-3" />
                    <span>{formatBytes(network.transfer_rx)}</span>
                  </div>
                  <div className="flex items-center gap-1 text-green-600">
                    <ArrowUpFromLine className="w-3 h-3" />
                    <span>{formatBytes(network.transfer_tx)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon={<Network className="w-12 h-12" />}
            title="No networks"
            description="Create your first network to get started"
            action={{
              label: 'Create Network',
              onClick: () => navigate('/networks'),
            }}
          />
        )}
      </Card>

      {/* Expired Nodes Warning */}
      {stats && stats.expired_nodes > 0 && (
        <Card className="border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-100 dark:bg-red-900/50 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-red-600" />
            </div>
            <div>
              <p className="font-medium text-red-800 dark:text-red-300">
                {stats.expired_nodes} node{stats.expired_nodes > 1 ? 's' : ''} expired
              </p>
              <p className="text-sm text-red-600 dark:text-red-400">
                These nodes need attention - their access has expired
              </p>
            </div>
            <Button
              variant="secondary"
              size="sm"
              className="ml-auto"
              onClick={() => navigate('/nodes')}
            >
              Manage Nodes
            </Button>
          </div>
        </Card>
      )}
    </div>
  )
}

export default DashboardPage
