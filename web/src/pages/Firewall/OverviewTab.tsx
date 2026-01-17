import { Ban, CheckCircle, Globe, Lock, Network, Plus, Shield } from 'lucide-react'
import { Badge, Card } from '@/components/ui'
import type { ChainInfo } from '@/types'

interface OverviewTabProps {
  chains: ChainInfo[]
  totalRules: number
  blockedIPs: number
  openPorts: number
  vpnRuleCount: number
  onOpenPort: () => void
  onBlockIP: () => void
  onAllowIP: () => void
}

export const OverviewTab = ({
  chains,
  totalRules,
  blockedIPs,
  openPorts,
  vpnRuleCount,
  onOpenPort,
  onBlockIP,
  onAllowIP,
}: OverviewTabProps) => {
  return (
    <div className="space-y-6">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
              <Shield className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Total Rules</p>
              <p className="text-2xl font-bold text-blue-600">{totalRules}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
              <Ban className="w-6 h-6 text-red-600 dark:text-red-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Blocked IPs</p>
              <p className="text-2xl font-bold text-red-600">{blockedIPs}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
              <Globe className="w-6 h-6 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Open Ports</p>
              <p className="text-2xl font-bold text-green-600">{openPorts}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
              <Network className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500">VPN Rules</p>
              <p className="text-2xl font-bold text-purple-600">{vpnRuleCount}</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Chain Policies */}
      <Card padding="none">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="font-semibold">Chain Policies</h3>
          <p className="text-sm text-gray-500">Default action for each iptables chain</p>
        </div>
        <div className="p-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {chains.map((chain: ChainInfo) => (
              <div
                key={chain.name}
                className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
              >
                <div className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-gray-500" />
                  <span className="font-medium">{chain.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={chain.policy === 'ACCEPT' ? 'success' : 'danger'}>
                    {chain.policy}
                  </Badge>
                  <span className="text-sm text-gray-500">{chain.rules?.length || 0} rules</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </Card>

      {/* Quick Actions */}
      <Card padding="none">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="font-semibold">Quick Actions</h3>
          <p className="text-sm text-gray-500">Common firewall operations</p>
        </div>
        <div className="p-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <button
              type="button"
              onClick={onOpenPort}
              className="flex items-center gap-3 p-4 bg-green-50 dark:bg-green-900/20 rounded-lg hover:bg-green-100 dark:hover:bg-green-900/30 transition-colors"
            >
              <div className="w-10 h-10 rounded-full bg-green-100 dark:bg-green-900/50 flex items-center justify-center">
                <Plus className="w-5 h-5 text-green-600" />
              </div>
              <div className="text-left">
                <p className="font-medium text-green-700 dark:text-green-300">Open Port</p>
                <p className="text-sm text-green-600 dark:text-green-400">Allow incoming traffic</p>
              </div>
            </button>
            <button
              type="button"
              onClick={onBlockIP}
              className="flex items-center gap-3 p-4 bg-red-50 dark:bg-red-900/20 rounded-lg hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors"
            >
              <div className="w-10 h-10 rounded-full bg-red-100 dark:bg-red-900/50 flex items-center justify-center">
                <Ban className="w-5 h-5 text-red-600" />
              </div>
              <div className="text-left">
                <p className="font-medium text-red-700 dark:text-red-300">Block IP</p>
                <p className="text-sm text-red-600 dark:text-red-400">Drop traffic from IP</p>
              </div>
            </button>
            <button
              type="button"
              onClick={onAllowIP}
              className="flex items-center gap-3 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/30 transition-colors"
            >
              <div className="w-10 h-10 rounded-full bg-blue-100 dark:bg-blue-900/50 flex items-center justify-center">
                <CheckCircle className="w-5 h-5 text-blue-600" />
              </div>
              <div className="text-left">
                <p className="font-medium text-blue-700 dark:text-blue-300">Allow IP</p>
                <p className="text-sm text-blue-600 dark:text-blue-400">Accept traffic from IP</p>
              </div>
            </button>
          </div>
        </div>
      </Card>
    </div>
  )
}
