import { Lock, Shield, Trash2 } from 'lucide-react'
import { Badge, Button, Card } from '@/components/ui'
import type { ChainInfo, FirewallRule } from '@/types'

// Host Rules Tab Component
interface HostRulesTabProps {
  chains: ChainInfo[]
  selectedChain: string
  onChainChange: (chain: string) => void
  currentChain?: ChainInfo
  onDeleteRule: (chain: string, lineNumber: number, isProtected: boolean) => void
  deleteLoading: boolean
}

export const HostRulesTab = ({
  chains,
  selectedChain,
  onChainChange,
  currentChain,
  onDeleteRule,
  deleteLoading,
}: HostRulesTabProps) => (
  <div className="space-y-4">
    {/* Chain Selector */}
    <Card className="p-4">
      <div className="flex items-center gap-4">
        <span className="text-sm text-gray-500">Chain:</span>
        <select
          value={selectedChain}
          onChange={(e) => onChainChange(e.target.value)}
          className="px-3 py-1.5 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600 font-medium"
        >
          {chains.map((chain: ChainInfo) => (
            <option key={chain.name} value={chain.name}>
              {chain.name}
            </option>
          ))}
        </select>
        {currentChain && (
          <Badge variant={currentChain.policy === 'ACCEPT' ? 'success' : 'danger'}>
            Policy: {currentChain.policy}
          </Badge>
        )}
        <span className="text-sm text-gray-500 ml-auto">
          {currentChain?.rules?.length || 0} rules
        </span>
      </div>
    </Card>

    {/* Rules Table */}
    <Card padding="none">
      <div className="overflow-x-auto">
        {currentChain?.rules && currentChain.rules.length > 0 ? (
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-800">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  #
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Target
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Protocol
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Source
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Destination
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Port
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Interface
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {currentChain.rules.map((rule: FirewallRule) => (
                <tr
                  key={rule.number}
                  className={rule.protected ? 'bg-yellow-50 dark:bg-yellow-900/10' : ''}
                >
                  <td className="px-4 py-3 text-sm font-mono">{rule.number}</td>
                  <td className="px-4 py-3">
                    <Badge
                      variant={
                        rule.target === 'ACCEPT'
                          ? 'success'
                          : rule.target === 'DROP'
                            ? 'danger'
                            : 'warning'
                      }
                    >
                      {rule.target}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-sm">{rule.protocol}</td>
                  <td className="px-4 py-3 text-sm font-mono">{rule.source}</td>
                  <td className="px-4 py-3 text-sm font-mono">{rule.destination}</td>
                  <td className="px-4 py-3 text-sm font-mono">{rule.port || '-'}</td>
                  <td className="px-4 py-3 text-sm">
                    {rule.in_interface || rule.out_interface || rule.interface || '-'}
                  </td>
                  <td className="px-4 py-3">
                    {rule.protected ? (
                      <span className="flex items-center gap-1 text-xs text-yellow-600 dark:text-yellow-400">
                        <Lock className="w-3 h-3" /> Protected
                      </span>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onDeleteRule(selectedChain, rule.number, rule.protected)}
                        loading={deleteLoading}
                      >
                        <Trash2 className="w-4 h-4 text-red-500" />
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-12 text-gray-500">
            <Shield className="w-12 h-12 mx-auto mb-3 text-gray-400" />
            <p className="font-medium">No rules in this chain</p>
            <p className="text-sm">Add rules using the buttons above</p>
          </div>
        )}
      </div>
    </Card>
  </div>
)
