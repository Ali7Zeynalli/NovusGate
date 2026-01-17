import { Ban, CheckCircle, Unlock } from 'lucide-react'
import { Button, Card } from '@/components/ui'
import type { FirewallRule } from '@/types'

// Blocked IPs Tab Component
interface BlockedIPsTabProps {
  blockedIPs: FirewallRule[]
  onUnblock: (chain: string, lineNumber: number) => void
  unblockLoading: boolean
}

export const BlockedIPsTab = ({ blockedIPs, onUnblock, unblockLoading }: BlockedIPsTabProps) => {
  return (
    <div className="space-y-4">
      {/* Blocked IPs List */}
      <Card padding="none">
        {blockedIPs.length > 0 ? (
          <div className="p-4 space-y-2">
            {blockedIPs.map((rule, index) => (
              <div
                key={`${rule.chain}-${rule.number}-${index}`}
                className="flex items-center justify-between p-3 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800"
              >
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-red-100 dark:bg-red-900/50 flex items-center justify-center">
                    <Ban className="w-5 h-5 text-red-600" />
                  </div>
                  <div>
                    <span className="font-mono font-medium">{rule.source}</span>
                    <div className="flex items-center gap-2 text-xs text-gray-500">
                      <span>Chain: {rule.chain}</span>
                      <span>•</span>
                      <span>Rule #{rule.number}</span>
                      {rule.port && (
                        <>
                          <span>•</span>
                          <span>Port: {rule.port}</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => onUnblock(rule.chain, rule.number)}
                  loading={unblockLoading}
                >
                  <Unlock className="w-4 h-4 mr-1" /> Unblock
                </Button>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12 text-gray-500">
            <CheckCircle className="w-12 h-12 mx-auto mb-3 text-green-500" />
            <p className="font-medium">No blocked IPs</p>
            <p className="text-sm">Use the "Block IP" button above</p>
          </div>
        )}
      </Card>
    </div>
  )
}
