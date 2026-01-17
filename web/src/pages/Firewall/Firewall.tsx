import { useState } from 'react'
import {
  Ban,
  CheckCircle,
  Download,
  Globe,
  Lock,
  Network,
  Plus,
  RefreshCw,
  RotateCcw,
  Shield,
} from 'lucide-react'
import {
  api,
  useAllowIP,
  useApplyVPNFirewallRules,
  useBlockIP,
  useClosePort,
  useCreateVPNFirewallRule,
  useDeleteFirewallRule,
  useDeleteVPNFirewallRule,
  useFirewallRules,
  useNetworks,
  useOpenPort,
  useResetFirewall,
  useUpdateVPNFirewallRule,
  useVPNFirewallRules,
} from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { Button, Card, Modal } from '@/components/ui'
import type { ChainInfo, FirewallRule, VPNFirewallRule, VPNFirewallRuleRequest } from '@/types'
import { HostRulesTab } from './HostRulesTab'
import { OverviewTab } from './OverviewTab'
import { VPNRulesTab } from './VPNRulesTab'
import { VPNRuleModal } from './VPNRuleModal'
import { BlockedIPsTab } from './BlockedIPsTab'
import { OpenPortsTab } from './OpenPortsTab'

type TabId = 'overview' | 'host-rules' | 'open-ports' | 'vpn-rules' | 'blocked-ips'

export const Firewall: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabId>('overview')
  const [selectedChain, setSelectedChain] = useState<string>('INPUT')

  // Modals
  const [showOpenPortModal, setShowOpenPortModal] = useState(false)
  const [showBlockIPModal, setShowBlockIPModal] = useState(false)
  const [showAllowIPModal, setShowAllowIPModal] = useState(false)
  const [showVPNRuleModal, setShowVPNRuleModal] = useState(false)
  const [editingVPNRule, setEditingVPNRule] = useState<VPNFirewallRule | null>(null)

  // Forms
  const [openPortForm, setOpenPortForm] = useState({ port: '', protocol: 'tcp', source: '' })
  const [blockIPForm, setBlockIPForm] = useState({ ip: '', ports: '' })
  const [allowIPForm, setAllowIPForm] = useState({ ip: '', ports: '' })
  const [vpnRuleForm, setVPNRuleForm] = useState<VPNFirewallRuleRequest>({
    name: '',
    description: '',
    source_type: 'any',
    dest_type: 'any',
    protocol: 'all',
    port: '',
    action: 'accept',
    priority: 100,
    enabled: true,
  })

  // Data queries
  const {
    data: firewallStatus,
    isLoading: rulesLoading,
    refetch: refetchRules,
  } = useFirewallRules()
  const { data: vpnRules, isLoading: vpnLoading, refetch: refetchVPN } = useVPNFirewallRules()
  const { data: networks } = useNetworks()

  // Mutations
  const openPortMutation = useOpenPort()
  const closePortMutation = useClosePort()
  const blockIPMutation = useBlockIP()
  const allowIPMutation = useAllowIP()
  const deleteRuleMutation = useDeleteFirewallRule()
  const resetFirewallMutation = useResetFirewall()
  const createVPNRuleMutation = useCreateVPNFirewallRule()
  const updateVPNRuleMutation = useUpdateVPNFirewallRule()
  const deleteVPNRuleMutation = useDeleteVPNFirewallRule()
  const applyVPNRulesMutation = useApplyVPNFirewallRules()

  const handleRefresh = () => {
    refetchRules()
    refetchVPN()
  }

  // Get chains data
  const chains = firewallStatus?.chains || []
  const currentChain = chains.find((c: ChainInfo) => c.name === selectedChain)

  // Calculate stats
  const totalRules = firewallStatus?.total_rules || 0
  const blockedIPs = firewallStatus?.blocked_ips || 0
  const openPorts = firewallStatus?.open_ports || 0
  const vpnRuleCount = vpnRules?.length || 0

  // Get blocked IPs from rules
  const getBlockedIPs = (): FirewallRule[] => {
    const blocked: FirewallRule[] = []
    chains.forEach((chain: ChainInfo) => {
      chain.rules?.forEach((rule: FirewallRule) => {
        if (rule.target === 'DROP' && rule.source !== 'anywhere' && rule.source !== '0.0.0.0/0') {
          blocked.push(rule)
        }
      })
    })
    return blocked
  }

  // Get open ports from rules
  const getOpenPorts = (): FirewallRule[] => {
    const ports: FirewallRule[] = []
    chains.forEach((chain: ChainInfo) => {
      if (chain.name === 'INPUT') {
        chain.rules?.forEach((rule: FirewallRule) => {
          if (rule.target === 'ACCEPT' && rule.port && rule.port !== '-') {
            ports.push(rule)
          }
        })
      }
    })
    return ports
  }

  // Close port handler
  const handleClosePort = async (port: number, protocol: string, isProtected: boolean) => {
    if (isProtected) {
      alert('This port is protected and cannot be closed (SSH, WireGuard or Admin API).')
      return
    }
    if (!confirm(`Are you sure you want to close port ${port}/${protocol}?`)) return
    try {
      await closePortMutation.mutateAsync({ port, protocol })
    } catch (error: any) {
      const errorMessage = error?.response?.data?.error || error?.message || 'Unknown error'
      console.error('Failed to close port:', error)
      alert(`Failed to close port: ${errorMessage}`)
    }
  }

  // Handlers
  const handleOpenPort = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await openPortMutation.mutateAsync({
        port: parseInt(openPortForm.port, 10),
        protocol: openPortForm.protocol,
        source: openPortForm.source || undefined,
      })
      setShowOpenPortModal(false)
      setOpenPortForm({ port: '', protocol: 'tcp', source: '' })
    } catch (error) {
      console.error('Failed to open port:', error)
    }
  }

  const handleBlockIP = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await blockIPMutation.mutateAsync({
        ip: blockIPForm.ip,
        ports: blockIPForm.ports || undefined,
      })
      setShowBlockIPModal(false)
      setBlockIPForm({ ip: '', ports: '' })
    } catch (error) {
      console.error('Failed to block IP:', error)
    }
  }

  const handleAllowIP = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await allowIPMutation.mutateAsync({
        ip: allowIPForm.ip,
        ports: allowIPForm.ports || undefined,
      })
      setShowAllowIPModal(false)
      setAllowIPForm({ ip: '', ports: '' })
    } catch (error) {
      console.error('Failed to allow IP:', error)
    }
  }

  const handleDeleteRule = async (chain: string, lineNumber: number, isProtected: boolean) => {
    if (isProtected) {
      alert('This rule is protected and cannot be deleted.')
      return
    }
    if (!confirm(`Are you sure you want to delete rule #${lineNumber} from ${chain}?`)) return
    try {
      await deleteRuleMutation.mutateAsync({ chain, line_number: lineNumber })
    } catch (error) {
      console.error('Failed to delete rule:', error)
    }
  }

  const handleUnblockIP = async (chain: string, lineNumber: number) => {
    if (!confirm('Are you sure you want to unblock this IP?')) return
    try {
      await deleteRuleMutation.mutateAsync({ chain, line_number: lineNumber, force: true })
    } catch (error) {
      console.error('Failed to unblock IP:', error)
    }
  }

  const handleExportRules = async () => {
    try {
      const rules = await api.exportFirewallRules()
      const blob = new Blob([rules], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `firewall-rules-${new Date().toISOString().split('T')[0]}.txt`
      a.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to export rules:', error)
    }
  }

  const handleResetFirewall = async () => {
    if (
      !confirm(
        'Are you sure you want to reset firewall to default NovusGate configuration? This will remove all custom rules.'
      )
    )
      return
    try {
      await resetFirewallMutation.mutateAsync()
    } catch (error) {
      console.error('Failed to reset firewall:', error)
    }
  }

  // VPN Rule handlers
  const handleVPNRuleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      if (editingVPNRule) {
        await updateVPNRuleMutation.mutateAsync({ id: editingVPNRule.id, request: vpnRuleForm })
      } else {
        await createVPNRuleMutation.mutateAsync(vpnRuleForm)
      }
      setShowVPNRuleModal(false)
      setEditingVPNRule(null)
      resetVPNRuleForm()
    } catch (error) {
      console.error('Failed to save VPN rule:', error)
    }
  }

  const handleEditVPNRule = (rule: VPNFirewallRule) => {
    setEditingVPNRule(rule)
    setVPNRuleForm({
      name: rule.name,
      description: rule.description || '',
      source_type: rule.source_type,
      source_network_id: rule.source_network_id,
      source_node_id: rule.source_node_id,
      source_ip: rule.source_ip,
      dest_type: rule.dest_type,
      dest_network_id: rule.dest_network_id,
      dest_node_id: rule.dest_node_id,
      dest_ip: rule.dest_ip,
      protocol: rule.protocol,
      port: rule.port || '',
      action: rule.action,
      priority: rule.priority,
      enabled: rule.enabled,
    })
    setShowVPNRuleModal(true)
  }

  const handleDeleteVPNRule = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to delete VPN rule "${name}"?`)) return
    try {
      await deleteVPNRuleMutation.mutateAsync(id)
    } catch (error) {
      console.error('Failed to delete VPN rule:', error)
    }
  }

  const resetVPNRuleForm = () => {
    setVPNRuleForm({
      name: '',
      description: '',
      source_type: 'any',
      dest_type: 'any',
      protocol: 'all',
      port: '',
      action: 'accept',
      priority: 100,
      enabled: true,
    })
  }

  const tabs = [
    { id: 'overview' as TabId, label: 'Overview', icon: Shield },
    { id: 'host-rules' as TabId, label: 'Host Rules', icon: Lock },
    { id: 'open-ports' as TabId, label: 'Open Ports', icon: Globe, count: openPorts },
    { id: 'vpn-rules' as TabId, label: 'VPN Rules', icon: Network, count: vpnRuleCount },
    { id: 'blocked-ips' as TabId, label: 'Blocked IPs', icon: Ban, count: blockedIPs },
  ]

  // Quick Actions Component - shown in all tabs
  const QuickActionsBar = () => (
    <Card className="p-4 mb-4">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-2 flex-wrap">
          <Button variant="primary" size="sm" onClick={() => setShowOpenPortModal(true)}>
            <Plus className="w-4 h-4 mr-1" /> Open Port
          </Button>
          <Button variant="danger" size="sm" onClick={() => setShowBlockIPModal(true)}>
            <Ban className="w-4 h-4 mr-1" /> Block IP
          </Button>
          <Button variant="secondary" size="sm" onClick={() => setShowAllowIPModal(true)}>
            <CheckCircle className="w-4 h-4 mr-1" /> Allow IP
          </Button>
          {activeTab === 'vpn-rules' && (
            <Button
              variant="primary"
              size="sm"
              onClick={() => {
                resetVPNRuleForm()
                setEditingVPNRule(null)
                setShowVPNRuleModal(true)
              }}
            >
              <Plus className="w-4 h-4 mr-1" /> VPN Rule
            </Button>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={handleExportRules} title="Export Rules">
            <Download className="w-4 h-4" />
          </Button>
          <Button variant="ghost" size="sm" onClick={handleRefresh} title="Refresh">
            <RefreshCw className="w-4 h-4" />
          </Button>
        </div>
      </div>
    </Card>
  )

  if (rulesLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Firewall Management"
        description="Manage host firewall rules and VPN network traffic control"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" onClick={handleExportRules}>
              <Download className="w-4 h-4 mr-1" /> Export
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleResetFirewall}
              loading={resetFirewallMutation.isPending}
            >
              <RotateCcw className="w-4 h-4 mr-1" /> Reset
            </Button>
            <Button variant="secondary" size="sm" onClick={handleRefresh}>
              <RefreshCw className="w-4 h-4 mr-1" /> Refresh
            </Button>
          </div>
        }
      />

      {/* Tab Navigation */}
      <div className="flex gap-1 p-1 bg-gray-100 dark:bg-gray-800 rounded-lg overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-md whitespace-nowrap transition-colors ${
              activeTab === tab.id
                ? 'bg-white dark:bg-gray-700 text-blue-600 dark:text-blue-400 shadow-sm'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
            {tab.count !== undefined && tab.count > 0 && (
              <span className="px-1.5 py-0.5 text-xs bg-red-100 dark:bg-red-900/50 text-red-600 dark:text-red-400 rounded-full">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Quick Actions Bar - shown in all tabs except Overview */}
      {activeTab !== 'overview' && <QuickActionsBar />}

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <OverviewTab
          chains={chains}
          totalRules={totalRules}
          blockedIPs={blockedIPs}
          openPorts={openPorts}
          vpnRuleCount={vpnRuleCount}
          onOpenPort={() => setShowOpenPortModal(true)}
          onBlockIP={() => setShowBlockIPModal(true)}
          onAllowIP={() => setShowAllowIPModal(true)}
        />
      )}

      {/* Host Rules Tab */}
      {activeTab === 'host-rules' && (
        <HostRulesTab
          chains={chains}
          selectedChain={selectedChain}
          onChainChange={setSelectedChain}
          currentChain={currentChain}
          onDeleteRule={handleDeleteRule}
          deleteLoading={deleteRuleMutation.isPending}
        />
      )}

      {/* Open Ports Tab */}
      {activeTab === 'open-ports' && (
        <OpenPortsTab
          openPorts={getOpenPorts()}
          onClosePort={handleClosePort}
          closeLoading={closePortMutation.isPending}
        />
      )}

      {/* VPN Rules Tab */}
      {activeTab === 'vpn-rules' && (
        <VPNRulesTab
          rules={vpnRules || []}
          loading={vpnLoading}
          onEditRule={handleEditVPNRule}
          onDeleteRule={handleDeleteVPNRule}
          onApplyRules={() => applyVPNRulesMutation.mutate()}
          applyLoading={applyVPNRulesMutation.isPending}
          deleteLoading={deleteVPNRuleMutation.isPending}
        />
      )}

      {/* Blocked IPs Tab */}
      {activeTab === 'blocked-ips' && (
        <BlockedIPsTab
          blockedIPs={getBlockedIPs()}
          onUnblock={handleUnblockIP}
          unblockLoading={deleteRuleMutation.isPending}
        />
      )}

      {/* Open Port Modal */}
      <Modal
        isOpen={showOpenPortModal}
        onClose={() => setShowOpenPortModal(false)}
        title="Open Port"
        size="md"
      >
        <form onSubmit={handleOpenPort} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Port Number</label>
            <input
              type="number"
              required
              min="1"
              max="65535"
              value={openPortForm.port}
              onChange={(e) => setOpenPortForm({ ...openPortForm, port: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder="e.g., 8080"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Protocol</label>
            <select
              value={openPortForm.protocol}
              onChange={(e) => setOpenPortForm({ ...openPortForm, protocol: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="both">Both</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Source IP (Optional)</label>
            <input
              type="text"
              value={openPortForm.source}
              onChange={(e) => setOpenPortForm({ ...openPortForm, source: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder="e.g., 192.168.1.0/24 (leave empty for any)"
            />
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" type="button" onClick={() => setShowOpenPortModal(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" loading={openPortMutation.isPending}>
              Open Port
            </Button>
          </div>
        </form>
      </Modal>

      {/* Block IP Modal */}
      <Modal
        isOpen={showBlockIPModal}
        onClose={() => setShowBlockIPModal(false)}
        title="Block IP Address"
        size="md"
      >
        <form onSubmit={handleBlockIP} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">IP Address or CIDR</label>
            <input
              type="text"
              required
              value={blockIPForm.ip}
              onChange={(e) => setBlockIPForm({ ...blockIPForm, ip: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder="e.g., 192.168.1.100 or 10.0.0.0/8"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Ports (Optional)</label>
            <input
              type="text"
              value={blockIPForm.ports}
              onChange={(e) => setBlockIPForm({ ...blockIPForm, ports: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder="e.g., 22,80,443 (leave empty for all ports)"
            />
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" type="button" onClick={() => setShowBlockIPModal(false)}>
              Cancel
            </Button>
            <Button variant="danger" type="submit" loading={blockIPMutation.isPending}>
              Block IP
            </Button>
          </div>
        </form>
      </Modal>

      {/* Allow IP Modal */}
      <Modal
        isOpen={showAllowIPModal}
        onClose={() => setShowAllowIPModal(false)}
        title="Allow IP Address"
        size="md"
      >
        <form onSubmit={handleAllowIP} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">IP Address or CIDR</label>
            <input
              type="text"
              required
              value={allowIPForm.ip}
              onChange={(e) => setAllowIPForm({ ...allowIPForm, ip: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder="e.g., 192.168.1.100 or 10.0.0.0/8"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Ports (Optional)</label>
            <input
              type="text"
              value={allowIPForm.ports}
              onChange={(e) => setAllowIPForm({ ...allowIPForm, ports: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder="e.g., 22,80,443 (leave empty for all ports)"
            />
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" type="button" onClick={() => setShowAllowIPModal(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" loading={allowIPMutation.isPending}>
              Allow IP
            </Button>
          </div>
        </form>
      </Modal>

      {/* VPN Rule Modal */}
      <VPNRuleModal
        isOpen={showVPNRuleModal}
        onClose={() => {
          setShowVPNRuleModal(false)
          setEditingVPNRule(null)
        }}
        form={vpnRuleForm}
        setForm={setVPNRuleForm}
        onSubmit={handleVPNRuleSubmit}
        isEditing={!!editingVPNRule}
        loading={createVPNRuleMutation.isPending || updateVPNRuleMutation.isPending}
        networks={networks || []}
      />
    </div>
  )
}
