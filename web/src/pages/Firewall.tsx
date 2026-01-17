import {
  AlertTriangle,
  ArrowRight,
  Ban,
  CheckCircle,
  Download,
  Globe,
  Info,
  Lock,
  Monitor,
  Network,
  Plus,
  RefreshCw,
  RotateCcw,
  Server,
  Shield,
  Trash2,
  Unlock,
  XCircle,
} from 'lucide-react'
import React, { useState } from 'react'
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
} from '../api/client'
import { PageHeader } from '../components/Layout'
import { Badge, Button, Card, Modal } from '../components/ui'
import type {
  ChainInfo,
  FirewallRule,
  Network as NetworkType,
  Node,
  VPNEndpointType,
  VPNFirewallAction,
  VPNFirewallProtocol,
  VPNFirewallRule,
  VPNFirewallRuleRequest,
} from '../types'

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

// Overview Tab Component
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

const OverviewTab: React.FC<OverviewTabProps> = ({
  chains,
  totalRules,
  blockedIPs,
  openPorts,
  vpnRuleCount,
  onOpenPort,
  onBlockIP,
  onAllowIP,
}) => {
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

// Host Rules Tab Component
interface HostRulesTabProps {
  chains: ChainInfo[]
  selectedChain: string
  onChainChange: (chain: string) => void
  currentChain?: ChainInfo
  onDeleteRule: (chain: string, lineNumber: number, isProtected: boolean) => void
  deleteLoading: boolean
}

const HostRulesTab: React.FC<HostRulesTabProps> = ({
  chains,
  selectedChain,
  onChainChange,
  currentChain,
  onDeleteRule,
  deleteLoading,
}) => {
  return (
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
}

// VPN Rules Tab Component
interface VPNRulesTabProps {
  rules: VPNFirewallRule[]
  loading: boolean
  onEditRule: (rule: VPNFirewallRule) => void
  onDeleteRule: (id: string, name: string) => void
  onApplyRules: () => void
  applyLoading: boolean
  deleteLoading: boolean
}

const VPNRulesTab: React.FC<VPNRulesTabProps> = ({
  rules,
  loading,
  onEditRule,
  onDeleteRule,
  onApplyRules,
  applyLoading,
  deleteLoading,
}) => {
  const getEndpointDisplay = (rule: VPNFirewallRule, type: 'source' | 'dest') => {
    const endpointType = type === 'source' ? rule.source_type : rule.dest_type
    const networkName = type === 'source' ? rule.source_network_name : rule.dest_network_name
    const nodeName = type === 'source' ? rule.source_node_name : rule.dest_node_name
    const ip = type === 'source' ? rule.source_ip : rule.dest_ip

    switch (endpointType) {
      case 'any':
        return <span className="text-gray-500">Any</span>
      case 'network':
        return (
          <span className="flex items-center gap-1">
            <Network className="w-3 h-3 text-blue-500" />
            {networkName || 'Unknown Network'}
          </span>
        )
      case 'node':
        return (
          <span className="flex items-center gap-1">
            <Server className="w-3 h-3 text-green-500" />
            {nodeName || 'Unknown Node'}
          </span>
        )
      case 'custom':
        return <span className="font-mono text-sm">{ip}</span>
      default:
        return <span className="text-gray-500">-</span>
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Apply Rules Button */}
      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-gray-500">
              Traffic control between VPN networks (FORWARD chain)
            </p>
          </div>
          <Button variant="secondary" size="sm" onClick={onApplyRules} loading={applyLoading}>
            <RefreshCw className="w-4 h-4 mr-1" /> Apply Rules
          </Button>
        </div>
      </Card>

      {/* Rules List */}
      <Card padding="none">
        {rules.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Priority
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Name
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Source
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Destination
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Protocol
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Port
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Action
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {rules.map((rule) => (
                  <tr key={rule.id} className={!rule.enabled ? 'opacity-50' : ''}>
                    <td className="px-4 py-3 text-sm font-mono">{rule.priority}</td>
                    <td className="px-4 py-3">
                      <div>
                        <p className="font-medium">{rule.name}</p>
                        {rule.description && (
                          <p className="text-xs text-gray-500 truncate max-w-[200px]">
                            {rule.description}
                          </p>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm">{getEndpointDisplay(rule, 'source')}</td>
                    <td className="px-4 py-3 text-sm">{getEndpointDisplay(rule, 'dest')}</td>
                    <td className="px-4 py-3 text-sm uppercase">{rule.protocol}</td>
                    <td className="px-4 py-3 text-sm font-mono">{rule.port || 'all'}</td>
                    <td className="px-4 py-3">
                      <Badge
                        variant={
                          rule.action === 'accept'
                            ? 'success'
                            : rule.action === 'drop'
                              ? 'danger'
                              : 'warning'
                        }
                      >
                        {rule.action === 'accept'
                          ? 'ACCEPT'
                          : rule.action === 'drop'
                            ? 'DROP'
                            : 'REJECT'}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant={rule.enabled ? 'success' : 'default'}>
                        {rule.enabled ? 'Active' : 'Disabled'}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => onEditRule(rule)}
                          title="Edit"
                        >
                          <Shield className="w-4 h-4 text-blue-500" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => onDeleteRule(rule.id, rule.name)}
                          loading={deleteLoading}
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4 text-red-500" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 px-6">
            <div className="max-w-3xl mx-auto">
              {/* Header */}
              <div className="text-center mb-8">
                <div className="w-16 h-16 rounded-full bg-gradient-to-br from-purple-100 to-indigo-100 dark:from-purple-900/30 dark:to-indigo-900/30 flex items-center justify-center mx-auto mb-4">
                  <Network className="w-8 h-8 text-purple-600 dark:text-purple-400" />
                </div>
                <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                  VPN Inter-Network Rules
                </h3>
                <p className="text-gray-600 dark:text-gray-400">
                  Define how traffic flows between VPN networks
                </p>
              </div>

              {/* What is VPN Rules */}
              <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-5 mb-6">
                <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-3 flex items-center gap-2">
                  <Info className="w-5 h-5" />
                  What are VPN Rules?
                </h4>
                <p className="text-blue-800 dark:text-blue-200 text-sm leading-relaxed">
                  VPN rules control the server's{' '}
                  <code className="bg-blue-100 dark:bg-blue-800 px-1.5 py-0.5 rounded text-xs font-mono">
                    FORWARD
                  </code>{' '}
                  chain. These rules determine whether traffic can pass between different VPN
                  networks. Since all VPN traffic flows through the server, these rules provide
                  complete control over inter-network communication.
                </p>
              </div>

              {/* Use Cases */}
              <div className="grid md:grid-cols-2 gap-4 mb-6">
                <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-4">
                  <h5 className="font-medium text-green-900 dark:text-green-100 mb-2 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" />
                    Allow Traffic
                  </h5>
                  <ul className="text-sm text-green-800 dark:text-green-200 space-y-1.5">
                    <li>• Access admin panel from office network</li>
                    <li>• Allow specific nodes to reach other networks</li>
                    <li>• Permit only certain ports (HTTP, SSH)</li>
                  </ul>
                </div>
                <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
                  <h5 className="font-medium text-red-900 dark:text-red-100 mb-2 flex items-center gap-2">
                    <XCircle className="w-4 h-4" />
                    Block Traffic
                  </h5>
                  <ul className="text-sm text-red-800 dark:text-red-200 space-y-1.5">
                    <li>• Complete isolation between networks</li>
                    <li>• Restrict access to sensitive resources</li>
                    <li>• Block specific protocols</li>
                  </ul>
                </div>
              </div>

              {/* How it works */}
              <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-5 mb-6">
                <h4 className="font-semibold text-gray-900 dark:text-white mb-3">How It Works</h4>
                <div className="flex items-center justify-between text-sm mb-4">
                  <div className="text-center">
                    <div className="w-12 h-12 rounded-lg bg-blue-100 dark:bg-blue-900/50 flex items-center justify-center mx-auto mb-2">
                      <Monitor className="w-6 h-6 text-blue-600" />
                    </div>
                    <span className="text-gray-600 dark:text-gray-400">Source Node</span>
                  </div>
                  <ArrowRight className="w-5 h-5 text-gray-400" />
                  <div className="text-center">
                    <div className="w-12 h-12 rounded-lg bg-purple-100 dark:bg-purple-900/50 flex items-center justify-center mx-auto mb-2">
                      <Server className="w-6 h-6 text-purple-600" />
                    </div>
                    <span className="text-gray-600 dark:text-gray-400">VPN Server</span>
                    <div className="text-xs text-purple-600 dark:text-purple-400 mt-1">
                      FORWARD rules
                    </div>
                  </div>
                  <ArrowRight className="w-5 h-5 text-gray-400" />
                  <div className="text-center">
                    <div className="w-12 h-12 rounded-lg bg-green-100 dark:bg-green-900/50 flex items-center justify-center mx-auto mb-2">
                      <Monitor className="w-6 h-6 text-green-600" />
                    </div>
                    <span className="text-gray-600 dark:text-gray-400">Destination Node</span>
                  </div>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  All VPN traffic flows through the server. VPN rules are applied on the server and
                  determine which traffic can be forwarded.
                </p>
              </div>

              {/* Important Note */}
              <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4 mb-6">
                <h5 className="font-medium text-amber-900 dark:text-amber-100 mb-2 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Important Note
                </h5>
                <p className="text-sm text-amber-800 dark:text-amber-200">
                  When you create a VPN rule, the source node's{' '}
                  <code className="bg-amber-100 dark:bg-amber-800 px-1.5 py-0.5 rounded text-xs font-mono">
                    AllowedIPs
                  </code>{' '}
                  configuration is automatically updated. However, existing connected devices may
                  need to reload their configuration.
                </p>
              </div>

              {/* Quick Start */}
              <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-5">
                <h4 className="font-semibold text-gray-900 dark:text-white mb-4">
                  Getting Started
                </h4>
                <ol className="space-y-3 text-sm">
                  <li className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-purple-100 dark:bg-purple-900/50 text-purple-600 dark:text-purple-400 flex items-center justify-center text-xs font-bold">
                      1
                    </span>
                    <span className="text-gray-600 dark:text-gray-400">
                      Click the{' '}
                      <strong className="text-gray-900 dark:text-white">"VPN Rule"</strong> button
                      above
                    </span>
                  </li>
                  <li className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-purple-100 dark:bg-purple-900/50 text-purple-600 dark:text-purple-400 flex items-center justify-center text-xs font-bold">
                      2
                    </span>
                    <span className="text-gray-600 dark:text-gray-400">
                      Select source and destination network/node
                    </span>
                  </li>
                  <li className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-purple-100 dark:bg-purple-900/50 text-purple-600 dark:text-purple-400 flex items-center justify-center text-xs font-bold">
                      3
                    </span>
                    <span className="text-gray-600 dark:text-gray-400">
                      Choose protocol and port (optional)
                    </span>
                  </li>
                  <li className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-purple-100 dark:bg-purple-900/50 text-purple-600 dark:text-purple-400 flex items-center justify-center text-xs font-bold">
                      4
                    </span>
                    <span className="text-gray-600 dark:text-gray-400">
                      Select action: <strong className="text-green-600">Accept</strong> (allow) or{' '}
                      <strong className="text-red-600">Drop</strong> (block)
                    </span>
                  </li>
                </ol>
              </div>
            </div>
          </div>
        )}
      </Card>
    </div>
  )
}

// Open Ports Tab Component
interface OpenPortsTabProps {
  openPorts: FirewallRule[]
  onClosePort: (port: number, protocol: string, isProtected: boolean) => void
  closeLoading: boolean
}

const OpenPortsTab: React.FC<OpenPortsTabProps> = ({ openPorts, onClosePort, closeLoading }) => {
  // Parse port number from rule - handles formats like "22", "dpt:22", "8000:9000"
  const parsePort = (portStr: string | undefined): number => {
    if (!portStr || portStr === '-') return 0
    // Extract first number from string (handles "dpt:22", "22", etc.)
    const match = portStr.match(/(\d+)/)
    return match ? parseInt(match[1], 10) : 0
  }

  // Handle close port with validation
  const handleClosePortClick = (rule: FirewallRule) => {
    const port = parsePort(rule.port)
    if (port === 0) {
      alert('Invalid port number')
      return
    }
    // Ensure protocol is lowercase and valid for close port operation
    let protocol = (rule.protocol || 'tcp').toLowerCase()
    // If protocol is 'all' or 'icmp', default to 'both' for tcp/udp
    if (protocol === 'all' || protocol === 'icmp') {
      protocol = 'both'
    }
    onClosePort(port, protocol, rule.protected)
  }

  return (
    <div className="space-y-4">
      {/* Open Ports List */}
      <Card padding="none">
        {openPorts.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Port
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Protocol
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Source
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Interface
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {openPorts.map((rule, index) => (
                  <tr
                    key={`${rule.chain}-${rule.number}-${index}`}
                    className={rule.protected ? 'bg-yellow-50 dark:bg-yellow-900/10' : ''}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-full bg-green-100 dark:bg-green-900/50 flex items-center justify-center">
                          <Globe className="w-4 h-4 text-green-600" />
                        </div>
                        <span className="font-mono font-bold text-lg">{rule.port}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="info">{rule.protocol.toUpperCase()}</Badge>
                    </td>
                    <td className="px-4 py-3 text-sm font-mono">
                      {rule.source === 'anywhere' || rule.source === '0.0.0.0/0' ? (
                        <span className="text-gray-500">Any</span>
                      ) : (
                        rule.source
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {rule.in_interface || rule.interface || '-'}
                    </td>
                    <td className="px-4 py-3">
                      {rule.protected ? (
                        <Badge variant="warning">
                          <Lock className="w-3 h-3 mr-1" /> Protected
                        </Badge>
                      ) : (
                        <Badge variant="success">Open</Badge>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {rule.protected ? (
                        <span className="flex items-center gap-1 text-xs text-yellow-600 dark:text-yellow-400">
                          <Lock className="w-3 h-3" /> SSH/WireGuard/API
                        </span>
                      ) : (
                        <Button
                          variant="danger"
                          size="sm"
                          onClick={() => handleClosePortClick(rule)}
                          loading={closeLoading}
                        >
                          <XCircle className="w-4 h-4 mr-1" /> Close
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-12 text-gray-500">
            <Globe className="w-12 h-12 mx-auto mb-3 text-gray-400" />
            <p className="font-medium">No open ports</p>
            <p className="text-sm">Use the "Open Port" button above</p>
          </div>
        )}
      </Card>

      {/* Info Card */}
      <Card className="p-4 bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-blue-600 dark:text-blue-400 mt-0.5" />
          <div>
            <h4 className="font-medium text-blue-700 dark:text-blue-300">Protected Ports</h4>
            <p className="text-sm text-blue-600 dark:text-blue-400 mt-1">
              SSH (22), WireGuard (51820+) and Admin API ports are protected and cannot be closed.
              Closing these ports could disconnect you from the server.
            </p>
          </div>
        </div>
      </Card>
    </div>
  )
}

// Blocked IPs Tab Component
interface BlockedIPsTabProps {
  blockedIPs: FirewallRule[]
  onUnblock: (chain: string, lineNumber: number) => void
  unblockLoading: boolean
}

const BlockedIPsTab: React.FC<BlockedIPsTabProps> = ({ blockedIPs, onUnblock, unblockLoading }) => {
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

// VPN Rule Modal Component
interface VPNRuleModalProps {
  isOpen: boolean
  onClose: () => void
  form: VPNFirewallRuleRequest
  setForm: React.Dispatch<React.SetStateAction<VPNFirewallRuleRequest>>
  onSubmit: (e: React.FormEvent) => void
  isEditing: boolean
  loading: boolean
  networks: NetworkType[]
}

const VPNRuleModal: React.FC<VPNRuleModalProps> = ({
  isOpen,
  onClose,
  form,
  setForm,
  onSubmit,
  isEditing,
  loading,
  networks,
}) => {
  const [sourceNodes, setSourceNodes] = useState<Node[]>([])
  const [destNodes, setDestNodes] = useState<Node[]>([])

  // Fetch nodes when network changes
  React.useEffect(() => {
    if (form.source_type === 'node' && form.source_network_id) {
      api
        .getNodes(form.source_network_id)
        .then(setSourceNodes)
        .catch(() => setSourceNodes([]))
    } else {
      setSourceNodes([])
    }
  }, [form.source_network_id, form.source_type])

  React.useEffect(() => {
    if (form.dest_type === 'node' && form.dest_network_id) {
      api
        .getNodes(form.dest_network_id)
        .then(setDestNodes)
        .catch(() => setDestNodes([]))
    } else {
      setDestNodes([])
    }
  }, [form.dest_network_id, form.dest_type])

  const endpointTypes: { value: VPNEndpointType; label: string }[] = [
    { value: 'any', label: 'Any' },
    { value: 'network', label: 'Network' },
    { value: 'node', label: 'Node' },
    { value: 'custom', label: 'Custom IP' },
  ]

  const protocols: { value: VPNFirewallProtocol; label: string }[] = [
    { value: 'all', label: 'All' },
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
    { value: 'icmp', label: 'ICMP' },
  ]

  const actions: { value: VPNFirewallAction; label: string }[] = [
    { value: 'accept', label: 'Accept' },
    { value: 'drop', label: 'Drop' },
    { value: 'reject', label: 'Reject' },
  ]

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={isEditing ? 'Edit VPN Rule' : 'Add VPN Rule'}
      size="lg"
    >
      <form onSubmit={onSubmit} className="space-y-4">
        {/* Basic Info */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Rule Name</label>
            <input
              type="text"
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder="e.g., Allow Web Traffic"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Priority</label>
            <input
              type="number"
              required
              min="1"
              max="1000"
              value={form.priority}
              onChange={(e) => setForm({ ...form, priority: parseInt(e.target.value, 10) || 100 })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
            />
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">Description (Optional)</label>
          <input
            type="text"
            value={form.description || ''}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
            placeholder="Brief description of this rule"
          />
        </div>

        {/* Source */}
        <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg space-y-3">
          <h4 className="font-medium flex items-center gap-2">
            <Globe className="w-4 h-4" /> Source
          </h4>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1">Type</label>
              <select
                value={form.source_type}
                onChange={(e) =>
                  setForm({
                    ...form,
                    source_type: e.target.value as VPNEndpointType,
                    source_network_id: undefined,
                    source_node_id: undefined,
                    source_ip: undefined,
                  })
                }
                className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              >
                {endpointTypes.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
            {form.source_type === 'network' && (
              <div>
                <label className="block text-sm font-medium mb-1">Network</label>
                <select
                  value={form.source_network_id || ''}
                  onChange={(e) =>
                    setForm({ ...form, source_network_id: e.target.value || undefined })
                  }
                  className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                >
                  <option value="">Select Network</option>
                  {networks.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name} ({n.cidr})
                    </option>
                  ))}
                </select>
              </div>
            )}
            {form.source_type === 'node' && (
              <>
                <div>
                  <label className="block text-sm font-medium mb-1">Network</label>
                  <select
                    value={form.source_network_id || ''}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        source_network_id: e.target.value || undefined,
                        source_node_id: undefined,
                      })
                    }
                    className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                  >
                    <option value="">Select Network</option>
                    {networks.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="col-span-2">
                  <label className="block text-sm font-medium mb-1">Node</label>
                  <select
                    value={form.source_node_id || ''}
                    onChange={(e) =>
                      setForm({ ...form, source_node_id: e.target.value || undefined })
                    }
                    className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                    disabled={!form.source_network_id}
                  >
                    <option value="">Select Node</option>
                    {sourceNodes.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name} ({n.virtual_ip})
                      </option>
                    ))}
                  </select>
                </div>
              </>
            )}
            {form.source_type === 'custom' && (
              <div>
                <label className="block text-sm font-medium mb-1">IP/CIDR</label>
                <input
                  type="text"
                  value={form.source_ip || ''}
                  onChange={(e) => setForm({ ...form, source_ip: e.target.value })}
                  className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                  placeholder="e.g., 10.10.0.0/24"
                />
              </div>
            )}
          </div>
        </div>

        {/* Destination */}
        <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg space-y-3">
          <h4 className="font-medium flex items-center gap-2">
            <Server className="w-4 h-4" /> Destination
          </h4>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1">Type</label>
              <select
                value={form.dest_type}
                onChange={(e) =>
                  setForm({
                    ...form,
                    dest_type: e.target.value as VPNEndpointType,
                    dest_network_id: undefined,
                    dest_node_id: undefined,
                    dest_ip: undefined,
                  })
                }
                className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              >
                {endpointTypes.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
            {form.dest_type === 'network' && (
              <div>
                <label className="block text-sm font-medium mb-1">Network</label>
                <select
                  value={form.dest_network_id || ''}
                  onChange={(e) =>
                    setForm({ ...form, dest_network_id: e.target.value || undefined })
                  }
                  className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                >
                  <option value="">Select Network</option>
                  {networks.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name} ({n.cidr})
                    </option>
                  ))}
                </select>
              </div>
            )}
            {form.dest_type === 'node' && (
              <>
                <div>
                  <label className="block text-sm font-medium mb-1">Network</label>
                  <select
                    value={form.dest_network_id || ''}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        dest_network_id: e.target.value || undefined,
                        dest_node_id: undefined,
                      })
                    }
                    className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                  >
                    <option value="">Select Network</option>
                    {networks.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="col-span-2">
                  <label className="block text-sm font-medium mb-1">Node</label>
                  <select
                    value={form.dest_node_id || ''}
                    onChange={(e) =>
                      setForm({ ...form, dest_node_id: e.target.value || undefined })
                    }
                    className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                    disabled={!form.dest_network_id}
                  >
                    <option value="">Select Node</option>
                    {destNodes.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name} ({n.virtual_ip})
                      </option>
                    ))}
                  </select>
                </div>
              </>
            )}
            {form.dest_type === 'custom' && (
              <div>
                <label className="block text-sm font-medium mb-1">IP/CIDR</label>
                <input
                  type="text"
                  value={form.dest_ip || ''}
                  onChange={(e) => setForm({ ...form, dest_ip: e.target.value })}
                  className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                  placeholder="e.g., 10.10.0.0/24"
                />
              </div>
            )}
          </div>
        </div>

        {/* Protocol, Port, Action */}
        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Protocol</label>
            <select
              value={form.protocol}
              onChange={(e) =>
                setForm({ ...form, protocol: e.target.value as VPNFirewallProtocol })
              }
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
            >
              {protocols.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Port (Optional)</label>
            <input
              type="text"
              value={form.port || ''}
              onChange={(e) => setForm({ ...form, port: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder="e.g., 80 or 8000-9000"
              disabled={form.protocol === 'icmp' || form.protocol === 'all'}
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Action</label>
            <select
              value={form.action}
              onChange={(e) => setForm({ ...form, action: e.target.value as VPNFirewallAction })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
            >
              {actions.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Enabled Toggle */}
        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="enabled"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            className="rounded"
          />
          <label htmlFor="enabled" className="text-sm">
            Rule is enabled
          </label>
        </div>

        {/* Submit */}
        <div className="flex justify-end gap-2 pt-4 border-t dark:border-gray-700">
          <Button variant="secondary" type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" loading={loading}>
            {isEditing ? 'Update Rule' : 'Create Rule'}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
