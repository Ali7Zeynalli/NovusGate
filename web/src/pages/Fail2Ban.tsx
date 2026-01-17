import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle,
  Clock,
  History,
  List,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Settings,
  Shield,
  ShieldOff,
  Trash2,
  Unlock,
  XCircle,
} from 'lucide-react'
import React, { useState } from 'react'
import { api, useFail2BanLogs, useFail2BanStatus, useUnbanIP } from '../api/client'
import { PageHeader } from '../components/Layout'
import { Badge, Button, Card } from '../components/ui'

// Hooks
const useManualBan = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { jail: string; ip: string; permanent: boolean }) =>
      api.banIP(data.jail, data.ip, data.permanent),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['fail2ban'] })
      qc.invalidateQueries({ queryKey: ['permanent-bans'] })
    },
  })
}

const useJailSettings = (jail: string) =>
  useQuery({
    queryKey: ['jail-settings', jail],
    queryFn: () => api.getJailSettings(jail),
    enabled: !!jail,
  })

const useUpdateJailSettings = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { jail: string; bantime?: string; maxretry?: string; findtime?: string }) =>
      api.updateJailSettings(data.jail, data),
    onSuccess: (_, v) => {
      qc.invalidateQueries({ queryKey: ['jail-settings', v.jail] })
      qc.invalidateQueries({ queryKey: ['fail2ban'] })
    },
  })
}

const useWhitelist = (jail: string) =>
  useQuery({
    queryKey: ['whitelist', jail],
    queryFn: () => api.getWhitelist(jail),
    enabled: !!jail,
  })

const useUpdateWhitelist = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { jail: string; action: 'add' | 'remove'; ip: string }) =>
      api.updateWhitelist(data.jail, data.action, data.ip),
    onSuccess: (_, v) => qc.invalidateQueries({ queryKey: ['whitelist', v.jail] }),
  })
}

const usePermanentBans = () =>
  useQuery({ queryKey: ['permanent-bans'], queryFn: () => api.getPermanentBans() })

const useRemovePermanentBan = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (ip: string) => api.removePermanentBan(ip),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['permanent-bans'] }),
  })
}

const useReloadFail2Ban = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (jail?: string) => api.reloadFail2Ban(jail),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fail2ban'] }),
  })
}

const useFail2BanPing = () =>
  useQuery({
    queryKey: ['fail2ban-ping'],
    queryFn: () => api.pingFail2Ban(),
    refetchInterval: 30000,
  })
const useBanHistory = () =>
  useQuery({ queryKey: ['ban-history'], queryFn: () => api.getBanHistory(undefined, 100) })

interface JailData {
  name: string
  banned_count?: number
  total_banned?: number
  failed_count?: number
  total_failed?: number
  banned_ips?: string[]
}
interface LogEntry {
  timestamp?: string
  action?: string
  raw: string
}
interface HistoryEntry {
  timestamp?: string
  action?: string
  jail?: string
  ip?: string
  raw: string
}

export const Fail2BanPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<
    'overview' | 'banned' | 'whitelist' | 'settings' | 'permanent' | 'history' | 'logs'
  >('overview')
  const [selectedJail, setSelectedJail] = useState<string>('sshd')
  const [showBanModal, setShowBanModal] = useState(false)
  const [banForm, setBanForm] = useState({ ip: '', permanent: false })
  const [settingsForm, setSettingsForm] = useState({ bantime: '', maxretry: '', findtime: '' })
  const [newWhitelistIP, setNewWhitelistIP] = useState('')

  const { data: status, isLoading: statusLoading, refetch: refetchStatus } = useFail2BanStatus()
  const { data: logs, refetch: refetchLogs } = useFail2BanLogs(100)
  const { data: jailSettings, refetch: refetchSettings } = useJailSettings(selectedJail)
  const { data: whitelist, refetch: refetchWhitelist } = useWhitelist(selectedJail)
  const { data: permanentBans, refetch: refetchPermanentBans } = usePermanentBans()
  const { data: pingStatus } = useFail2BanPing()
  const { data: banHistory, refetch: refetchHistory } = useBanHistory()

  const unbanMutation = useUnbanIP()
  const banMutation = useManualBan()
  const updateSettingsMutation = useUpdateJailSettings()
  const updateWhitelistMutation = useUpdateWhitelist()
  const removePermanentBanMutation = useRemovePermanentBan()
  const reloadMutation = useReloadFail2Ban()

  const handleRefresh = () => {
    refetchStatus()
    refetchLogs()
    refetchSettings()
    refetchWhitelist()
    refetchPermanentBans()
    refetchHistory()
  }

  // Set default jail when status loads
  React.useEffect(() => {
    if (status?.jails?.length > 0 && !status.jails.find((j: JailData) => j.name === selectedJail)) {
      setSelectedJail(status.jails[0].name)
    }
  }, [status, selectedJail])

  // Load settings when jail changes
  React.useEffect(() => {
    if (jailSettings) {
      setSettingsForm({
        bantime: jailSettings.bantime || '',
        maxretry: jailSettings.maxretry || '',
        findtime: jailSettings.findtime || '',
      })
    }
  }, [jailSettings])

  const formatBantime = (s: string) => {
    const n = parseInt(s, 10)
    if (n === -1) return 'Permanent'
    if (n >= 86400) return `${Math.floor(n / 86400)} days`
    if (n >= 3600) return `${Math.floor(n / 3600)} hours`
    if (n >= 60) return `${Math.floor(n / 60)} min`
    return `${n} sec`
  }

  const currentJail = status?.jails?.find((j: JailData) => j.name === selectedJail)

  if (statusLoading)
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    )

  if (!status?.installed)
    return (
      <div className="space-y-6">
        <PageHeader title="Fail2Ban" description="Intrusion prevention system" />
        <Card className="text-center py-12">
          <ShieldOff className="w-16 h-16 mx-auto text-gray-400 mb-4" />
          <h2 className="text-xl font-semibold mb-2">Fail2Ban Not Installed</h2>
          <p className="text-gray-500">
            Install Fail2Ban to protect your server from brute-force attacks.
          </p>
        </Card>
      </div>
    )

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Shield, count: undefined },
    { id: 'banned', label: 'Banned IPs', icon: Ban, count: currentJail?.banned_count },
    { id: 'whitelist', label: 'Whitelist', icon: CheckCircle, count: undefined },
    { id: 'settings', label: 'Settings', icon: Settings, count: undefined },
    { id: 'permanent', label: 'Permanent Bans', icon: Ban, count: permanentBans?.count },
    { id: 'history', label: 'History', icon: History, count: undefined },
    { id: 'logs', label: 'Logs', icon: List, count: undefined },
  ] as const

  return (
    <div className="space-y-6">
      <PageHeader
        title="Fail2Ban Control Panel"
        description="Intrusion prevention and IP ban management"
      />

      {/* Status Bar */}
      <Card className="p-4">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <Badge variant={status.running ? 'success' : 'danger'} size="md">
              {status.running ? (
                <>
                  <CheckCircle className="w-4 h-4 mr-1" /> Running
                </>
              ) : (
                <>
                  <XCircle className="w-4 h-4 mr-1" /> Stopped
                </>
              )}
            </Badge>
            {pingStatus?.alive && (
              <Badge variant="default" size="md">
                <Activity className="w-4 h-4 mr-1" /> Responsive
              </Badge>
            )}

            {/* Jail Selector */}
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-500">Jail:</span>
              <select
                value={selectedJail}
                onChange={(e) => setSelectedJail(e.target.value)}
                className="px-3 py-1.5 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600 font-medium"
              >
                {status.jails?.map((jail: JailData) => (
                  <option key={jail.name} value={jail.name}>
                    {jail.name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button variant="danger" size="sm" onClick={() => setShowBanModal(true)}>
              <Ban className="w-4 h-4 mr-1" /> Ban IP
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => reloadMutation.mutate(undefined)}
              loading={reloadMutation.isPending}
            >
              <RotateCcw className="w-4 h-4 mr-1" /> Reload
            </Button>
            <Button variant="secondary" size="sm" onClick={handleRefresh}>
              <RefreshCw className="w-4 h-4 mr-1" /> Refresh
            </Button>
          </div>
        </div>
      </Card>

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

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-lg bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
                <Ban className="w-6 h-6 text-red-600 dark:text-red-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500">Currently Banned</p>
                <p className="text-2xl font-bold text-red-600">{currentJail?.banned_count || 0}</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-lg bg-orange-100 dark:bg-orange-900/30 flex items-center justify-center">
                <AlertTriangle className="w-6 h-6 text-orange-600 dark:text-orange-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500">Failed Attempts</p>
                <p className="text-2xl font-bold text-orange-600">
                  {currentJail?.failed_count || 0}
                </p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-lg bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
                <Shield className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500">Total Banned</p>
                <p className="text-2xl font-bold text-blue-600">{currentJail?.total_banned || 0}</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-lg bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
                <Ban className="w-6 h-6 text-purple-600 dark:text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500">Permanent Bans</p>
                <p className="text-2xl font-bold text-purple-600">{permanentBans?.count || 0}</p>
              </div>
            </div>
          </Card>

          {/* Quick Info */}
          <Card className="p-4 md:col-span-2">
            <h3 className="font-semibold mb-3">Current Settings: {selectedJail}</h3>
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <p className="text-xs text-gray-500 mb-1">Ban Time</p>
                <p className="font-bold">{formatBantime(jailSettings?.bantime || '0')}</p>
              </div>
              <div className="text-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <p className="text-xs text-gray-500 mb-1">Max Retry</p>
                <p className="font-bold">{jailSettings?.maxretry || '0'}</p>
              </div>
              <div className="text-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <p className="text-xs text-gray-500 mb-1">Find Time</p>
                <p className="font-bold">{formatBantime(jailSettings?.findtime || '0')}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4 md:col-span-2">
            <h3 className="font-semibold mb-3">All Jails</h3>
            <div className="space-y-2">
              {status.jails?.map((jail: JailData) => (
                <div
                  key={jail.name}
                  className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                >
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-blue-500" />
                    <span className="font-medium">{jail.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {(jail.banned_count || 0) > 0 && (
                      <Badge variant="danger">{jail.banned_count} banned</Badge>
                    )}
                    <Badge variant="default">{jail.failed_count || 0} failed</Badge>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* Banned IPs Tab */}
      {activeTab === 'banned' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold">Banned IPs in {selectedJail}</h3>
            <p className="text-sm text-gray-500">
              IPs currently banned by Fail2Ban (temporary bans)
            </p>
          </div>
          <div className="p-4">
            {currentJail?.banned_ips && currentJail.banned_ips.length > 0 ? (
              <div className="space-y-2">
                {currentJail.banned_ips.map((ip: string) => (
                  <div
                    key={ip}
                    className="flex items-center justify-between p-3 bg-red-50 dark:bg-red-900/20 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <Ban className="w-5 h-5 text-red-500" />
                      <span className="font-mono font-medium">{ip}</span>
                    </div>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        if (confirm(`Unban ${ip}?`))
                          unbanMutation.mutate({ jail: selectedJail, ip })
                      }}
                      loading={unbanMutation.isPending}
                    >
                      <Unlock className="w-4 h-4 mr-1" /> Unban
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <CheckCircle className="w-12 h-12 mx-auto mb-3 text-green-500" />
                <p className="font-medium">No banned IPs</p>
                <p className="text-sm">All clear in {selectedJail} jail</p>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Whitelist Tab */}
      {activeTab === 'whitelist' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold">Whitelist for {selectedJail}</h3>
            <p className="text-sm text-gray-500">IPs that will never be banned</p>
          </div>
          <div className="p-4 space-y-4">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Enter IP or CIDR (e.g., 192.168.1.0/24)"
                value={newWhitelistIP}
                onChange={(e) => setNewWhitelistIP(e.target.value)}
                className="flex-1 px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              />
              <Button
                variant="primary"
                onClick={() => {
                  if (newWhitelistIP) {
                    updateWhitelistMutation.mutate({
                      jail: selectedJail,
                      action: 'add',
                      ip: newWhitelistIP,
                    })
                    setNewWhitelistIP('')
                  }
                }}
                loading={updateWhitelistMutation.isPending}
              >
                <Plus className="w-4 h-4 mr-1" /> Add
              </Button>
            </div>

            {whitelist?.whitelist && whitelist.whitelist.length > 0 ? (
              <div className="space-y-2">
                {whitelist.whitelist.map((ip: string) => (
                  <div
                    key={ip}
                    className="flex items-center justify-between p-3 bg-green-50 dark:bg-green-900/20 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <CheckCircle className="w-5 h-5 text-green-500" />
                      <span className="font-mono font-medium">{ip}</span>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        if (confirm(`Remove ${ip} from whitelist?`))
                          updateWhitelistMutation.mutate({
                            jail: selectedJail,
                            action: 'remove',
                            ip,
                          })
                      }}
                    >
                      <Trash2 className="w-4 h-4 text-red-500" />
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <p>No whitelisted IPs</p>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Settings Tab */}
      {activeTab === 'settings' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold">Settings for {selectedJail}</h3>
            <p className="text-sm text-gray-500">
              Configure ban parameters (changes apply immediately)
            </p>
          </div>
          <div className="p-4 space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <label className="block text-sm font-medium mb-2">Ban Time</label>
                <input
                  type="text"
                  placeholder="3600"
                  value={settingsForm.bantime}
                  onChange={(e) => setSettingsForm({ ...settingsForm, bantime: e.target.value })}
                  className="w-full px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                />
                <p className="text-xs text-gray-500 mt-1">Seconds (-1 = permanent)</p>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Max Retry</label>
                <input
                  type="text"
                  placeholder="3"
                  value={settingsForm.maxretry}
                  onChange={(e) => setSettingsForm({ ...settingsForm, maxretry: e.target.value })}
                  className="w-full px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                />
                <p className="text-xs text-gray-500 mt-1">Failed attempts before ban</p>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Find Time</label>
                <input
                  type="text"
                  placeholder="600"
                  value={settingsForm.findtime}
                  onChange={(e) => setSettingsForm({ ...settingsForm, findtime: e.target.value })}
                  className="w-full px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                />
                <p className="text-xs text-gray-500 mt-1">Time window (seconds)</p>
              </div>
            </div>
            <div className="flex justify-end">
              <Button
                variant="primary"
                onClick={() =>
                  updateSettingsMutation.mutate({ jail: selectedJail, ...settingsForm })
                }
                loading={updateSettingsMutation.isPending}
              >
                <Save className="w-4 h-4 mr-1" /> Save Settings
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* Permanent Bans Tab */}
      {activeTab === 'permanent' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold">Permanent Bans (iptables)</h3>
            <p className="text-sm text-gray-500">
              IPs blocked via firewall rules - persist until manually removed
            </p>
          </div>
          <div className="p-4">
            {permanentBans?.permanent_bans && permanentBans.permanent_bans.length > 0 ? (
              <div className="space-y-2">
                {permanentBans.permanent_bans.map(
                  (ban: { ip: string; line_number: string; protocol: string }) => (
                    <div
                      key={ban.ip}
                      className="flex items-center justify-between p-3 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800"
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-full bg-red-100 dark:bg-red-900/50 flex items-center justify-center">
                          <Ban className="w-5 h-5 text-red-600" />
                        </div>
                        <div>
                          <span className="font-mono font-medium">{ban.ip}</span>
                          <p className="text-xs text-gray-500">
                            Rule #{ban.line_number} • Protocol: {ban.protocol}
                          </p>
                        </div>
                      </div>
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => {
                          if (confirm(`Remove permanent ban for ${ban.ip}?`))
                            removePermanentBanMutation.mutate(ban.ip)
                        }}
                        loading={removePermanentBanMutation.isPending}
                      >
                        <Unlock className="w-4 h-4 mr-1" /> Unblock
                      </Button>
                    </div>
                  )
                )}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <CheckCircle className="w-12 h-12 mx-auto mb-3 text-green-500" />
                <p className="font-medium">No permanent bans</p>
                <p className="text-sm">No IPs are permanently blocked</p>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <div>
              <h3 className="font-semibold">Ban History</h3>
              <p className="text-sm text-gray-500">Recent ban and unban events</p>
            </div>
            <Button variant="ghost" size="sm" onClick={() => refetchHistory()}>
              <RefreshCw className="w-4 h-4" />
            </Button>
          </div>
          <div className="p-4">
            {banHistory?.history && banHistory.history.length > 0 ? (
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {banHistory.history.map((entry: HistoryEntry, i: number) => (
                  <div
                    key={i}
                    className={`flex items-center justify-between p-3 rounded-lg ${entry.action === 'ban' ? 'bg-red-50 dark:bg-red-900/20' : 'bg-green-50 dark:bg-green-900/20'}`}
                  >
                    <div className="flex items-center gap-3">
                      <Badge variant={entry.action === 'ban' ? 'danger' : 'success'}>
                        {entry.action?.toUpperCase()}
                      </Badge>
                      <span className="font-mono">{entry.ip}</span>
                      {entry.jail && <Badge variant="default">{entry.jail}</Badge>}
                    </div>
                    {entry.timestamp && (
                      <span className="text-xs text-gray-500">
                        <Clock className="w-3 h-3 inline mr-1" />
                        {entry.timestamp}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <History className="w-12 h-12 mx-auto mb-3" />
                <p>No history available</p>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Logs Tab */}
      {activeTab === 'logs' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <div>
              <h3 className="font-semibold">Fail2Ban Logs</h3>
              <p className="text-sm text-gray-500">Recent log entries</p>
            </div>
            <Button variant="ghost" size="sm" onClick={() => refetchLogs()}>
              <RefreshCw className="w-4 h-4" />
            </Button>
          </div>
          <div className="p-4">
            {logs?.logs && logs.logs.length > 0 ? (
              <div className="space-y-1 max-h-96 overflow-y-auto font-mono text-xs">
                {logs.logs.map((log: LogEntry, i: number) => (
                  <div
                    key={i}
                    className={`p-2 rounded ${log.action === 'ban' ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300' : log.action === 'unban' ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300' : 'bg-gray-50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-400'}`}
                  >
                    {log.timestamp && <span className="text-gray-500 mr-2">{log.timestamp}</span>}
                    {log.action && (
                      <Badge variant={log.action === 'ban' ? 'danger' : 'success'} size="sm">
                        {log.action.toUpperCase()}
                      </Badge>
                    )}
                    <span className="ml-2 break-all">{log.raw}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <List className="w-12 h-12 mx-auto mb-3" />
                <p>No logs available</p>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Ban Modal */}
      {showBanModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md shadow-xl">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Ban className="w-5 h-5 text-red-500" /> Ban IP Address
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">IP Address</label>
                <input
                  type="text"
                  placeholder="e.g., 192.168.1.100"
                  value={banForm.ip}
                  onChange={(e) => setBanForm({ ...banForm, ip: e.target.value })}
                  className="w-full px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Jail</label>
                <select
                  value={selectedJail}
                  onChange={(e) => setSelectedJail(e.target.value)}
                  className="w-full px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                >
                  {status.jails?.map((jail: JailData) => (
                    <option key={jail.name} value={jail.name}>
                      {jail.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="permanent"
                  checked={banForm.permanent}
                  onChange={(e) => setBanForm({ ...banForm, permanent: e.target.checked })}
                  className="rounded"
                />
                <label htmlFor="permanent" className="text-sm">
                  Permanent ban (via iptables firewall)
                </label>
              </div>
              {banForm.permanent && (
                <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg text-sm text-yellow-700 dark:text-yellow-300 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  <span>
                    Permanent bans are added to iptables and persist until manually removed.
                  </span>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <Button variant="secondary" onClick={() => setShowBanModal(false)}>
                Cancel
              </Button>
              <Button
                variant="danger"
                onClick={() => {
                  if (banForm.ip) {
                    banMutation.mutate({
                      jail: selectedJail,
                      ip: banForm.ip,
                      permanent: banForm.permanent,
                    })
                    setBanForm({ ip: '', permanent: false })
                    setShowBanModal(false)
                  }
                }}
                loading={banMutation.isPending}
              >
                <Ban className="w-4 h-4 mr-1" /> Ban IP
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Fail2BanPage
