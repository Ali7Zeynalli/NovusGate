import { Globe, Server } from 'lucide-react'
import React, { useState } from 'react'
import { api } from '@/api/client'
import { Button, Modal } from '@/components/ui'
import type {
  Network as NetworkType,
  Node,
  VPNEndpointType,
  VPNFirewallAction,
  VPNFirewallProtocol,
  VPNFirewallRuleRequest,
} from '@/types'

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

export const VPNRuleModal = ({
  isOpen,
  onClose,
  form,
  setForm,
  onSubmit,
  isEditing,
  loading,
  networks,
}: VPNRuleModalProps) => {
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
