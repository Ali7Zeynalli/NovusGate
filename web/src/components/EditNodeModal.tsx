import { Clock, Power, PowerOff } from 'lucide-react'
import type React from 'react'
import { useEffect, useMemo, useState } from 'react'
import type { Node } from '@/types'
import { Button, Input, Modal, Select } from '@/components/ui'

interface EditNodeModalProps {
  isOpen: boolean
  onClose: () => void
  node: Node | null
  onSubmit: (data: {
    name: string
    expires_at?: string | null
    status?: string
    node_info?: { os: string; arch: string; hostname: string }
  }) => void
  isLoading?: boolean
}

// Helper to get minimum datetime for the date picker (current time)
const getMinDateTime = () => {
  const now = new Date()
  now.setMinutes(now.getMinutes() - now.getTimezoneOffset())
  return now.toISOString().slice(0, 16)
}

export const EditNodeModal = ({
  isOpen,
  onClose,
  node,
  onSubmit,
  isLoading,
}: EditNodeModalProps) => {
  const [name, setName] = useState('')
  const [expiryType, setExpiryType] = useState('keep')
  const [customDate, setCustomDate] = useState('')
  const [status, setStatus] = useState<string>('')
  const [os, setOs] = useState('')
  const [arch, setArch] = useState('')
  const [hostname, setHostname] = useState('')

  useEffect(() => {
    if (node) {
      setName(node.name)
      setStatus(node.status)
      setOs(node.node_info?.os || '')
      setArch(node.node_info?.arch || '')
      setHostname(node.node_info?.hostname || '')

      if (node.expires_at) {
        setExpiryType('existing')
        // Convert to local datetime for the input
        const d = new Date(node.expires_at)
        d.setMinutes(d.getMinutes() - d.getTimezoneOffset())
        setCustomDate(d.toISOString().slice(0, 16))
      } else {
        setExpiryType('keep')
        setCustomDate('')
      }
    }
  }, [node, isOpen])

  const expiryOptions = useMemo(
    () => [
      { value: 'keep', label: node?.expires_at ? 'Keep Current' : 'Forever (No limit)' },
      { value: 'forever', label: 'Remove Limit (Forever)' },
      { value: '1h', label: 'Extend +1 Hour' },
      { value: '1d', label: 'Extend +1 Day' },
      { value: '1w', label: 'Extend +1 Week' },
      { value: 'custom', label: 'Set Custom Date' },
    ],
    [node?.expires_at]
  )

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    let expiresAt: string | null | undefined // undefined means no change
    const now = new Date()

    if (expiryType === 'forever') {
      expiresAt = null // Remove expiration
    } else if (expiryType === '1h') {
      const base = node?.expires_at ? new Date(node.expires_at) : now
      expiresAt = new Date(Math.max(base.getTime(), now.getTime()) + 60 * 60 * 1000).toISOString()
    } else if (expiryType === '1d') {
      const base = node?.expires_at ? new Date(node.expires_at) : now
      expiresAt = new Date(
        Math.max(base.getTime(), now.getTime()) + 24 * 60 * 60 * 1000
      ).toISOString()
    } else if (expiryType === '1w') {
      const base = node?.expires_at ? new Date(node.expires_at) : now
      expiresAt = new Date(
        Math.max(base.getTime(), now.getTime()) + 7 * 24 * 60 * 60 * 1000
      ).toISOString()
    } else if (expiryType === 'custom' && customDate) {
      const selectedDate = new Date(customDate)
      const minDate = node?.expires_at ? new Date(node.expires_at) : now
      if (selectedDate <= now) {
        alert('Expiration date must be in the future!')
        return
      }
      if (node?.expires_at && selectedDate < minDate) {
        alert('Expiration date cannot be earlier than the minimum date!')
        return
      }
      expiresAt = selectedDate.toISOString()
    } else if (expiryType === 'existing' && customDate) {
      // User modified the existing date
      const selectedDate = new Date(customDate)
      const originalDate = node?.expires_at ? new Date(node.expires_at) : now
      if (selectedDate <= now) {
        alert('Expiration date must be in the future!')
        return
      }
      // Only allow extending, not reducing
      if (selectedDate < originalDate) {
        alert('Cannot reduce expiration time! You can only extend it.')
        return
      }
      expiresAt = selectedDate.toISOString()
    }

    onSubmit({
      name,
      expires_at: expiresAt,
      status: status !== node?.status ? status : undefined,
      node_info: { os, arch, hostname },
    })
  }

  const isExpired = node?.status === 'expired'
  const _canReactivate = isExpired || node?.status === 'offline'

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Edit: ${node?.name || 'Node'}`}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Peer Name"
          placeholder="e.g. My Phone, Office Laptop"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />

        {/* Status Control */}
        <div className="space-y-2">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Status
          </label>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setStatus('pending')}
              className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-lg border transition-colors ${
                status === 'pending'
                  ? 'bg-green-100 border-green-500 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                  : 'border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800'
              }`}
            >
              <Power className="w-4 h-4" />
              Active
            </button>
            <button
              type="button"
              onClick={() => setStatus('expired')}
              className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-lg border transition-colors ${
                status === 'expired'
                  ? 'bg-red-100 border-red-500 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                  : 'border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800'
              }`}
            >
              <PowerOff className="w-4 h-4" />
              Disabled
            </button>
          </div>
        </div>

        {/* Expiration Control */}
        <div className="space-y-1">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Expiration
          </label>
          <Select
            options={expiryOptions}
            value={expiryType}
            onChange={(e) => setExpiryType(e.target.value)}
          />
        </div>

        {(expiryType === 'custom' || expiryType === 'existing') && (
          <Input
            label="Expiration Date & Time"
            type="datetime-local"
            value={customDate}
            min={getMinDateTime()}
            onChange={(e) => {
              setCustomDate(e.target.value)
              if (expiryType === 'existing') setExpiryType('custom')
            }}
            required
          />
        )}

        {expiryType !== 'keep' &&
          expiryType !== 'existing' &&
          expiryType !== 'forever' &&
          expiryType !== 'custom' && (
            <div className="flex items-center gap-2 text-xs text-blue-600 bg-blue-50 dark:bg-blue-900/20 p-2 rounded-lg">
              <Clock className="w-4 h-4" />
              <span>This will extend the current expiration time.</span>
            </div>
          )}

        {isExpired && status !== 'expired' && (
          <div className="flex items-center gap-2 text-xs text-amber-600 bg-amber-50 dark:bg-amber-900/20 p-2 rounded-lg">
            <Power className="w-4 h-4" />
            <span>Node will be reactivated and added back to WireGuard.</span>
          </div>
        )}

        {/* Metadata Controls */}
        <div className="space-y-4 pt-4 border-t border-gray-100 dark:border-gray-700">
          <h4 className="text-sm font-medium text-gray-900 dark:text-white">
            Device Information (Optional)
          </h4>
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="OS"
              placeholder="e.g. Linux, Android"
              value={os}
              onChange={(e) => setOs(e.target.value)}
            />
            <Input
              label="Architecture"
              placeholder="e.g. amd64, arm64"
              value={arch}
              onChange={(e) => setArch(e.target.value)}
            />
            <div className="col-span-2">
              <Input
                label="Hostname"
                placeholder="e.g. server-01"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
              />
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-3 mt-6">
          <Button variant="secondary" type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={isLoading} disabled={!name}>
            Save Changes
          </Button>
        </div>
      </form>
    </Modal>
  )
}
