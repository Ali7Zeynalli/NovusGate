import { Clock } from 'lucide-react'
import type React from 'react'
import { useState } from 'react'
import { Button, Input, Modal, Select } from '@/components/ui'

interface CreateNodeModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: { name: string; expires_at?: string }) => void
  isLoading?: boolean
}

const expiryOptions = [
  { value: 'forever', label: 'Forever (No limit)' },
  { value: '1h', label: '1 Hour' },
  { value: '1d', label: '1 Day' },
  { value: '1w', label: '1 Week' },
  { value: 'custom', label: 'Custom Date' },
]

type ExpiryValueProp = (typeof expiryOptions)[number]['value']

export const CreateNodeModal = ({ isOpen, onClose, onSubmit, isLoading }: CreateNodeModalProps) => {
  const [name, setName] = useState('')
  const [expiryType, setExpiryType] = useState<ExpiryValueProp>('forever')
  const [customDate, setCustomDate] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    let expiresAt: string | undefined
    const now = new Date()

    if (expiryType === '1h') {
      expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString()
    } else if (expiryType === '1d') {
      expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString()
    } else if (expiryType === '1w') {
      expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString()
    } else if (expiryType === 'custom' && customDate) {
      expiresAt = new Date(customDate).toISOString()
    }

    onSubmit({ name, expires_at: expiresAt })
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create New Peer">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Peer Name"
          placeholder="e.g. My Phone, Office Laptop"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />

        <div className="space-y-1">
          <label
            htmlFor="expiry-type"
            className="block text-sm font-medium text-gray-700 dark:text-gray-300"
          >
            Expiration (Access Duration)
          </label>
          <div className="flex gap-2">
            <div className="flex-1">
              <Select
                id="expiry-type"
                options={expiryOptions}
                value={expiryType}
                onChange={(e) => setExpiryType(e.target.value)}
              />
            </div>
          </div>
        </div>

        {expiryType === 'custom' && (
          <Input
            label="Custom Expiration Date"
            type="datetime-local"
            value={customDate}
            min={new Date().toISOString().slice(0, 16)}
            onChange={(e) => setCustomDate(e.target.value)}
            required
          />
        )}

        {expiryType !== 'forever' && expiryType !== 'custom' && (
          <div className="flex items-center gap-2 text-xs text-blue-600 bg-blue-50 dark:bg-blue-900/20 p-2 rounded-lg">
            <Clock className="w-4 h-4" />
            <span>This peer will be automatically disabled after specified time.</span>
          </div>
        )}

        <div className="flex justify-end gap-3 mt-6">
          <Button variant="secondary" type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={isLoading} disabled={!name}>
            Create & Download Config
          </Button>
        </div>
      </form>
    </Modal>
  )
}
