import { format } from 'date-fns'
import { Activity, Network, Plus, Search, Shield, Trash2 } from 'lucide-react'
import type React from 'react'
import { useState } from 'react'
import { useCreateNetwork, useDeleteNetwork, useNetworks } from '@/api/client'
import { PageHeader } from '@/components/Layout'
import type { CreateNetworkForm } from '@/types'

export const Networks = () => {
  const { data: networks, isLoading } = useNetworks()
  const createMutation = useCreateNetwork()
  const deleteMutation = useDeleteNetwork()
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)
  const [formData, setFormData] = useState<CreateNetworkForm>({ name: '', cidr: '10.10.0.0/24' })
  const [searchQuery, setSearchQuery] = useState('')
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  const filteredNetworks = networks?.filter(
    (n) =>
      n.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      n.cidr.includes(searchQuery) ||
      n.interface_name?.includes(searchQuery)
  )

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setErrorMessage(null)
    try {
      await createMutation.mutateAsync(formData)
      setIsCreateModalOpen(false)
      setFormData({ name: '', cidr: '10.10.0.0/24' })
    } catch (error: any) {
      console.error('Failed to create network:', error)
      // Extract error message from response
      const message = error?.response?.data?.error || error?.message || 'Failed to create network'
      setErrorMessage(message)
    }
  }

  const handleDelete = async (id: string, name: string) => {
    if (
      confirm(
        `Are you sure you want to delete network "${name}"? This action cannot be undone and will disconnect all nodes.`
      )
    ) {
      try {
        await deleteMutation.mutateAsync(id)
      } catch (error) {
        console.error('Failed to delete network:', error)
      }
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  return (
    <div>
      <PageHeader
        title="Networks"
        description="Manage your isolated VPN networks and Hub-and-Spoke configurations."
        actions={
          <button
            type="button"
            onClick={() => setIsCreateModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Create Network
          </button>
        }
      />

      {/* Search */}
      <div className="mb-6">
        <div className="relative max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search networks by name, CIDR, or interface..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900 dark:text-white"
          />
        </div>
      </div>

      {/* Networks List */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredNetworks?.map((network) => (
          <div
            key={network.id}
            className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden hover:shadow-lg transition-shadow"
          >
            <div className="p-6">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-blue-50 dark:bg-blue-900/20 rounded-lg flex items-center justify-center">
                    <Network className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white">{network.name}</h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Created {format(new Date(network.created_at), 'MMM d, yyyy')}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleDelete(network.id, network.name)}
                  className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                  title="Delete Network"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-4">
                {/* Network Details */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <label className="text-xs text-gray-500 dark:text-gray-400 block mb-1">
                      CIDR Range
                    </label>
                    <span className="font-medium text-gray-900 dark:text-gray-200">
                      {network.cidr}
                    </span>
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 dark:text-gray-400 block mb-1">
                      Interface
                    </label>
                    <div className="flex items-center gap-1.5 font-medium text-gray-900 dark:text-gray-200">
                      <Shield className="w-3.5 h-3.5 text-green-500" />
                      {network.interface_name || 'wg0'}
                    </div>
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 dark:text-gray-400 block mb-1">
                      Listen Port
                    </label>
                    <span className="font-mono text-gray-900 dark:text-gray-200">
                      {network.listen_port || 51820}
                    </span>
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 dark:text-gray-400 block mb-1">
                      Server Endpoint
                    </label>
                    <span
                      className="font-mono text-xs text-gray-900 dark:text-gray-200 truncate block"
                      title={network.server_endpoint}
                    >
                      {network.server_endpoint || 'Auto-detected'}
                    </span>
                  </div>
                </div>

                {/* Status Bar - Mock for now but could be real if backend returned it */}
                <div className="pt-4 border-t border-gray-100 dark:border-gray-700">
                  <div className="flex items-center justify-between text-sm mb-2">
                    <span className="text-gray-500 dark:text-gray-400 flex items-center gap-2">
                      <Activity className="w-4 h-4" />
                      Status
                    </span>
                    <span className="text-green-600 dark:text-green-400 font-medium">Active</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}

        {/* Add New Card (Empty State or Last Item) */}
        <button
          type="button"
          onClick={() => setIsCreateModalOpen(true)}
          className="flex flex-col items-center justify-center p-6 border-2 border-dashed border-gray-300 dark:border-gray-700 rounded-xl hover:border-blue-500 dark:hover:border-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/10 transition-all group min-h-[250px]"
        >
          <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900/40 rounded-full flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
            <Plus className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <span className="font-medium text-gray-900 dark:text-white">Create New Network</span>
          <p className="text-sm text-gray-500 text-center mt-2 max-w-[200px]">
            Set up a completely isolated VPN environment with its own subnet.
          </p>
        </button>
      </div>

      {/* Create Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-xl max-w-md w-full p-6">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
              Create New Network
            </h2>
            <form onSubmit={handleCreate}>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Network Name
                  </label>
                  <input
                    type="text"
                    required
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full rounded-lg border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="e.g. My Secure Network"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    CIDR Range
                  </label>
                  <input
                    type="text"
                    required
                    value={formData.cidr}
                    onChange={(e) => setFormData({ ...formData, cidr: e.target.value })}
                    className="w-full rounded-lg border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="e.g. 10.10.0.0/24"
                    pattern="^10\.\d+\.\d+\.0\/24$"
                    title="Must be a valid private network (10.x.x.0/24)"
                  />
                  <p className="mt-1 text-xs text-gray-500">
                    Must be a /24 private subnet (e.g., 10.10.5.0/24). All networks are restricted
                    to /24 for security and performance.
                  </p>
                </div>

                <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg flex gap-3 text-sm text-blue-800 dark:text-blue-200">
                  <Shield className="w-5 h-5 shrink-0" />
                  <p>
                    A dedicated WireGuard interface and listening port will be automatically
                    assigned to this network.
                  </p>
                </div>

                {/* Error Message */}
                {errorMessage && (
                  <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4 rounded-lg text-sm text-red-700 dark:text-red-300">
                    <strong>Error:</strong> {errorMessage}
                  </div>
                )}
              </div>

              <div className="flex justify-end gap-3 mt-6">
                <button
                  type="button"
                  onClick={() => {
                    setIsCreateModalOpen(false)
                    setErrorMessage(null)
                  }}
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-50"
                >
                  {createMutation.isPending ? 'Creating...' : 'Create Network'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
