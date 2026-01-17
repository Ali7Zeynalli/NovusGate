import { useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import {
  Activity,
  CheckCircle,
  Clock,
  Copy,
  Download,
  Laptop,
  Pencil,
  Server,
  ShieldAlert,
  Trash2,
} from 'lucide-react'
import type React from 'react'
import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  useCreateServerWithConfig,
  useDeleteNode,
  useNetworks,
  useNode,
  useNodes,
  useUpdateNode,
} from '../api/client'
import { CreateNodeModal } from '../components/CreateNodeModal'
import { EditNodeModal } from '../components/EditNodeModal'
import { PageHeader } from '../components/Layout'
import { ServerConfigModal } from '../components/ServerConfigModal'
import { Badge, Button, Card, EmptyState, Modal, StatusIndicator, Table } from '../components/ui'
import { useCurrentNetworkId } from '../store'
import type { Node } from '../types'

const formatBytes = (bytes: number = 0) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`
}

export const NodesPage: React.FC = () => {
  const navigate = useNavigate()
  const networkId = useCurrentNetworkId()
  const { data: nodes, isLoading } = useNodes(networkId || '')
  const deleteNode = useDeleteNode()
  const createServer = useCreateServerWithConfig()
  const updateNode = useUpdateNode()
  const { data: networks } = useNetworks()
  const currentNetwork = networks?.find((n) => n.id === networkId)
  const isAdminNetwork =
    currentNetwork?.interface_name === 'wg0' || currentNetwork?.name === 'Admin Management Network'

  const [selectedNode, setSelectedNode] = useState<Node | null>(null)
  const [showDeleteModal, setShowDeleteModal] = useState(false)
  const [showConfigModal, setShowConfigModal] = useState(false)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)

  if (!networkId) {
    return (
      <EmptyState
        icon={<Server className="w-12 h-12" />}
        title="No network selected"
        description="Select a network from the sidebar to view nodes"
      />
    )
  }

  const handleDelete = async () => {
    if (selectedNode) {
      await deleteNode.mutateAsync(selectedNode.id)
      setShowDeleteModal(false)
      setSelectedNode(null)
    }
  }

  const handleCreatePeer = async (data: { name: string; expires_at?: string }) => {
    createServer.mutate(
      {
        networkId: networkId || '',
        data: {
          name: data.name,
          expires_at: data.expires_at,
          labels: { type: 'client' },
        },
      },
      {
        onSuccess: (response) => {
          setShowCreateModal(false)
          // Show the config download modal for the new node
          if (response.node) {
            setSelectedNode(response.node)
            setShowConfigModal(true)
          }
        },
      }
    )
  }

  const columns = [
    {
      key: 'name',
      header: 'Name',
      render: (node: Node) => (
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gray-100 dark:bg-gray-700 rounded-lg">
            <Server className="w-4 h-4 text-gray-600 dark:text-gray-400" />
          </div>
          <div>
            <p className="font-medium text-gray-900 dark:text-white">{node.name}</p>
            <p className="text-xs text-gray-500">{node.id.slice(0, 8)}...</p>
          </div>
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (node: Node) => <StatusIndicator status={node.status} />,
    },
    {
      key: 'virtual_ip',
      header: 'Virtual IP',
      render: (node: Node) => (
        <code className="text-sm bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
          {node.virtual_ip}
        </code>
      ),
    },
    {
      key: 'public_ip',
      header: 'Public IP',
      render: (node: Node) => (
        <span className="text-sm font-mono text-gray-600 dark:text-gray-400">
          {node.public_ip || '-'}
        </span>
      ),
    },
    {
      key: 'transfer',
      header: 'Transfer',
      render: (node: Node) => (
        <div className="text-xs space-y-0.5">
          <p className="text-green-600">↓ {formatBytes(node.transfer_rx)}</p>
          <p className="text-blue-600">↑ {formatBytes(node.transfer_tx)}</p>
        </div>
      ),
    },
    {
      key: 'labels',
      header: 'Labels',
      render: (node: Node) => (
        <div className="flex flex-wrap gap-1">
          {Object.entries(node.labels || {})
            .slice(0, 2)
            .map(([key, value]) => (
              <Badge key={key} size="sm">
                {key}={value}
              </Badge>
            ))}
          {Object.keys(node.labels || {}).length > 2 && (
            <Badge size="sm">+{Object.keys(node.labels).length - 2}</Badge>
          )}
        </div>
      ),
    },
    {
      key: 'expires',
      header: 'Expires',
      render: (node: Node) => (
        <span
          className={`text-sm ${node.status === 'expired' ? 'text-red-500 font-bold' : 'text-gray-500'}`}
        >
          {node.expires_at && node.expires_at !== '0001-01-01T00:00:00Z'
            ? new Date(node.expires_at).toLocaleString('az-AZ', {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
              })
            : 'Forever'}
        </span>
      ),
    },
    {
      key: 'last_seen',
      header: 'Last Seen',
      render: (node: Node) => (
        <span className="text-gray-500">
          {node.last_seen && node.last_seen !== '0001-01-01T00:00:00Z'
            ? formatDistanceToNow(new Date(node.last_seen), { addSuffix: true })
            : 'Never'}
        </span>
      ),
    },
    {
      key: 'config',
      header: 'Config',
      className: 'w-10',
      render: (node: Node) => {
        // Hide download button for imported nodes (they don't have private keys)
        const hasPrivateKey = node.labels?.wireguard_private_key
        if (!hasPrivateKey) {
          return (
            <span className="text-xs text-gray-400" title="Config not available for imported nodes">
              -
            </span>
          )
        }
        return (
          <button
            onClick={(e) => {
              e.stopPropagation()
              setSelectedNode(node)
              setShowConfigModal(true)
            }}
            className="p-1 text-primary-600 hover:text-primary-700"
            title="Download Config"
          >
            <Download className="w-4 h-4" />
          </button>
        )
      },
    },
    {
      key: 'actions',
      header: '',
      className: 'w-20',
      render: (node: Node) => (
        <div className="flex items-center gap-1">
          <button
            onClick={(e) => {
              e.stopPropagation()
              setSelectedNode(node)
              setShowEditModal(true)
            }}
            className="p-1 text-gray-400 hover:text-blue-600"
            title="Edit"
          >
            <Pencil className="w-4 h-4" />
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation()
              setSelectedNode(node)
              setShowDeleteModal(true)
            }}
            className="p-1 text-gray-400 hover:text-red-600"
            title="Delete"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      ),
    },
  ]

  const onlineCount = nodes?.filter((n) => n.status === 'online').length || 0
  const pendingCount = nodes?.filter((n) => n.status === 'pending').length || 0
  const offlineCount =
    nodes?.filter((n) => n.status === 'offline' || n.status === 'expired').length || 0

  return (
    <div>
      <PageHeader
        title="Nodes"
        description="Manage nodes in your mesh network"
        actions={
          <Button onClick={() => setShowCreateModal(true)}>
            <Server className="w-4 h-4 mr-2" />
            Create Peer
          </Button>
        }
      />

      {/* Admin Network Warning */}
      {isAdminNetwork && (
        <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
          <div>
            <h3 className="text-sm font-semibold text-red-800 dark:text-red-300">
              Admin Network Security Warning
            </h3>
            <p className="text-sm text-red-700 dark:text-red-400 mt-1">
              You are viewing the <strong>Admin Management Network (wg0)</strong>. Nodes created in
              this network will have access to the Admin Panel and internal management services.
              Only create peers here for trusted administrators. Do not share these configs with
              regular users.
            </p>
          </div>
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Nodes</p>
              <p className="text-2xl font-semibold">{nodes?.length || 0}</p>
            </div>
            <Server className="w-8 h-8 text-gray-400" />
          </div>
        </Card>
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Online</p>
              <p className="text-2xl font-semibold text-green-600">{onlineCount}</p>
            </div>
            <div className="w-3 h-3 bg-green-500 rounded-full" />
          </div>
        </Card>
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Pending</p>
              <p className="text-2xl font-semibold text-orange-500">{pendingCount}</p>
            </div>
            <div className="w-3 h-3 bg-orange-500 rounded-full animate-pulse" />
          </div>
        </Card>
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Offline</p>
              <p className="text-2xl font-semibold text-gray-400">{offlineCount}</p>
            </div>
            <div className="w-3 h-3 bg-gray-400 rounded-full" />
          </div>
        </Card>
      </div>

      {/* Nodes table */}
      <Card padding="none">
        <Table
          columns={columns}
          data={nodes || []}
          loading={isLoading}
          onRowClick={(node) => navigate(`/nodes/${node.id}`)}
          emptyMessage="No nodes in this network. Create an enrollment token to add nodes."
        />
      </Card>

      {/* Delete confirmation modal */}
      <Modal isOpen={showDeleteModal} onClose={() => setShowDeleteModal(false)} title="Delete Node">
        <div className="space-y-4">
          <p className="text-gray-600 dark:text-gray-400">
            Are you sure you want to remove <strong>{selectedNode?.name}</strong> from the network?
            This action cannot be undone.
          </p>
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={() => setShowDeleteModal(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleDelete} loading={deleteNode.isPending}>
              Delete Node
            </Button>
          </div>
        </div>
      </Modal>

      {/* Peer creation modal */}
      <CreateNodeModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onSubmit={handleCreatePeer}
        isLoading={createServer.isPending}
      />

      {/* Config Modal */}
      <ServerConfigModal
        isOpen={showConfigModal}
        onClose={() => {
          setShowConfigModal(false)
          setSelectedNode(null)
        }}
        nodeId={selectedNode?.id || ''}
        nodeName={selectedNode?.name || ''}
      />

      {/* Edit Node Modal */}
      <EditNodeModal
        isOpen={showEditModal}
        onClose={() => {
          setShowEditModal(false)
          setSelectedNode(null)
        }}
        node={selectedNode}
        onSubmit={(data) => {
          if (selectedNode) {
            updateNode.mutate(
              {
                id: selectedNode.id,
                data: {
                  name: data.name,
                  expires_at: data.expires_at === undefined ? undefined : data.expires_at || '',
                  status: data.status,
                  node_info: data.node_info,
                },
              },
              {
                onSuccess: () => {
                  setShowEditModal(false)
                  setSelectedNode(null)
                },
              }
            )
          }
        }}
        isLoading={updateNode.isPending}
      />
    </div>
  )
}

// Node detail page
export const NodeDetailPage: React.FC = () => {
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const [copied, setCopied] = useState(false)
  const { data: node, isLoading, error } = useNode(id || '')
  const [showEditModal, setShowEditModal] = useState(false)

  // Update node mutation
  const queryClient = useQueryClient()
  const updateNode = useUpdateNode()

  const handleEditSubmit = (data: {
    name: string
    expires_at?: string | null
    status?: string
    node_info?: { os: string; arch: string; hostname: string }
  }) => {
    if (node) {
      updateNode.mutate(
        {
          id: node.id,
          data: {
            name: data.name,
            expires_at: data.expires_at === undefined ? undefined : data.expires_at || '',
            status: data.status,
            node_info: data.node_info,
          },
        },
        {
          onSuccess: () => {
            setShowEditModal(false)
            queryClient.invalidateQueries({ queryKey: ['node', node.id] })
          },
        }
      )
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (error || !node) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <Server className="w-12 h-12 text-gray-300 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white">Node not found</h3>
        <p className="text-gray-500 mb-4">
          The requested node could not be found or has been deleted.
        </p>
        <Button variant="secondary" onClick={() => navigate('/nodes')}>
          Back to Nodes
        </Button>
      </div>
    )
  }

  const copyToClipboard = async (text: string) => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text)
        setCopied(true)
      } else {
        // Fallback for non-secure contexts
        const textArea = document.createElement('textarea')
        textArea.value = text
        textArea.style.position = 'fixed'
        textArea.style.left = '-9999px'
        textArea.style.top = '0'
        document.body.appendChild(textArea)
        textArea.focus()
        textArea.select()
        try {
          document.execCommand('copy')
          setCopied(true)
        } catch (err) {
          console.error('Fallback: Oops, unable to copy', err)
        }
        document.body.removeChild(textArea)
      }
    } catch (err) {
      console.error('Failed to copy!', err)
    }
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header with Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white dark:bg-gray-800 p-6 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{node.name}</h1>
            <StatusIndicator status={node.status} />
          </div>
          <p className="mt-1 text-sm text-gray-500 font-mono">ID: {node.id}</p>
        </div>
        <div className="flex gap-3">
          <Button variant="secondary" onClick={() => navigate('/nodes')}>
            Back
          </Button>
          <Button onClick={() => setShowEditModal(true)} className="flex items-center gap-2">
            <Pencil className="w-4 h-4" />
            Edit Node
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Status & Expiration Card */}
        <Card>
          <div className="flex items-center gap-2 mb-4">
            <Clock className="w-5 h-5 text-primary-500" />
            <h3 className="text-lg font-semibold">Status & Expiration</h3>
          </div>

          <div className="space-y-4">
            <div className="flex justify-between items-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
              <span className="text-gray-600 dark:text-gray-300">Connection Status</span>
              <div className="flex items-center gap-2">
                <div
                  className={`w-3 h-3 rounded-full ${node.status === 'online' ? 'bg-green-500 animate-pulse' : node.status === 'expired' ? 'bg-red-500' : 'bg-gray-400'}`}
                ></div>
                <span className="font-medium capitalize">{node.status}</span>
              </div>
            </div>

            <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg text-xs text-blue-700 dark:text-blue-300">
              If node is not connecting, try: Edit → Disabled → Save, then Edit → Active → Save.
            </div>

            <div className="flex justify-between items-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
              <span className="text-gray-600 dark:text-gray-300">Expiration</span>
              <div className="text-right">
                <div
                  className={`font-bold ${node.status === 'expired' ? 'text-red-500' : 'text-gray-900 dark:text-white'}`}
                >
                  {node.expires_at && node.expires_at !== '0001-01-01T00:00:00Z'
                    ? new Date(node.expires_at).toLocaleString('az-AZ')
                    : 'Unlimited (Forever)'}
                </div>
                {node.expires_at &&
                  node.expires_at !== '0001-01-01T00:00:00Z' &&
                  node.status !== 'expired' && (
                    <span className="text-xs text-gray-500">
                      Expires {formatDistanceToNow(new Date(node.expires_at), { addSuffix: true })}
                    </span>
                  )}
              </div>
            </div>

            <div className="flex justify-between items-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
              <span className="text-gray-600 dark:text-gray-300">Last Seen</span>
              <span className="font-mono">
                {node.last_seen && node.last_seen !== '0001-01-01T00:00:00Z'
                  ? formatDistanceToNow(new Date(node.last_seen), { addSuffix: true })
                  : 'Never'}
              </span>
            </div>
          </div>
        </Card>

        {/* Network Activity Card */}
        <Card>
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-5 h-5 text-blue-500" />
            <h3 className="text-lg font-semibold">Network Activity</h3>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-xl border border-blue-100 dark:border-blue-900/30 text-center">
              <div className="text-sm text-blue-600 dark:text-blue-400 mb-1">Download (Rx)</div>
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {formatBytes(node.transfer_rx)}
              </div>
            </div>
            <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-xl border border-green-100 dark:border-green-900/30 text-center">
              <div className="text-sm text-green-600 dark:text-green-400 mb-1">Upload (Tx)</div>
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {formatBytes(node.transfer_tx)}
              </div>
            </div>
          </div>

          <div className="mt-4 space-y-2">
            <div className="flex justify-between text-sm py-2 border-b dark:border-gray-700">
              <span className="text-gray-500">Virtual IP</span>
              <code className="font-mono">{node.virtual_ip}</code>
            </div>
            <div className="flex justify-between text-sm py-2 border-b dark:border-gray-700">
              <span className="text-gray-500">Public Endpoint</span>
              <code className="font-mono">{node.public_ip || 'Unknown'}</code>
            </div>
          </div>
        </Card>

        {/* System Info Card */}
        <Card className="lg:col-span-2">
          <div className="flex items-center gap-2 mb-4">
            <Laptop className="w-5 h-5 text-purple-500" />
            <h3 className="text-lg font-semibold">Device & System</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <dt className="text-sm text-gray-500">Operating System</dt>
              <dd className="mt-1 font-medium">{node.node_info?.os || 'Unknown'}</dd>
            </div>
            <div>
              <dt className="text-sm text-gray-500">Hostname</dt>
              <dd className="mt-1 font-medium">{node.node_info?.hostname || 'Unknown'}</dd>
            </div>
            <div>
              <dt className="text-sm text-gray-500">Architecture</dt>
              <dd className="mt-1 font-medium">{node.node_info?.arch || 'Unknown'}</dd>
            </div>
            <div className="col-span-full">
              <dt className="text-sm text-gray-500">Public Key</dt>
              <dd className="mt-1 flex items-center gap-2">
                <code className="bg-gray-100 dark:bg-gray-700 px-3 py-2 rounded-lg text-sm flex-1 font-mono break-all">
                  {node.public_key}
                </code>
                <button
                  onClick={() => copyToClipboard(node.public_key)}
                  className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                  title="Copy Public Key"
                >
                  {copied ? (
                    <CheckCircle className="w-5 h-5 text-green-500" />
                  ) : (
                    <Copy className="w-5 h-5 text-gray-500" />
                  )}
                </button>
              </dd>
            </div>
          </div>
        </Card>
      </div>

      <EditNodeModal
        isOpen={showEditModal}
        onClose={() => setShowEditModal(false)}
        node={node}
        onSubmit={handleEditSubmit}
        isLoading={updateNode.isPending}
      />
    </div>
  )
}

export default NodesPage
