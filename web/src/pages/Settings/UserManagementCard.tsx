import { useCreateUser, useDeleteUser, useUsers } from '@/api/client'
import { Shield, Trash2, User, UserPlus } from 'lucide-react'
import { useState } from 'react'

export const UserManagementCard: React.FC = () => {
  const { data: users, isLoading } = useUsers()
  const createUser = useCreateUser()
  const deleteUser = useDeleteUser()

  const [isAdding, setIsAdding] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [error, setError] = useState('')

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      await createUser.mutateAsync({ username: newUsername, password: newPassword })
      setNewUsername('')
      setNewPassword('')
      setIsAdding(false)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to create user')
    }
  }

  const handleDelete = async (id: string, username: string) => {
    if (username === 'admin') {
      alert('Cannot delete the main admin user.') // Simple protection
      return
    }
    if (confirm(`Are you sure you want to delete user ${username}?`)) {
      await deleteUser.mutateAsync(id)
    }
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
      <div className="p-6 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-100 dark:bg-purple-900/50 rounded-lg text-purple-600 dark:text-purple-400">
            <Shield className="w-5 h-5" />
          </div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Admin Users</h2>
        </div>
        <button
          type="button"
          onClick={() => setIsAdding(!isAdding)}
          className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium text-blue-600 hover:bg-blue-50 dark:text-blue-400 dark:hover:bg-blue-900/20 rounded-lg transition-colors"
        >
          <UserPlus className="w-4 h-4" />
          Add User
        </button>
      </div>

      <div className="p-6">
        {isAdding && (
          <form
            onSubmit={handleAddUser}
            className="mb-6 p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg space-y-4"
          >
            <h3 className="text-sm font-medium text-gray-900 dark:text-white">New User Details</h3>
            {error && <div className="text-sm text-red-600 dark:text-red-400">{error}</div>}
            <div className="grid grid-cols-2 gap-4">
              <input
                type="text"
                placeholder="Username"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                className="px-3 py-2 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                required
              />
              <input
                type="password"
                placeholder="Password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="px-3 py-2 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                required
              />
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setIsAdding(false)}
                className="px-3 py-1.5 text-sm text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={createUser.isPending}
                className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                Create
              </button>
            </div>
          </form>
        )}

        {isLoading ? (
          <div className="text-center py-4 text-gray-500">Loading users...</div>
        ) : (
          <div className="space-y-2">
            {users?.map((user) => (
              <div
                key={user.id}
                className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-gray-200 dark:bg-gray-600 flex items-center justify-center text-gray-500 dark:text-gray-300">
                    <User className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {user.username}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      Created: {new Date(user.created_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>

                {user.username !== 'admin' && ( // Hide delete for admin
                  <button
                    type="button"
                    onClick={() => handleDelete(user.id, user.username)}
                    className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400 opacity-0 group-hover:opacity-100 transition-opacity"
                    title="Delete User"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            ))}
            {users?.length === 0 && (
              <p className="text-center text-gray-500 py-4">No users found</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
