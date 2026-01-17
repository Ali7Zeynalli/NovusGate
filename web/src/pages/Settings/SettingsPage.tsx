import { PageHeader } from '@/components/Layout'
import { ChangePasswordCard } from './ChangePasswordCard'
import { UserManagementCard } from './UserManagementCard'

export const SettingsPage: React.FC = () => {
  return (
    <div className="space-y-8">
      <PageHeader title="Settings" description="Manage your account profile and system users." />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <ChangePasswordCard />
        <UserManagementCard />
      </div>
    </div>
  )
}
