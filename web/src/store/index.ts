import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { WebSocketEvent } from '@/types'

interface AppState {
  // Current network
  currentNetworkId: string | null
  setCurrentNetworkId: (id: string | null) => void

  // Selected node for details
  selectedNodeId: string | null
  setSelectedNodeId: (id: string | null) => void

  // UI state
  sidebarOpen: boolean
  toggleSidebar: () => void
  setSidebarOpen: (open: boolean) => void

  // Theme
  theme: 'light' | 'dark' | 'system'
  setTheme: (theme: 'light' | 'dark' | 'system') => void

  // Notifications
  notifications: Notification[]
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp'>) => void
  removeNotification: (id: string) => void
  clearNotifications: () => void

  // WebSocket events (recent)
  recentEvents: WebSocketEvent[]
  addEvent: (event: WebSocketEvent) => void
  clearEvents: () => void
}

interface Notification {
  id: string
  type: 'info' | 'success' | 'warning' | 'error'
  title: string
  message?: string
  timestamp: number
}

export const useAppStore = create<AppState>()(
  persist(
    (set, get) => ({
      // Current network
      currentNetworkId: null,
      setCurrentNetworkId: (id) => set({ currentNetworkId: id }),

      // Selected node
      selectedNodeId: null,
      setSelectedNodeId: (id) => set({ selectedNodeId: id }),

      // UI state
      sidebarOpen: true,
      toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
      setSidebarOpen: (open) => set({ sidebarOpen: open }),

      // Theme
      theme: 'system',
      setTheme: (theme) => set({ theme }),

      // Notifications
      notifications: [],
      addNotification: (notification) => {
        const id = crypto.randomUUID()
        const newNotification: Notification = {
          ...notification,
          id,
          timestamp: Date.now(),
        }
        set((state) => ({
          notifications: [...state.notifications, newNotification].slice(-10), // Keep last 10
        }))

        // Auto-remove after 5 seconds for non-error notifications
        if (notification.type !== 'error') {
          setTimeout(() => {
            get().removeNotification(id)
          }, 5000)
        }
      },
      removeNotification: (id) =>
        set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
        })),
      clearNotifications: () => set({ notifications: [] }),

      // WebSocket events
      recentEvents: [],
      addEvent: (event) =>
        set((state) => ({
          recentEvents: [...state.recentEvents, event].slice(-50), // Keep last 50
        })),
      clearEvents: () => set({ recentEvents: [] }),
    }),
    {
      name: 'novusgate-storage',
      partialize: (state) => ({
        currentNetworkId: state.currentNetworkId,
        theme: state.theme,
        sidebarOpen: state.sidebarOpen,
      }),
    }
  )
)

// Selector hooks for performance
export const useCurrentNetworkId = () => useAppStore((state) => state.currentNetworkId)
export const useTheme = () => useAppStore((state) => state.theme)
export const useSidebarOpen = () => useAppStore((state) => state.sidebarOpen)
export const useNotifications = () => useAppStore((state) => state.notifications)
