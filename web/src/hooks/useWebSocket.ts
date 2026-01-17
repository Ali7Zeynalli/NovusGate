import { useCallback, useEffect, useRef } from 'react'
import { useAppStore, useCurrentNetworkId } from '../store'
import type { WebSocketEvent } from '../types'

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8080'

export function useWebSocket() {
  const networkId = useCurrentNetworkId()
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout>>()
  const { addEvent, addNotification } = useAppStore()

  const connect = useCallback(() => {
    if (!networkId) return

    const ws = new WebSocket(`${WS_URL}/api/v1/ws?network_id=${networkId}`)

    ws.onopen = () => {
      console.log('WebSocket connected')

      // Subscribe to events
      ws.send(
        JSON.stringify({
          type: 'subscribe',
          channels: ['nodes', 'services', 'access_logs'],
          network_id: networkId,
        })
      )
    }

    ws.onmessage = (event) => {
      try {
        const data: WebSocketEvent = JSON.parse(event.data)
        addEvent(data)

        // Handle specific events
        switch (data.type) {
          case 'node_status': {
            const nodeEvent = data.payload
            if (nodeEvent.status === 'offline') {
              addNotification({
                type: 'warning',
                title: 'Node Offline',
                message: `Node ${nodeEvent.node_id} went offline`,
              })
            }
            break
          }
        }
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error)
      }
    }

    ws.onerror = (error) => {
      console.error('WebSocket error:', error)
    }

    ws.onclose = () => {
      console.log('WebSocket disconnected, reconnecting...')
      reconnectTimeoutRef.current = setTimeout(connect, 5000)
    }

    wsRef.current = ws
  }, [networkId, addEvent, addNotification])

  useEffect(() => {
    connect()

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [connect])

  return wsRef.current
}

// Hook for connection status
export function useConnectionStatus() {
  const wsRef = useRef<WebSocket | null>(null)

  return {
    isConnected: wsRef.current?.readyState === WebSocket.OPEN,
    isConnecting: wsRef.current?.readyState === WebSocket.CONNECTING,
  }
}
