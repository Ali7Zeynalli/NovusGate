import axios, { AxiosInstance, AxiosError } from 'axios';
import type {
  Network,
  Node,
  CreateNetworkForm,
  SystemInfo,
  Fail2BanStatus,
  Fail2BanLogs,
  StatsOverview,
  FirewallStatus,
  OpenPortRequest,
  ClosePortRequest,
  BlockIPRequest,
  AllowIPRequest,
  DeleteRuleRequest,
  ImportRulesRequest,
  VPNFirewallRule,
  VPNFirewallRuleRequest,
} from '../types';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';
const API_KEY = import.meta.env.VITE_API_KEY || '';

class ApiClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: `${API_URL}/api/v1`,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
    });

    // Add auth interceptor
    this.client.interceptors.request.use((config) => {
      const token = localStorage.getItem('auth_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Add error interceptor
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('auth_token');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  // Networks
  async getNetworks(): Promise<Network[]> {
    const { data } = await this.client.get<Network[]>('/networks');
    return data;
  }

  async getNetwork(id: string): Promise<Network> {
    const { data } = await this.client.get<Network>(`/networks/${id}`);
    return data;
  }

  async createNetwork(network: CreateNetworkForm): Promise<Network> {
    const { data } = await this.client.post<Network>('/networks', network);
    return data;
  }

  async deleteNetwork(id: string): Promise<void> {
    await this.client.delete(`/networks/${id}`);
  }

  // Nodes
  async getNodes(networkId: string): Promise<Node[]> {
    const { data } = await this.client.get<Node[]>(`/networks/${networkId}/nodes`);
    return data;
  }

  async getNode(id: string): Promise<Node> {
    const { data } = await this.client.get<Node>(`/nodes/${id}`);
    return data;
  }

  async deleteNode(id: string): Promise<void> {
    await this.client.delete(`/nodes/${id}`);
  }

  async updateNode(id: string, data: { name?: string; expires_at?: string | null; status?: string; node_info?: { os: string; arch: string; hostname: string } }): Promise<Node> {
    const { data: res } = await this.client.put<Node>(`/nodes/${id}`, data);
    return res;
  }

  async createServerWithConfig(networkId: string, data: any): Promise<any> {
    const { data: res } = await this.client.post(`/networks/${networkId}/servers`, data);
    return res;
  }

  async getNodeConfig(nodeId: string): Promise<string> {
    const { data } = await this.client.get(`/nodes/${nodeId}/config`, {
      responseType: 'text',
    });
    return data;
  }

  async getNodeQrCode(nodeId: string): Promise<Blob> {
    const { data } = await this.client.get(`/nodes/${nodeId}/qrcode`, {
      responseType: 'blob',
    });
    return data;
  }
  // User Management
  async updatePassword(username: string, oldPass: string, newPass: string): Promise<void> {
    await this.client.put('/auth/password', { username, oldPassword: oldPass, newPassword: newPass });
  }

  async getUsers(): Promise<any[]> {
    const { data } = await this.client.get('/users');
    return data;
  }

  async createUser(username: string, password: string): Promise<any> {
    const { data } = await this.client.post('/users', { username, password });
    return data;
  }

  async deleteUser(id: string): Promise<void> {
    await this.client.delete(`/users/${id}`);
  }

  // Health check
  async healthCheck(): Promise<{ status: string; version: string }> {
    const { data } = await this.client.get('/health');
    return data;
  }

  // System Info
  async getSystemInfo(): Promise<SystemInfo> {
    const { data } = await this.client.get('/system/info');
    return data;
  }

  // Fail2Ban
  async getFail2BanStatus(): Promise<Fail2BanStatus> {
    const { data } = await this.client.get('/system/fail2ban/status');
    return data;
  }

  async getFail2BanLogs(lines: number = 100): Promise<Fail2BanLogs> {
    const { data } = await this.client.get(`/system/fail2ban/logs?lines=${lines}`);
    return data;
  }

  async unbanIP(jail: string, ip: string): Promise<void> {
    await this.client.post('/system/fail2ban/unban', { jail, ip });
  }

  // Fail2Ban - Manual Ban
  async banIP(jail: string, ip: string, permanent: boolean = false): Promise<any> {
    const { data } = await this.client.post('/system/fail2ban/ban', { jail, ip, permanent });
    return data;
  }

  // Fail2Ban - Jail Settings
  async getJailSettings(jail: string = 'sshd'): Promise<any> {
    const { data } = await this.client.get(`/system/fail2ban/jail/settings?jail=${jail}`);
    return data;
  }

  async updateJailSettings(jail: string, settings: { bantime?: string; maxretry?: string; findtime?: string }): Promise<any> {
    const { data } = await this.client.put('/system/fail2ban/jail/settings', { jail, ...settings });
    return data;
  }

  // Fail2Ban - Whitelist
  async getWhitelist(jail: string = 'sshd'): Promise<any> {
    const { data } = await this.client.get(`/system/fail2ban/whitelist?jail=${jail}`);
    return data;
  }

  async updateWhitelist(jail: string, action: 'add' | 'remove', ip: string): Promise<any> {
    const { data } = await this.client.put('/system/fail2ban/whitelist', { jail, action, ip });
    return data;
  }

  // Fail2Ban - Permanent Bans (iptables)
  async getPermanentBans(): Promise<any> {
    const { data } = await this.client.get('/system/fail2ban/permanent-bans');
    return data;
  }

  async removePermanentBan(ip: string): Promise<any> {
    const { data } = await this.client.delete('/system/fail2ban/permanent-bans', { data: { ip } });
    return data;
  }

  // Fail2Ban - Jail Control
  async controlJail(jail: string, action: 'start' | 'stop'): Promise<any> {
    const { data } = await this.client.post('/system/fail2ban/jail/control', { jail, action });
    return data;
  }

  // Fail2Ban - Reload
  async reloadFail2Ban(jail?: string): Promise<any> {
    const url = jail ? `/system/fail2ban/reload?jail=${jail}` : '/system/fail2ban/reload';
    const { data } = await this.client.post(url);
    return data;
  }

  // Fail2Ban - Ping (health check)
  async pingFail2Ban(): Promise<any> {
    const { data } = await this.client.get('/system/fail2ban/ping');
    return data;
  }

  // Fail2Ban - Ban History
  async getBanHistory(jail?: string, limit: number = 100): Promise<any> {
    let url = `/system/fail2ban/ban-history?limit=${limit}`;
    if (jail) url += `&jail=${jail}`;
    const { data } = await this.client.get(url);
    return data;
  }

  // Stats Overview (all networks)
  async getStatsOverview(): Promise<StatsOverview> {
    const { data } = await this.client.get('/stats/overview');
    return data;
  }

  // =====================
  // Host Firewall Methods
  // =====================

  // Get all iptables rules (optionally filtered by chain)
  async getFirewallRules(chain?: string): Promise<FirewallStatus> {
    const params = chain ? { chain } : {};
    const { data } = await this.client.get<FirewallStatus>('/firewall/host/rules', { params });
    return data;
  }

  // Open a port in the firewall
  async openPort(request: OpenPortRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/port/open', request);
    return data;
  }

  // Close a port in the firewall
  async closePort(request: ClosePortRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/port/close', request);
    return data;
  }

  // Block an IP address
  async blockIP(request: BlockIPRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/ip/block', request);
    return data;
  }

  // Allow an IP address
  async allowIP(request: AllowIPRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/ip/allow', request);
    return data;
  }

  // Delete a firewall rule
  async deleteFirewallRule(request: DeleteRuleRequest): Promise<any> {
    const { data } = await this.client.delete('/firewall/host/rules', { data: request });
    return data;
  }

  // Export firewall rules (iptables-save format)
  async exportFirewallRules(): Promise<string> {
    const { data } = await this.client.get('/firewall/host/export', {
      responseType: 'text',
    });
    return data;
  }

  // Import firewall rules (iptables-restore format)
  async importFirewallRules(request: ImportRulesRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/import', request);
    return data;
  }

  // Reset firewall to default NovusGate configuration
  async resetFirewall(): Promise<any> {
    const { data } = await this.client.post('/firewall/host/reset');
    return data;
  }

  // ====================
  // VPN Firewall Methods
  // ====================

  // Get all VPN firewall rules
  async getVPNFirewallRules(): Promise<VPNFirewallRule[]> {
    const { data } = await this.client.get<VPNFirewallRule[]>('/firewall/vpn/rules');
    return data;
  }

  // Create a VPN firewall rule
  async createVPNFirewallRule(request: VPNFirewallRuleRequest): Promise<VPNFirewallRule> {
    const { data } = await this.client.post<VPNFirewallRule>('/firewall/vpn/rules', request);
    return data;
  }

  // Update a VPN firewall rule
  async updateVPNFirewallRule(id: string, request: VPNFirewallRuleRequest): Promise<VPNFirewallRule> {
    const { data } = await this.client.put<VPNFirewallRule>(`/firewall/vpn/rules/${id}`, request);
    return data;
  }

  // Delete a VPN firewall rule
  async deleteVPNFirewallRule(id: string): Promise<void> {
    await this.client.delete(`/firewall/vpn/rules/${id}`);
  }

  // Apply all VPN firewall rules to iptables
  async applyVPNFirewallRules(): Promise<any> {
    const { data } = await this.client.post('/firewall/vpn/apply');
    return data;
  }
}

export const api = new ApiClient();

export const getAuthHeaders = () => {
  const token = localStorage.getItem('auth_token');
  return {
    'Authorization': token ? `Bearer ${token}` : '',
    'X-API-Key': import.meta.env.VITE_API_KEY || '',
  };
};

// React Query hooks
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

// Export hooks


// Network hooks
export function useNetworks() {
  return useQuery({
    queryKey: ['networks'],
    queryFn: () => api.getNetworks(),
  });
}

export function useNetwork(id: string) {
  return useQuery({
    queryKey: ['networks', id],
    queryFn: () => api.getNetwork(id),
    enabled: !!id,
  });
}

export function useCreateNetwork() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateNetworkForm) => api.createNetwork(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['networks'] });
    },
  });
}

export function useDeleteNetwork() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteNetwork(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['networks'] });
    },
  });
}

// Node hooks
export function useNodes(networkId: string) {
  return useQuery({
    queryKey: ['nodes', networkId],
    queryFn: () => api.getNodes(networkId),
    enabled: !!networkId,
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

export function useNode(id: string) {
  return useQuery({
    queryKey: ['nodes', 'detail', id],
    queryFn: () => api.getNode(id),
    enabled: !!id,
  });
}

export function useDeleteNode() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteNode(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['nodes'] });
    },
  });
}

export function useCreateServerWithConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: { networkId: string; data: any }) => 
      api.createServerWithConfig(vars.networkId, vars.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['nodes'] });
    },
  });
}

export function useUpdateNode() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; data: { name?: string; expires_at?: string | null; status?: string; node_info?: { os: string; arch: string; hostname: string } } }) =>
      api.updateNode(vars.id, vars.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['nodes'] });
    },
  });
}

// User Management hooks
export function useUpdatePassword() {
  return useMutation({
    mutationFn: (data: { username: string; oldPass: string; newPass: string }) =>
      api.updatePassword(data.username, data.oldPass, data.newPass),
  });
}

export function useUsers() {
  return useQuery({
    queryKey: ['users'],
    queryFn: () => api.getUsers(),
  });
}

export function useCreateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { username: string; password: string }) =>
      api.createUser(data.username, data.password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
}

export function useDeleteUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteUser(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
}

// System Info hooks
export function useSystemInfo() {
  return useQuery({
    queryKey: ['systemInfo'],
    queryFn: () => api.getSystemInfo(),
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

// Fail2Ban hooks
export function useFail2BanStatus() {
  return useQuery({
    queryKey: ['fail2ban', 'status'],
    queryFn: () => api.getFail2BanStatus(),
    refetchInterval: 30000,
  });
}

export function useFail2BanLogs(lines: number = 100) {
  return useQuery({
    queryKey: ['fail2ban', 'logs', lines],
    queryFn: () => api.getFail2BanLogs(lines),
  });
}

export function useUnbanIP() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { jail: string; ip: string }) => api.unbanIP(data.jail, data.ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fail2ban'] });
    },
  });
}

// Stats Overview hook
export function useStatsOverview() {
  return useQuery({
    queryKey: ['stats', 'overview'],
    queryFn: () => api.getStatsOverview(),
    refetchInterval: 30000,
  });
}

// =====================
// Host Firewall Hooks
// =====================

export function useFirewallRules(chain?: string) {
  return useQuery({
    queryKey: ['firewall', 'host', 'rules', chain],
    queryFn: () => api.getFirewallRules(chain),
    refetchInterval: 30000,
  });
}

export function useOpenPort() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: OpenPortRequest) => api.openPort(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] });
    },
  });
}

export function useClosePort() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: ClosePortRequest) => api.closePort(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] });
    },
  });
}

export function useBlockIP() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: BlockIPRequest) => api.blockIP(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] });
    },
  });
}

export function useAllowIP() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: AllowIPRequest) => api.allowIP(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] });
    },
  });
}

export function useDeleteFirewallRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: DeleteRuleRequest) => api.deleteFirewallRule(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] });
    },
  });
}

export function useImportFirewallRules() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: ImportRulesRequest) => api.importFirewallRules(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] });
    },
  });
}

export function useResetFirewall() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.resetFirewall(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] });
    },
  });
}

// ====================
// VPN Firewall Hooks
// ====================

export function useVPNFirewallRules() {
  return useQuery({
    queryKey: ['firewall', 'vpn', 'rules'],
    queryFn: () => api.getVPNFirewallRules(),
    refetchInterval: 30000,
  });
}

export function useCreateVPNFirewallRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: VPNFirewallRuleRequest) => api.createVPNFirewallRule(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn'] });
    },
  });
}

export function useUpdateVPNFirewallRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; request: VPNFirewallRuleRequest }) =>
      api.updateVPNFirewallRule(vars.id, vars.request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn'] });
    },
  });
}

export function useDeleteVPNFirewallRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteVPNFirewallRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn'] });
    },
  });
}

export function useApplyVPNFirewallRules() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.applyVPNFirewallRules(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn'] });
    },
  });
}
