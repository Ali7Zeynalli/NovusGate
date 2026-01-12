# NovusGate Web Dashboard - Developer Guide

## Overview

The NovusGate Web Dashboard is a modern, responsive React application for managing WireGuard mesh VPN networks. It provides a visual interface for node management, network monitoring, and user administration.

## Tech Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| React | 18.x | UI Framework |
| TypeScript | 5.x | Type Safety |
| Vite | 5.x | Build Tool & Dev Server |
| Tailwind CSS | 3.x | Styling (Dark Mode support) |
| React Query | 5.x | Server State Management |
| Zustand | 4.x | Client State Management |
| React Router | 6.x | Routing |
| Axios | 1.x | HTTP Client |
| Lucide React | - | Icons |
| clsx | - | Class Name Utility |

## Directory Structure

```
web/
├── src/
│   ├── api/
│   │   └── client.ts          # Axios instance, API functions, React Query hooks
│   ├── components/
│   │   ├── ui.tsx             # Reusable UI components (Button, Card, Modal, Table, etc.)
│   │   ├── Layout.tsx         # Main layout with sidebar navigation
│   │   ├── CreateNodeModal.tsx    # New peer creation form
│   │   ├── EditNodeModal.tsx      # Peer editing form
│   │   └── ServerConfigModal.tsx  # WireGuard config & QR code display
│   ├── pages/
│   │   ├── Dashboard.tsx      # Overview statistics
│   │   ├── Networks.tsx       # Network management (CRUD)
│   │   ├── Nodes.tsx          # Peer/Node management
│   │   └── Settings.tsx       # User & password management
│   ├── store/
│   │   └── index.ts           # Zustand store (auth, theme, sidebar)
│   ├── types/
│   │   └── index.ts           # TypeScript interfaces
│   ├── App.tsx                # Router & Auth wrapper
│   └── main.tsx               # React DOM entry point
├── public/                    # Static assets
├── index.html                 # HTML entry point
├── nginx.conf                 # Production HTTPS config
├── Dockerfile                 # Multi-stage Docker build
├── vite.config.ts             # Vite configuration
├── tailwind.config.js         # Tailwind CSS config
└── tsconfig.json              # TypeScript config
```

## Core Components

### API Client (`src/api/client.ts`)

Centralized API layer with Axios and React Query:

```typescript
// Axios instance with interceptors
const axiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api/v1',
});

// Auth header injection
axiosInstance.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  const apiKey = localStorage.getItem('apiKey');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  if (apiKey) config.headers['X-API-Key'] = apiKey;
  return config;
});

// API Functions
export const api = {
  login: (username: string, password: string) => Promise<LoginResponse>,
  getNodes: () => Promise<Node[]>,
  createNode: (data: CreateNodeRequest) => Promise<Node>,
  updateNode: (id: string, data: UpdateNodeRequest) => Promise<Node>,
  deleteNode: (id: string) => Promise<void>,
  getNodeConfig: (id: string) => Promise<string>,
  getNodeQrCode: (id: string) => Promise<Blob>,
  // ... more endpoints
};

// React Query Hooks
export const useNodes = () => useQuery({ queryKey: ['nodes'], queryFn: api.getNodes });
export const useCreateNode = () => useMutation({ mutationFn: api.createNode });
```

### State Management (`src/store/index.ts`)

Zustand store for client-side state:

```typescript
interface AppState {
  // Auth
  isAuthenticated: boolean;
  user: User | null;
  login: (user: User, token: string) => void;
  logout: () => void;
  
  // UI
  sidebarOpen: boolean;
  toggleSidebar: () => void;
  theme: 'light' | 'dark';
  setTheme: (theme: 'light' | 'dark') => void;
}
```

### UI Components (`src/components/ui.tsx`)

Reusable component library:

| Component | Props | Description |
|-----------|-------|-------------|
| `Button` | variant, size, loading, disabled | Primary action button |
| `Card` | padding, className | Container card |
| `Badge` | variant (success/warning/danger/info) | Status badges |
| `StatusIndicator` | status, showLabel | Online/offline indicator |
| `Input` | label, error, helperText | Form input |
| `Select` | label, options, error | Dropdown select |
| `Modal` | isOpen, onClose, title, size | Dialog modal |
| `Table` | columns, data, onRowClick, loading | Data table |
| `StatCard` | title, value, icon, change | Statistics card |
| `EmptyState` | icon, title, description, action | Empty state placeholder |

### Page Components

#### Dashboard (`src/pages/Dashboard.tsx`)
- Displays total/online/offline node counts
- Shows recent activity list
- Uses `StatCard` components

#### Nodes (`src/pages/Nodes.tsx`)
- Lists all peers with status, IP, transfer stats
- Create/Edit/Delete operations
- Config download & QR code generation
- Filtering and search

#### Networks (`src/pages/Networks.tsx`)
- Network CRUD operations
- Subnet configuration
- Node assignment

#### Settings (`src/pages/Settings.tsx`)
- Password change form
- User management (admin only)
- Create/delete dashboard users

#### Firewall (`src/pages/Firewall.tsx`)

Comprehensive firewall management page with multiple tabs:

**Components Structure:**
```typescript
// Main component
export const Firewall: React.FC

// Tab components
const OverviewTab: React.FC<OverviewTabProps>
const HostRulesTab: React.FC<HostRulesTabProps>
const OpenPortsTab: React.FC<OpenPortsTabProps>
const VPNRulesTab: React.FC<VPNRulesTabProps>
const BlockedIPsTab: React.FC<BlockedIPsTabProps>

// Modal component
const VPNRuleModal: React.FC<VPNRuleModalProps>
```

**API Hooks Used:**
```typescript
// Host Firewall
useFirewallRules()      // GET /api/v1/firewall/rules
useOpenPort()           // POST /api/v1/firewall/open-port
useClosePort()          // POST /api/v1/firewall/close-port
useBlockIP()            // POST /api/v1/firewall/block-ip
useAllowIP()            // POST /api/v1/firewall/allow-ip
useDeleteFirewallRule() // DELETE /api/v1/firewall/rules
useResetFirewall()      // POST /api/v1/firewall/reset

// VPN Firewall
useVPNFirewallRules()       // GET /api/v1/vpn-firewall/rules
useCreateVPNFirewallRule()  // POST /api/v1/vpn-firewall/rules
useUpdateVPNFirewallRule()  // PUT /api/v1/vpn-firewall/rules/:id
useDeleteVPNFirewallRule()  // DELETE /api/v1/vpn-firewall/rules/:id
useApplyVPNFirewallRules()  // POST /api/v1/vpn-firewall/apply
```

**TypeScript Interfaces:**
```typescript
interface FirewallRule {
  number: number;
  target: string;
  protocol: string;
  source: string;
  destination: string;
  port?: string;
  in_interface?: string;
  out_interface?: string;
  chain: string;
  protected: boolean;
}

interface VPNFirewallRule {
  id: string;
  name: string;
  description?: string;
  source_type: VPNEndpointType;
  source_network_id?: string;
  source_network_name?: string;
  source_node_id?: string;
  source_node_name?: string;
  source_ip?: string;
  dest_type: VPNEndpointType;
  dest_network_id?: string;
  dest_network_name?: string;
  dest_node_id?: string;
  dest_node_name?: string;
  dest_ip?: string;
  protocol: VPNFirewallProtocol;
  port?: string;
  action: VPNFirewallAction;
  priority: number;
  enabled: boolean;
}

type VPNEndpointType = 'any' | 'network' | 'node' | 'custom';
type VPNFirewallProtocol = 'all' | 'tcp' | 'udp' | 'icmp';
type VPNFirewallAction = 'accept' | 'drop' | 'reject';
```

**Key Features:**
- Tab-based navigation (Overview, Host Rules, Open Ports, VPN Rules, Blocked IPs)
- Protected port detection (SSH, WireGuard, API)
- VPN rule priority system
- Auto AllowedIPs sync when VPN rules change
- Real-time rule application

### Modal Components

#### CreateNodeModal
- Peer name input
- Expiration options: Forever, 1h, 1d, 1w, Custom
- Auto-generates WireGuard keys on server

#### EditNodeModal
- Edit name, status, expiration
- Device metadata (OS, arch, hostname)
- Extend or remove time limits

#### ServerConfigModal
- Multi-tab interface:
  - **General**: Config text + QR code
  - **Windows**: Download link + instructions
  - **macOS**: App Store link + instructions
  - **Linux**: One-line install script + manual steps
  - **Docker**: Docker run command

## Development Setup

### Prerequisites
- Node.js 18+
- npm or yarn

### Environment Variables

Create `.env` file:
```bash
VITE_API_URL=http://localhost:8080/api/v1
VITE_API_KEY=your-api-key  # Optional for development
```

### Running Locally

```bash
# Install dependencies
cd web
npm install

# Start development server
npm run dev
```

Access at `http://localhost:3000`

### API Proxy

Vite proxies `/api` requests to the backend:

```typescript
// vite.config.ts
server: {
  port: 3000,
  proxy: {
    '/api': {
      target: 'http://localhost:8080',
      changeOrigin: true,
    },
  },
},
```

## Production Build

### Build Command
```bash
npm run build
```

Output: `dist/` directory with static files

### Docker Build

Multi-stage Dockerfile:

```dockerfile
# Stage 1: Build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Stage 2: Serve with Nginx
FROM nginx:alpine
RUN apk add --no-cache openssl
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Generate self-signed SSL certificate
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/key.pem \
    -out /etc/nginx/ssl/cert.pem \
    -subj "/C=AZ/ST=Baku/L=Baku/O=NovusGate/CN=NovusGate.local"

EXPOSE 3007
CMD ["nginx", "-g", "daemon off;"]
```

### Nginx Configuration

```nginx
server {
    listen 3007 ssl;
    server_name _;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    root /usr/share/nginx/html;
    index index.html;

    # SPA routing
    location / {
        try_files $uri $uri/ /index.html;
    }

    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
}
```

## TypeScript Types

### Core Interfaces (`src/types/index.ts`)

```typescript
interface Node {
  id: string;
  name: string;
  public_key: string;
  endpoint: string;
  allowed_ips: string;
  status: 'online' | 'offline' | 'pending' | 'expired';
  last_handshake: string;
  transfer_rx: number;
  transfer_tx: number;
  expires_at?: string;
  node_info?: {
    os: string;
    arch: string;
    hostname: string;
  };
  created_at: string;
  updated_at: string;
}

interface Network {
  id: string;
  name: string;
  subnet: string;
  description?: string;
  created_at: string;
}

interface User {
  id: string;
  username: string;
  role: 'admin' | 'user';
  created_at: string;
}
```

## Styling Guidelines

### Tailwind CSS
- Use utility classes for all styling
- Dark mode: `dark:` prefix
- Responsive: `sm:`, `md:`, `lg:`, `xl:` breakpoints

### Color Palette
- Primary: `blue-600` / `blue-500`
- Success: `green-500`
- Warning: `yellow-500`
- Danger: `red-500`
- Background: `white` / `gray-900` (dark)

### Dark Mode
```tsx
// Toggle in store
const { theme, setTheme } = useStore();

// Apply to root
<html className={theme === 'dark' ? 'dark' : ''}>
```

## Authentication Flow

1. User submits login form
2. `api.login()` sends credentials to `/api/v1/auth/login`
3. Server returns JWT token
4. Token stored in `localStorage`
5. Axios interceptor adds `Authorization: Bearer <token>` to all requests
6. Zustand store updates `isAuthenticated` state
7. Router redirects to Dashboard

## Error Handling

```typescript
// React Query error handling
const { data, error, isLoading } = useNodes();

if (error) {
  return <div className="text-red-500">{error.message}</div>;
}

// Axios interceptor for 401
axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);
```

## Testing

```bash
# Run tests
npm run test

# Type checking
npm run type-check

# Linting
npm run lint
```

## Contributing

1. Follow TypeScript strict mode
2. Use functional components with hooks
3. Keep components small and focused
4. Use React Query for server state
5. Use Zustand for client state
6. Maintain dark mode compatibility
7. Ensure responsive design

## Support

Developed by [Ali Zeynalli](https://github.com/Ali7Zeynalli)
