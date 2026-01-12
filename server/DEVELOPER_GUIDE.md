# NovusGate Server - Developer Guide

## Overview

**NovusGate Server** is the core component responsible for managing the WireGuard mesh network overlay. It handles peer coordination, configuration distribution, key management, and API access for the dashboard. Written in **Go**, it's designed to be high-performance and cloud-native.

## Architecture

### Tech Stack
| Component | Technology |
|-----------|------------|
| Language | Go 1.23+ |
| Database | PostgreSQL 16 |
| VPN Protocol | WireGuard (`wg-quick` and kernel modules) |
| API | REST/JSON over HTTP |
| Authentication | JWT (JSON Web Tokens) + API Key |
| Router | Gorilla Mux |

### Directory Structure
```
server/
├── cmd/
│   └── control-plane/
│       └── main.go           # Main entry point (CLI commands)
├── internal/
│   ├── controlplane/
│   │   ├── api/
│   │   │   └── rest/
│   │   │       └── handlers.go   # REST API handlers
│   │   └── store/
│   │       └── store.go          # PostgreSQL database operations
│   ├── wireguard/
│   │   ├── manager.go            # WireGuard interface management
│   │   ├── keys.go               # Key generation
│   │   ├── config_generator.go   # Configuration generation
│   │   └── install_script.go     # Client install script
│   └── shared/
│       └── models/
│           └── models.go         # Data models
├── deployments/
│   └── docker/
│       ├── docker-compose.yml    # Orchestration
│       ├── Dockerfile.control-plane
│       └── setup-firewall.sh     # Firewall configuration
├── go.mod                        # Go modules
└── go.sum                        # Dependency hashes
```

## Core Modules

### 1. Control Plane (`internal/controlplane`)

This module acts as the system's "brain".

#### API Layer (`api/rest/handlers.go`)
Provides REST API endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/login` | User login |
| `PUT` | `/api/v1/auth/password` | Change password |
| `GET` | `/api/v1/networks` | List networks |
| `POST` | `/api/v1/networks` | Create new network |
| `DELETE` | `/api/v1/networks/{id}` | Delete network |
| `GET` | `/api/v1/networks/{networkId}/nodes` | List nodes |
| `POST` | `/api/v1/networks/{networkId}/servers` | Create new server/peer |
| `GET` | `/api/v1/nodes/{id}` | Get node details |
| `PUT` | `/api/v1/nodes/{id}` | Update node |
| `DELETE` | `/api/v1/nodes/{id}` | Delete node |
| `GET` | `/api/v1/nodes/{id}/config` | WireGuard configuration |
| `GET` | `/api/v1/nodes/{id}/qrcode` | QR code image |
| `GET` | `/api/v1/users` | List users |
| `POST` | `/api/v1/users` | Create new user |
| `DELETE` | `/api/v1/users/{id}` | Delete user |
| `GET` | `/health` | Health check |

**Host Firewall Endpoints (`firewall_handlers.go`):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/firewall/rules` | Get all firewall rules |
| `POST` | `/api/v1/firewall/open-port` | Open a port |
| `POST` | `/api/v1/firewall/close-port` | Close a port |
| `POST` | `/api/v1/firewall/block-ip` | Block an IP/CIDR |
| `POST` | `/api/v1/firewall/allow-ip` | Allow an IP/CIDR |
| `DELETE` | `/api/v1/firewall/rules` | Delete a rule |
| `POST` | `/api/v1/firewall/reset` | Reset to defaults |
| `GET` | `/api/v1/firewall/export` | Export rules |

**VPN Firewall Endpoints (`vpn_firewall_handlers.go`):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/vpn-firewall/rules` | List VPN rules |
| `POST` | `/api/v1/vpn-firewall/rules` | Create VPN rule |
| `PUT` | `/api/v1/vpn-firewall/rules/{id}` | Update VPN rule |
| `DELETE` | `/api/v1/vpn-firewall/rules/{id}` | Delete VPN rule |
| `POST` | `/api/v1/vpn-firewall/apply` | Apply rules to iptables |

#### Store Layer (`store/store.go`)
PostgreSQL database operations:

```go
// Core functions
func (s *Store) CreateNetwork(ctx, network) error
func (s *Store) GetNetwork(ctx, id) (*Network, error)
func (s *Store) ListNetworks(ctx) ([]*Network, error)
func (s *Store) DeleteNetwork(ctx, id) error

func (s *Store) CreateNode(ctx, node) error
func (s *Store) GetNode(ctx, id) (*Node, error)
func (s *Store) ListNodes(ctx, networkID) ([]*Node, error)
func (s *Store) UpdateNode(ctx, node) error
func (s *Store) DeleteNode(ctx, id) error
func (s *Store) AllocateIP(ctx, networkID) (net.IP, error)

func (s *Store) CreateUser(ctx, user) error
func (s *Store) GetUserByUsername(ctx, username) (*User, error)
func (s *Store) UpdateUserPassword(ctx, username, hash) error
```

### 2. WireGuard Manager (`internal/wireguard`)

Manages WireGuard interfaces.

#### manager.go
```go
type Manager struct {
    InterfaceName string  // wg0, wg1, ...
    ConfigPath    string  // /etc/wireguard/wg0.conf
}

// Core methods
func (m *Manager) Init() error                    // Verify wg command exists
func (m *Manager) Up() error                      // wg-quick up
func (m *Manager) Down() error                    // wg-quick down
func (m *Manager) AddPeer(pubKey, allowedIPs)     // Add peer
func (m *Manager) RemovePeer(pubKey)              // Remove peer
func (m *Manager) GetPeers() map[string]PeerStatus // Get peer statuses
func (m *Manager) GetPublicKey() (string, error)  // Server public key
```

#### PeerStatus struct
```go
type PeerStatus struct {
    PublicKey           string
    Endpoint            string
    AllowedIPs          string
    LatestHandshakeTime int64   // Unix timestamp
    TransferRx          int64   // Bytes received
    TransferTx          int64   // Bytes sent
}
```

### 3. Data Models (`internal/shared/models`)

#### Network
```go
type Network struct {
    ID               string    // UUID
    Name             string    // "Admin Management", "Office VPN"
    CIDR             string    // "10.10.0.0/24"
    ServerPrivateKey string    // WireGuard private key (hidden)
    ServerPublicKey  string    // WireGuard public key
    ServerEndpoint   string    // "64.225.108.60:51820"
    ListenPort       int       // 51820, 51821, ...
    InterfaceName    string    // "wg0", "wg1", ...
    CreatedAt        time.Time
    UpdatedAt        time.Time
}
```

#### Node
```go
type Node struct {
    ID         string            // UUID
    NetworkID  string            // Which network it belongs to
    Name       string            // "Ali's Laptop"
    VirtualIP  net.IP            // 10.10.0.5
    PublicKey  string            // Client public key
    Labels     map[string]string // Metadata
    Status     NodeStatus        // pending/online/offline/expired
    LastSeen   time.Time
    PublicIP   string            // Real IP (from endpoint)
    TransferRx int64             // Download bytes
    TransferTx int64             // Upload bytes
    ExpiresAt  *time.Time        // Expiration time (optional)
    NodeInfo   *NodeInfo         // OS, arch, hostname
    CreatedAt  time.Time
}
```

#### NodeStatus
```go
const (
    NodeStatusPending NodeStatus = "pending"   // Awaiting configuration
    NodeStatusOnline  NodeStatus = "online"    // Active connection
    NodeStatusOffline NodeStatus = "offline"   // No connection
    NodeStatusExpired NodeStatus = "expired"   // Time expired
)
```

## CLI Commands

Server provides CLI via `cobra` library:

```bash
# Start server
NovusGate-server serve --listen :8080 --grpc-listen :8443

# Database migration
NovusGate-server migrate --database "postgres://..."

# Network initialization
NovusGate-server init --name "Admin Network" --cidr "10.99.0.0/24"

# Version
NovusGate-server version
```

## Middlewares

### 1. AuthMiddleware
JWT token validation:
```go
// Authorization: Bearer <token>
// /health and /login endpoints are exempt
```

### 2. APIKeyMiddleware
API key validation:
```go
// X-API-Key: <key>
// Skipped in dev mode (empty key)
```

### 3. LoggingMiddleware
Request logging (currently placeholder).

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `NovusGate_LISTEN` | HTTP API port | `:8080` |
| `NovusGate_GRPC_LISTEN` | gRPC port | `:8443` |
| `JWT_SECRET` | Token signing key | Required |
| `NovusGate_API_KEY` | API key | Required |
| `ADMIN_USERNAME` | Initial admin username | `admin` |
| `ADMIN_PASSWORD` | Initial admin password | Required |
| `WG_SERVER_ENDPOINT` | Server public IP | Required |
| `ADMIN_CIDR` | Admin network CIDR | `10.99.0.0/24` |

## Docker Deployment

### docker-compose.yml structure
```yaml
services:
  postgres:
    image: postgres:16-alpine
    # Database

  control-plane:
    build: ...
    network_mode: host      # Critical for WireGuard!
    cap_add:
      - NET_ADMIN           # Network management
      - SYS_MODULE          # Kernel modules
    volumes:
      - /etc/wireguard:/etc/wireguard:rw  # Host WireGuard

  web:
    build: ...
    network_mode: host
```

### Important Notes
- `network_mode: host` - Required for WireGuard traffic to work properly
- `/etc/wireguard` mount - Access to host's WireGuard configuration
- `NET_ADMIN` capability - Required to manage network interfaces

## Development

### Local Development
```bash
cd server

# Download dependencies
go mod download

# Set environment variables
export DATABASE_URL="postgres://NovusGate:password@localhost:5432/NovusGate?sslmode=disable"
export JWT_SECRET="dev_secret"
export NovusGate_API_KEY="dev_key"
export ADMIN_PASSWORD="admin123"

# Run
go run ./cmd/control-plane serve
```

### Build
```bash
# Binary build
go build -o NovusGate-server ./cmd/control-plane

# Docker build
docker build -f deployments/docker/Dockerfile.control-plane -t NovusGate-server .
```

### Test
```bash
go test ./...
```

## Security

1. **JWT Tokens** - New admin token generated on each startup
2. **API Key** - Required for all API calls
3. **Bcrypt** - Passwords are hashed
4. **Behind VPN** - Admin panel only accessible via wg0
5. **CORS** - All origins allowed (for development)

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| "wg command not found" | WireGuard not installed | `apt install wireguard-tools` |
| "permission denied" | Missing NET_ADMIN capability | Check `cap_add` in Docker |
| "database connection refused" | PostgreSQL not running | Check container status |
| "interface already exists" | wg0 already exists | `wg-quick down wg0` |
| Peers not visible | Manager not initialized | Check server logs |

## Contributing

1. **Code Style** - Follow `gofmt` and Go idioms
2. **Testing** - Add unit tests for `internal/`
3. **Migration** - Schema changes must be added as SQL migration files
4. **Documentation** - Update guides for new features
