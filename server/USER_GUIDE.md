# NovusGate Server - User Guide

## Introduction

**NovusGate Server** is the backbone of your VPN network. It runs quietly in the background, maintaining secure encrypted tunnels between your devices.

## Installation

*Note: We highly recommend using the **NovusGate Installer** for automatic deployment.*

### Docker Deployment (Manual)

1. **Create `docker-compose.yml`:**
```yaml
version: "3.8"
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: NovusGate
      POSTGRES_USER: NovusGate
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - ./data/postgres:/var/lib/postgresql/data

  control-plane:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.control-plane
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    volumes:
      - /etc/wireguard:/etc/wireguard:rw
    env_file: .env
    depends_on:
      - postgres
```

2. **Create `.env` configuration:**
```bash
# Database
DB_NAME=NovusGate
DB_USER=NovusGate
DB_PASSWORD=strong_password_123

# Security
JWT_SECRET=very_secure_random_string
API_KEY=internal_communication_key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin_password

# Network
WG_SERVER_ENDPOINT=YOUR_PUBLIC_IP
ADMIN_CIDR=10.99.0.0/24
```

3. **Start:**
```bash
docker-compose up -d
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `JWT_SECRET` | Secret key for signing API tokens | Required |
| `NovusGate_API_KEY` | Key for inter-service communication | Required |
| `ADMIN_USERNAME` | Initial admin username | `admin` |
| `ADMIN_PASSWORD` | Initial admin password | Required |
| `WG_SERVER_ENDPOINT` | Public IP where clients connect | Required |
| `ADMIN_CIDR` | Admin network CIDR range | `10.99.0.0/24` |
| `NovusGate_LISTEN` | API listening port | `:8080` |

### Data Storage

- **Database:** Stored in PostgreSQL (`data/postgres/`)
- **WireGuard Configs:** In `/etc/wireguard/` directory
- **Backup:** Regularly backup `data/` folder and PostgreSQL

## Network Structure

NovusGate supports multiple VPN networks:

```
┌─────────────────────────────────────────────────────────────┐
│                    NovusGate Server                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │ Admin Network   │  │ Office Network  │                  │
│  │ wg0 (51820)     │  │ wg1 (51821)     │                  │
│  │ 10.99.0.0/24    │  │ 10.10.0.0/24    │                  │
│  │                 │  │                 │                  │
│  │ ● Admin Panel   │  │ ● Employee 1    │                  │
│  │ ● Monitoring    │  │ ● Employee 2    │                  │
│  └─────────────────┘  │ ● Server        │                  │
│                       └─────────────────┘                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Admin Network (wg0)
- **Purpose:** Secure access to admin panel
- **CIDR:** `10.99.0.0/24` (default)
- **Port:** 51820
- **Note:** Cannot be deleted

### Additional Networks (wg1, wg2, ...)
- Created from dashboard
- Each has its own CIDR range
- Independent peers

## API Endpoints

### Authentication
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | Login (get token) |
| `/api/v1/auth/password` | PUT | Change password |

### Networks
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/networks` | GET | List networks |
| `/api/v1/networks` | POST | Create new network |
| `/api/v1/networks/{id}` | GET | Network details |
| `/api/v1/networks/{id}` | DELETE | Delete network |

### Nodes (Peers)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/networks/{id}/nodes` | GET | List nodes |
| `/api/v1/networks/{id}/servers` | POST | Create new peer |
| `/api/v1/nodes/{id}` | GET | Node details |
| `/api/v1/nodes/{id}` | PUT | Update node |
| `/api/v1/nodes/{id}` | DELETE | Delete node |
| `/api/v1/nodes/{id}/config` | GET | WireGuard config |
| `/api/v1/nodes/{id}/qrcode` | GET | QR code image |

### Users
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/users` | GET | List users |
| `/api/v1/users` | POST | Create new user |
| `/api/v1/users/{id}` | DELETE | Delete user |

### Host Firewall
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/firewall/rules` | GET | Get all firewall rules and status |
| `/api/v1/firewall/open-port` | POST | Open a port for incoming traffic |
| `/api/v1/firewall/close-port` | POST | Close an open port |
| `/api/v1/firewall/block-ip` | POST | Block an IP address or CIDR |
| `/api/v1/firewall/allow-ip` | POST | Allow an IP address or CIDR |
| `/api/v1/firewall/rules` | DELETE | Delete a firewall rule |
| `/api/v1/firewall/reset` | POST | Reset firewall to default config |
| `/api/v1/firewall/export` | GET | Export firewall rules as text |

### VPN Firewall (Inter-Network Rules)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/vpn-firewall/rules` | GET | List all VPN firewall rules |
| `/api/v1/vpn-firewall/rules` | POST | Create a new VPN rule |
| `/api/v1/vpn-firewall/rules/{id}` | PUT | Update a VPN rule |
| `/api/v1/vpn-firewall/rules/{id}` | DELETE | Delete a VPN rule |
| `/api/v1/vpn-firewall/apply` | POST | Apply VPN rules to iptables |

## Node Statuses

| Status | Description | Color |
|--------|-------------|-------|
| `pending` | Awaiting configuration | Yellow |
| `online` | Active connection | Green |
| `offline` | No connection | Gray |
| `expired` | Time expired | Red |

### Online Detection
Server determines online status using two methods:

1. **Traffic Activity** (~30-45 seconds)
   - Clients with PersistentKeepalive=25 send data every 25 seconds
   - Traffic in last 45 seconds = online

2. **Handshake Time** (~2.5 minutes)
   - WireGuard handshake timestamp
   - Handshake in last 150 seconds = online

## Troubleshooting

### "Clients cannot connect"
- Check if port **51820 UDP** is open on your firewall
- Verify `WG_SERVER_ENDPOINT` in `.env` matches your actual Public IP
- Check interface status with `wg show`

### "Server restart loop"
- Check logs: `docker logs NovusGate-control-plane`
- Common causes:
  - PostgreSQL connection error
  - No access to `/etc/wireguard` directory
  - `ADMIN_PASSWORD` not set

### "API 500 Error"
- Ensure `JWT_SECRET` is set
- Check database connection
- Look for error messages in server logs

### "Peers not visible"
- Check if WireGuard interface is UP: `ip link show wg0`
- Verify peer is added to WireGuard: `wg show wg0`
- Check if node exists in database

## Viewing Logs

```bash
# All container logs
docker-compose logs -f

# Control-plane only
docker logs -f NovusGate-control-plane

# WireGuard status
wg show

# Network interfaces
ip addr show
```

## Security Best Practices

1. **Use strong passwords** - For `JWT_SECRET`, `API_KEY`, `ADMIN_PASSWORD`
2. **Configure firewall** - Only open necessary ports
3. **Keep behind VPN** - Admin panel should only be accessible via wg0
4. **Regular backups** - PostgreSQL and `/etc/wireguard` directory
5. **Monitor logs** - Watch for suspicious activity

## Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 8080 | TCP | REST API |
| 8443 | TCP | gRPC (future use) |
| 51820+ | UDP | WireGuard (one port per network) |
| 5432 | TCP | PostgreSQL (localhost only) |
| 3007 | TCP | Web Dashboard |

## Support

- **Developer:** [Ali Zeynalli](https://github.com/Ali7Zeynalli)
- **Issues:** Open an issue on GitHub repository
- **Documentation:** See DEVELOPER_GUIDE.md for technical details
