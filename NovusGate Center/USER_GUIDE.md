# NovusGate Center - User Guide

## Introduction

The NovusGate Center is a web-based control panel for deploying and managing NovusGate VPN servers. It allows you to install, update, and monitor your VPN infrastructure from a simple dashboard.

## Quick Start

### Prerequisites

- **Target Server:** Ubuntu 22.04 LTS (or Debian 11+)
- **Access:** Root SSH access (IP, username, password)
- **Resources:** Minimum 1GB RAM, 10GB disk space
- **Ports:** 22 (SSH), 51820 (WireGuard), 8080 (API), 3007 (Dashboard)

### Starting NovusGate Center

**Option 1: Docker (Recommended)**
```bash
cd "NovusGate Center"
docker-compose up -d
```

**Option 2: Node.js**
```bash
cd "NovusGate Center"
npm install
node server.js
```

Access the dashboard at: `http://localhost:3017`

## Dashboard Overview

```
┌─────────────────────────────────────────────────────────────┐
│  NovusGate                                                  │
├─────────────┬───────────────────────────────────────────────┤
│             │                                               │
│  SERVERS    │   Server Dashboard                            │
│             │                                               │
│  ● Prod     │   ┌─────────┐ ┌─────────┐ ┌─────────┐        │
│  ○ Dev      │   │ Status  │ │ Disk    │ │ Memory  │        │
│             │   │   ✓     │ │ 45GB    │ │ 2.1GB   │        │
│             │   └─────────┘ └─────────┘ └─────────┘        │
│             │                                               │
│  + New      │   [Install] [Update] [Reinstall] [Uninstall] │
│             │                                               │
│             │   Docker Containers                           │
│             │   ┌─────────────────────────────────────┐    │
│             │   │ NovusGate-control-plane  Running    │    │
│             │   │ NovusGate-web            Running    │    │
│             │   │ NovusGate-postgres       Running    │    │
│             │   └─────────────────────────────────────┘    │
└─────────────┴───────────────────────────────────────────────┘
```

## Adding a Server

1. Click **+ New Server** in the sidebar
2. Fill in the details:
   - **Name:** Friendly name (e.g., "Production VPN")
   - **Host:** Server IP address
   - **Port:** SSH port (default: 22)
   - **Username:** Usually `root`
   - **Password:** Root password
3. Click **Add**

## Installation

### Fresh Install

1. Select your server from the sidebar
2. Click **📦 Install NovusGate Server**
3. Configure installation options:

| Option | Default | Description |
|--------|---------|-------------|
| Admin Username | `admin` | Dashboard login username |
| Admin Password | auto | Leave empty to auto-generate |
| Admin Network IP | `10.99.0.1` | VPN gateway IP for admin access |
| Database Name | `NovusGate` | PostgreSQL database |
| Database User | `NovusGate` | PostgreSQL username |
| Database Password | auto | Leave empty to auto-generate |

4. Click **Start Installation 🚀**
5. Watch the live installation log
6. **IMPORTANT:** Save the credentials shown at the end!

### Post-Installation

After installation completes, you'll see:

```
==========================================
  INSTALLATION COMPLETE!
==========================================
Server IP: 64.225.108.60

------------------------------------------
  🔒 ADMIN VPN CONFIG (REQUIRED)
------------------------------------------
The Admin Dashboard is now HIDDEN behind this VPN.
You MUST connect to this VPN to access the dashboard.

[Interface]
PrivateKey = ...
Address = 10.99.0.2/32
...

------------------------------------------
  SECURITY KEYS (SAVE THESE!)
------------------------------------------
ADMIN USER:  admin
ADMIN PASS:  a1b2c3d4e5f6...
API_KEY:     f6e5d4c3b2a1...
------------------------------------------
```

**Steps to connect:**
1. Download the VPN config file (click **📥 Download admin-vpn.conf**)
2. Import into WireGuard app
3. Connect to VPN
4. Access dashboard at `https://10.99.0.1:3007`

## Operations

### 🚀 Update (Smart)

Updates your server to the latest version while preserving:
- ✅ Database and all data
- ✅ User accounts
- ✅ Configuration files (.env)
- ✅ WireGuard keys and peers

**Smart Detection:**
- Only rebuilds containers that have changed
- Skips unchanged components for faster updates
- Automatically runs database migrations

### 🔄 Reinstall

Use when the server is broken but you want to keep data:
- Stops all containers
- Removes system files (keeps data/)
- Re-deploys from scratch
- Restores configuration

**Warning:** This is disruptive - services will be offline during reinstall.

### 🗄️ Database Migration Only

Runs database migrations without touching files or containers:
- Safe for schema updates
- No downtime
- Preserves all data

### 🗑️ Uninstall

**⚠️ DANGER: This permanently deletes everything!**
- Stops and removes all containers
- Deletes all data and configuration
- Removes WireGuard interfaces
- Resets firewall rules

## Docker Management

### Container Controls

| Button | Action |
|--------|--------|
| ▶ | Start container |
| ⏹ | Stop container |
| 🔄 | Restart container |
| 📋 | View live logs |
| 🗑️ | Remove container |

### Resource Cleanup

- **Prune Images:** Remove unused Docker images
- **Prune Volumes:** Remove unused volumes
- **Prune All:** Complete cleanup (images, containers, volumes)

## Troubleshooting

### Connection Issues

| Error | Solution |
|-------|----------|
| "Server not found" | Check IP address and network connectivity |
| "Authentication failed" | Verify password; ensure `PermitRootLogin yes` in sshd_config |
| "Connection timeout" | Check firewall; ensure port 22 is open |

### Installation Issues

| Error | Solution |
|-------|----------|
| "Cannot execute: required file not found" | Windows line ending issue - automatically fixed |
| "ADMIN_PASSWORD is required" | Configuration error - check .env file |
| "No space left on device" | Free up disk space; run Docker prune |
| "Port already in use" | Stop conflicting services or change ports |

### VPN Issues

| Error | Solution |
|-------|----------|
| Can't connect to VPN | Check WireGuard config; verify server IP |
| Dashboard not loading | Ensure VPN is connected; check https://10.99.0.1:3007 |
| "Handshake timeout" | Firewall blocking UDP 51820; check iptables |

### Viewing Logs

1. Click on a container
2. Click 📋 (logs button)
3. View real-time streaming logs
4. Check for error messages

### Manual SSH Access

If NovusGate Center can't connect, SSH manually:
```bash
ssh root@your-server-ip
cd /opt/NovusGate
docker-compose -f server/deployments/docker/docker-compose.yml logs -f
```

## Security Best Practices

1. **Change default passwords** after installation
2. **Keep VPN config secure** - it grants admin access
3. **Regular updates** - use Smart Update frequently
4. **Backup data** before major operations
5. **Monitor logs** for suspicious activity

## Support

- **Developer:** [Ali Zeynalli](https://github.com/Ali7Zeynalli)
- **Issues:** GitHub repository
- **Documentation:** See DEVELOPER_GUIDE.md for technical details
