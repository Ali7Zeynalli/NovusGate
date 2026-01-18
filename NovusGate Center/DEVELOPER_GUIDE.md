# NovusGate Center - Developer Guide

## Overview

The **NovusGate Center** is a web-based management tool for deploying, updating, and maintaining NovusGate VPN servers on remote Linux machines via SSH. It provides a centralized control panel that runs locally (via Docker) and connects to target servers to perform operations.

## Architecture

### Tech Stack
| Component | Technology |
|-----------|------------|
| Backend | Node.js 20, Express.js |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| SSH | `ssh2` library |
| File Transfer | SFTP (via ssh2) |
| Deployment | Docker & Docker Compose |

### File Structure
```
NovusGate Center/
├── server.js              # Main backend - API endpoints & install scripts
├── log_service.js         # Docker log streaming service
├── public/
│   └── index.html         # Single-page frontend application
├── data/
│   └── servers.json       # Persisted server credentials
├── Dockerfile             # Container definition
├── docker-compose.yml     # Orchestration config
├── package.json           # Node.js dependencies
└── .env                   # Environment variables (PORT)
```

## Core Components

### 1. Backend API (`server.js`)

#### Server Management Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/servers` | List all saved servers |
| `POST` | `/api/servers` | Add new server credentials |
| `DELETE` | `/api/servers/:id` | Remove a server |
| `GET` | `/api/servers/:id/status` | Check server health & installation status |

#### Installation Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/servers/:id/install` | Install/Update/Reinstall NovusGate |
| `POST` | `/api/servers/:id/uninstall` | Complete removal |
| `POST` | `/api/servers/:id/command` | Execute custom SSH command |

#### Docker Management Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/servers/:id/docker` | List containers |
| `POST` | `/api/servers/:id/docker/:action` | Control container (start/stop/restart/logs) |
| `GET` | `/api/servers/:id/docker/logs/stream` | Live log streaming (SSE) |
| `GET` | `/api/servers/:id/images` | List Docker images |
| `DELETE` | `/api/servers/:id/images/:name` | Delete image |
| `GET` | `/api/servers/:id/volumes` | List Docker volumes |
| `DELETE` | `/api/servers/:id/volumes/:name` | Delete volume |
| `POST` | `/api/servers/:id/prune` | Prune unused resources |

### 2. Embedded Install Scripts

All installation logic is embedded as template literals in `server.js`:

| Script | Purpose |
|--------|---------|
| `GENERATE_INSTALL_SCRIPT(config)` | Fresh installation with configuration |
| `GENERATE_REINSTALL_SCRIPT(config)` | Reinstall preserving data |
| `UPDATE_SCRIPT` | Smart update - only changed components |
| `UNINSTALL_SCRIPT` | Complete removal |
| `DATABASE_MIGRATE_SCRIPT` | Database-only migration |

### 3. Installation Flow

```
┌─────────────────┐
│  User clicks    │
│  "Install"      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Create Archive  │  tar -czf NovusGate.tar.gz server/ web/
│ (local files)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ SSH Connect     │  ssh2 library
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Upload Archive  │  SFTP to /tmp/NovusGate.tar.gz
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Execute Script  │  INSTALL_SCRIPT runs on remote
│ (streaming)     │  stdout/stderr → SSE → Frontend
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Parse Output    │  Extract: API_KEY, ADMIN_PASS, VPN Config
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Update web/.env │  Write VITE_API_URL and VITE_API_KEY
└─────────────────┘
```

### 4. Smart Update Flow (v2.0)

The update script detects what changed and only rebuilds affected components:

```bash
# Detection Logic
SERVER_CHANGED=false   # server/ directory
WEB_CHANGED=false      # web/ directory
DOCKER_CHANGED=false   # docker-compose.yml or Dockerfiles

# Selective Rebuild
if SERVER_CHANGED && WEB_CHANGED:
    rebuild control-plane, web
elif SERVER_CHANGED:
    rebuild control-plane only
elif WEB_CHANGED:
    rebuild web only
elif DOCKER_CHANGED:
    full rebuild
else:
    "No changes detected"
```

### 5. Frontend (`public/index.html`)

Single-file SPA with:
- **Server List Sidebar** - Manage multiple servers
- **Dashboard View** - Status, resources, containers
- **Real-time Logs** - SSE streaming from backend
- **Credential Display** - Auto-parsed from install output
- **VPN Config Download** - Extracted from install output

## Key Features

### SSH Connection
```javascript
function createSSHConnection(server) {
  const config = {
    host: server.host,
    port: server.port || 22,
    username: server.username,
    readyTimeout: 30000
  };
  
  if (server.privateKey) {
    config.privateKey = server.privateKey;
  } else if (server.password) {
    config.password = server.password;
  }
  
  conn.connect(config);
}
```

### Archive Creation
```javascript
const excludes = [
  '--exclude=node_modules',
  '--exclude=.git',
  '--exclude=*.exe',
  '--exclude=*.tar.gz',
  '--exclude=*.log',
  '--exclude=.env',
  '--exclude=.idea',
  '--exclude=.vscode'
];

const tarCommand = `tar -czf "${archivePath}" -C "${PROJECT_ROOT}" ${excludes} server web`;
```

### Real-time Streaming
```javascript
// Backend: SSE (Server-Sent Events)
res.setHeader('Content-Type', 'text/event-stream');
res.write(`data: ${JSON.stringify({ text: output })}\n\n`);

// Frontend: EventSource
const source = new EventSource(`/api/servers/${id}/docker/logs/stream?container=${name}`);
source.onmessage = (e) => {
  const data = JSON.parse(e.data);
  outputLog.textContent += data.text;
};
```

## Configuration

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3017` | NovusGate Center web server port |

### Install Configuration (passed to scripts)
| Parameter | Default | Description |
|-----------|---------|-------------|
| `adminUsername` | `admin` | Dashboard admin username |
| `adminPassword` | auto-generated | Dashboard admin password |
| `vpnIp` | `10.99.0.1` | Admin VPN gateway IP |
| `dbName` | `NovusGate` | PostgreSQL database name |
| `dbUser` | `NovusGate` | PostgreSQL username |
| `dbPassword` | auto-generated | PostgreSQL password |

## Development

### Local Development
```bash
cd "NovusGate Center"
npm install
node server.js
# Access: http://localhost:3017
```

### Docker Development
```bash
cd "NovusGate Center"
docker-compose up -d --build
# Access: http://localhost:3017
```

### Testing SSH Connection
```javascript
// Use /api/servers/:id/command endpoint
POST /api/servers/abc123/command
{
  "command": "whoami && hostname"
}
```

## Security Considerations

1. **Credentials Storage** - Server passwords stored in `data/servers.json` (plaintext for MVP)
2. **SSH Keys** - Supported via `privateKey` field
3. **Generated Secrets** - API keys and passwords use `openssl rand -hex 16`
4. **VPN Security** - Admin dashboard only accessible via WireGuard VPN (wg0)

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Cannot execute: required file not found" | Windows CRLF line endings | Script includes `sed -i 's/\r$//'` fix |
| "ADMIN_PASSWORD is required" | Missing .env file | Ensure .env exists before docker-compose |
| Containers stop after firewall | Docker restart in firewall script | Script now restarts containers after |
| Archive creation fails | Missing tar command | Install tar on Windows or use WSL |

### Debug Endpoints
- `GET /api/health` - Check NovusGate Center health
- `POST /api/servers/:id/command` - Run arbitrary commands

## Contributing

1. **Code Style** - Use ES6+, async/await
2. **Scripts** - Ensure all .sh files use LF line endings
3. **Testing** - Test on Ubuntu 22.04 LTS
4. **Documentation** - Update guides for new features
