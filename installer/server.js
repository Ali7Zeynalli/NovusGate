const express = require('express');
const { Client } = require('ssh2');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const logService = require('./modules/log_service'); // Import Log Service
const fail2banModule = require('./modules/fail2ban'); // Import Fail2ban Module

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Project paths
const PROJECT_ROOT = '/project_root';
const DATA_DIR = path.join(__dirname, 'data');
const SERVERS_FILE = path.join(DATA_DIR, 'servers.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Initialize servers.json if not exists
if (!fs.existsSync(SERVERS_FILE)) {
  fs.writeFileSync(SERVERS_FILE, JSON.stringify({ servers: [] }, null, 2));
}

// Load/Save servers
function loadServers() {
  try {
    return JSON.parse(fs.readFileSync(SERVERS_FILE, 'utf8'));
  } catch {
    return { servers: [] };
  }
}

function saveServers(data) {
  fs.writeFileSync(SERVERS_FILE, JSON.stringify(data, null, 2));
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

// SSH Connection helper
function createSSHConnection(server) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    
    conn.on('ready', () => resolve(conn));
    conn.on('error', reject);
    
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
  });
}

// Execute SSH command
function execSSH(conn, command) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) return reject(err);
      
      let stdout = '';
      let stderr = '';
      
      stream.on('close', (code) => {
        resolve({ code, stdout, stderr });
      });
      stream.on('data', (data) => { stdout += data.toString(); });
      stream.stderr.on('data', (data) => { stderr += data.toString(); });
    });
  });
}

// ============ API ENDPOINTS ============

// GET /api/servers - List all servers
app.get('/api/servers', (req, res) => {
  const data = loadServers();
  // Don't send passwords
  const servers = data.servers.map(s => ({
    id: s.id,
    name: s.name,
    host: s.host,
    port: s.port,
    username: s.username,
    status: s.status,
    lastCheck: s.lastCheck,
    installedAt: s.installedAt,
    history: s.history
  }));
  res.json(servers);
});

// POST /api/servers - Add new server
app.post('/api/servers', (req, res) => {
  const { name, host, port, username, password, privateKey } = req.body;
  
  if (!name || !host || !username) {
    return res.status(400).json({ error: 'Name, host, and username are required' });
  }
  
  const data = loadServers();
  const server = {
    id: generateId(),
    name,
    host,
    port: port || 22,
    username,
    password,
    privateKey,
    status: 'unknown',
    lastCheck: null,
    installedAt: null,
    history: []
  };
  
  data.servers.push(server);
  saveServers(data);
  
  res.json({ id: server.id, message: 'Server added' });
});

// DELETE /api/servers/:id
app.delete('/api/servers/:id', (req, res) => {
  const data = loadServers();
  data.servers = data.servers.filter(s => s.id !== req.params.id);
  saveServers(data);
  res.json({ message: 'Server deleted' });
});

// GET /api/servers/:id/status - Check server status
app.get('/api/servers/:id/status', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    
    // Check NovusGate installation
    const NovusGateCheck = await execSSH(conn, 'test -d /opt/NovusGate && echo "installed" || echo "not_installed"');
    const isInstalled = NovusGateCheck.stdout.trim() === 'installed';
    
    // Check Docker containers
    const dockerPs = await execSSH(conn, 'docker ps --format "{{.Names}}|{{.Status}}|{{.Ports}}" 2>/dev/null | grep NovusGate || true');
    const containers = dockerPs.stdout.trim().split('\n').filter(Boolean).map(line => {
      const [name, status, ports] = line.split('|');
      return { name, status, ports };
    });
    
    // Check disk space - total and used
    const diskCheck = await execSSH(conn, "df -h / | tail -1 | awk '{print $2\"|\"$3\"|\"$4\"|\"$5}'");
    const diskParts = diskCheck.stdout.trim().split('|');
    const totalDisk = diskParts[0] || 'N/A';
    const usedDisk = diskParts[1] || 'N/A';
    const freeSpace = diskParts[2] || 'N/A';
    const diskPercent = diskParts[3] || 'N/A';
    
    // Check memory - total, used, available
    const memCheck = await execSSH(conn, "free -h | grep Mem | awk '{print $2\"|\"$3\"|\"$7}'");
    const memParts = memCheck.stdout.trim().split('|');
    const totalMemory = memParts[0] || 'N/A';
    const usedMemory = memParts[1] || 'N/A';
    const freeMemory = memParts[2] || 'N/A';
    
    // Check CPU usage
    const cpuCheck = await execSSH(conn, "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1");
    const cpuUsage = cpuCheck.stdout.trim() || 'N/A';
    
    // Check uptime
    const uptimeCheck = await execSSH(conn, "uptime -p 2>/dev/null || uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}'");
    const uptime = uptimeCheck.stdout.trim() || 'N/A';
    
    conn.end();
    
    // Update server status
    server.status = isInstalled ? 'installed' : 'not_installed';
    server.lastCheck = new Date().toISOString();
    saveServers(data);
    
    res.json({
      id: server.id,
      name: server.name,
      host: server.host,
      status: server.status,
      isInstalled,
      containers,
      // Disk info
      totalDisk,
      usedDisk,
      freeSpace,
      diskPercent,
      // Memory info
      totalMemory,
      usedMemory,
      freeMemory,
      // CPU & Uptime
      cpuUsage,
      uptime,
      lastCheck: server.lastCheck
    });
    
  } catch (err) {
    server.status = 'offline';
    server.lastCheck = new Date().toISOString();
    saveServers(data);
    
    res.status(500).json({ error: 'Unable to connect to server: ' + err.message });
  }
});

// GET /api/servers/:id/docker - Get Docker containers
app.get('/api/servers/:id/docker', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    
    const result = await execSSH(conn, `
      docker ps -a --format '{"name":"{{.Names}}","status":"{{.Status}}","image":"{{.Image}}","ports":"{{.Ports}}"}' 2>/dev/null || echo "[]"
    `);
    
    conn.end();
    
    const containers = result.stdout.trim().split('\n').filter(Boolean).map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    }).filter(Boolean);
    
    res.json(containers);
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Stream Docker Logs (Live) - Add this BEFORE or AFTER generic docker actions
app.get('/api/servers/:id/docker/logs/stream', async (req, res) => {
  const { container } = req.query;
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) return res.status(404).json({ error: 'Server not found' });
  if (!container) return res.status(400).json({ error: 'Container name required' });
  
  await logService.streamContainerLogs(server, container, req, res);
});

// POST /api/servers/:id/docker/:action - Control Docker container
app.post('/api/servers/:id/docker/:action', async (req, res) => {
  const { container } = req.body;
  const action = req.params.action; // start, stop, restart, remove
  
  if (!['start', 'stop', 'restart', 'remove', 'logs'].includes(action)) {
    return res.status(400).json({ error: 'Invalid action' });
  }
  
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    
    let command;
    if (action === 'logs') {
      command = `docker logs --tail 100 ${container}`;
    } else if (action === 'remove') {
      command = `docker rm -f ${container}`;
    } else {
      command = `docker ${action} ${container}`;
    }
    
    const result = await execSSH(conn, command);
    conn.end();
    
    // Add to history
    server.history = server.history || [];
    server.history.unshift({
      action: `docker_${action}`,
      container,
      timestamp: new Date().toISOString(),
      success: result.code === 0
    });
    server.history = server.history.slice(0, 50); // Keep last 50
    saveServers(data);
    
    if (action === 'logs') {
      res.json({ logs: result.stdout + result.stderr });
    } else {
      res.json({ 
        success: result.code === 0, 
        output: result.stdout + result.stderr 
      });
    }
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/images - Get Docker images
app.get('/api/servers/:id/images', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    // Include ID for dangling images that have no repository/tag
    const result = await execSSH(conn, `docker images --format '{"id":"{{.ID}}","repository":"{{.Repository}}","tag":"{{.Tag}}","size":"{{.Size}}","created":"{{.CreatedSince}}"}' 2>/dev/null`);
    conn.end();
    
    const images = result.stdout.trim().split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);
    
    res.json(images);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/:id/prune - Prune unused Docker resources
app.post('/api/servers/:id/prune', async (req, res) => {
  const { type = 'all' } = req.body; // images, containers, volumes, all
  
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    
    let command;
    switch (type) {
      case 'images':
        command = 'docker image prune -af';
        break;
      case 'containers':
        command = 'docker container prune -f';
        break;
      case 'volumes':
        command = 'docker volume prune -f';
        break;
      default:
        command = 'docker system prune -af --volumes';
    }
    
    const result = await execSSH(conn, command);
    conn.end();
    
    server.history = server.history || [];
    server.history.unshift({
      action: `prune_${type}`,
      timestamp: new Date().toISOString(),
      success: result.code === 0
    });
    saveServers(data);
    
    res.json({ success: result.code === 0, output: result.stdout + result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/servers/:id/images/:name - Delete Docker image
app.delete('/api/servers/:id/images/:name', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    const result = await execSSH(conn, `docker rmi -f ${decodeURIComponent(req.params.name)}`);
    conn.end();
    
    res.json({ success: result.code === 0, output: result.stdout + result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/volumes - Get Docker volumes
app.get('/api/servers/:id/volumes', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    const result = await execSSH(conn, `docker volume ls --format '{"name":"{{.Name}}","driver":"{{.Driver}}"}' 2>/dev/null`);
    conn.end();
    
    const volumes = result.stdout.trim().split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);
    
    res.json(volumes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/servers/:id/volumes/:name - Delete Docker volume
app.delete('/api/servers/:id/volumes/:name', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    const result = await execSSH(conn, `docker volume rm -f ${req.params.name}`);
    conn.end();
    
    res.json({ success: result.code === 0, output: result.stdout + result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/credentials - Get credentials from server's .env file
app.get('/api/servers/:id/credentials', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    
    // Read .env file from server
    const envResult = await execSSH(conn, 'cat /opt/NovusGate/server/deployments/docker/.env 2>/dev/null || echo "NOT_FOUND"');
    
    if (envResult.stdout.trim() === 'NOT_FOUND') {
      conn.end();
      return res.status(404).json({ error: 'NovusGate not installed or .env file not found' });
    }
    
    // Parse .env file
    const envContent = envResult.stdout;
    const parseEnv = (key) => {
      const match = envContent.match(new RegExp(`^${key}=(.*)$`, 'm'));
      return match ? match[1].trim() : null;
    };
    
    const credentials = {
      adminUser: parseEnv('ADMIN_USERNAME') || 'admin',
      adminPass: parseEnv('ADMIN_PASSWORD'),
      apiKey: parseEnv('API_KEY'),
      dbName: parseEnv('DB_NAME'),
      dbUser: parseEnv('DB_USER'),
      dbPass: parseEnv('DB_PASSWORD'),
      jwtSecret: parseEnv('JWT_SECRET'),
      vpnIp: parseEnv('VPN_IP') || '10.99.0.1'
    };
    
    conn.end();
    res.json(credentials);
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/vpn-config - Get admin VPN config from server
app.get('/api/servers/:id/vpn-config', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    
    // Try to read admin VPN config - check multiple locations
    const configResult = await execSSH(conn, `
      if [ -f /tmp/admin-vpn.conf ]; then
        cat /tmp/admin-vpn.conf
      elif [ -f /opt/NovusGate/admin-vpn.conf ]; then
        cat /opt/NovusGate/admin-vpn.conf
      elif [ -f /root/admin-vpn.conf ]; then
        cat /root/admin-vpn.conf
      else
        echo "NOT_FOUND"
      fi
    `);
    
    conn.end();
    
    if (configResult.stdout.trim() === 'NOT_FOUND') {
      return res.status(404).json({ error: 'VPN config not found. It may have been deleted after installation.' });
    }
    
    res.json({ config: configResult.stdout.trim() });
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/:id/uninstall - Clean uninstall NovusGate
app.post('/api/servers/:id/uninstall', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
// Use the shared UNINSTALL_SCRIPT
  // const UNINSTALL_SCRIPT = ... (defined below)

  try {
    const conn = await createSSHConnection(server);
    const result = await execSSH(conn, UNINSTALL_SCRIPT);
    conn.end();
    
    server.status = 'not_installed';
    server.history = server.history || [];
    server.history.unshift({
      action: 'uninstall',
      timestamp: new Date().toISOString(),
      success: result.code === 0
    });
    saveServers(data);
    
    res.json({ success: result.code === 0, output: result.stdout + result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/:id/install - Install NovusGate
app.post('/api/servers/:id/install', async (req, res) => {
  const { source = 'local', reinstall = false, update = false, migrateOnly = false } = req.body;
  
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  // STREAM RESPONSE IMMEDIATELY
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const sendLog = (text, isError = false) => {
    res.write(`data: ${JSON.stringify({ text: text + '\n', stderr: isError })}\n\n`);
  };

  try {
    sendLog('[INFO] Initializing installation...');

    // 1. Create Archive (Local only)
    let archivePath = null;
    if (source === 'local') {
      sendLog('[INFO] Creating project archive...');
      try {
        archivePath = await createProjectArchive();
        sendLog('[INFO] Archive created successfully.');
      } catch (err) {
        sendLog(`[ERROR] Failed to create archive: ${err.message}`, true);
        res.end();
        return;
      }
    }

    // 2. Connect SSH
    sendLog(`[INFO] Connecting to server ${server.host}...`);
    const conn = await createSSHConnection(server);
    sendLog('[INFO] Connected!');

    // 3. Upload Archive
    if (archivePath) {
      sendLog('[INFO] Uploading archive to server (this may take a moment)...');
      try {
        await uploadFile(conn, archivePath, '/tmp/NovusGate.tar.gz');
        sendLog('[INFO] Upload complete.');
      } catch (uploadErr) {
        sendLog(`[ERROR] Upload failed: ${uploadErr.message}`, true);
        throw uploadErr; // Rethrow to trigger outer catch
      } finally {
         if (fs.existsSync(archivePath)) fs.unlinkSync(archivePath); // Cleanup local
      }
    }

    // 4. Prepare Config & Script
    const config = {
      adminUsername: req.body.adminUsername,
      adminPassword: req.body.adminPassword,
      networkName: req.body.networkName,
      networkCidr: req.body.networkCidr,
      vpnIp: req.body.vpnIp,
      dbName: req.body.dbName,
      dbUser: req.body.dbUser,
      dbPassword: req.body.dbPassword
    };

    let script = GENERATE_INSTALL_SCRIPT(config);
    if (migrateOnly) script = DATABASE_MIGRATE_SCRIPT;
    else if (update) script = UPDATE_SCRIPT;
    else if (reinstall) script = GENERATE_REINSTALL_SCRIPT(config);

    const envs = `export DEBIAN_FRONTEND=noninteractive`;

    // 5. Execute Script
    sendLog('[INFO] Executing installation script...');
    
    conn.exec(`${envs}\n${script}`, (err, stream) => {
      if (err) {
        sendLog(`[ERROR] Execution failed: ${err.message}`, true);
        res.end();
        conn.end();
        return;
      }
      
      let outputBuffer = '';

      stream.on('data', (chunk) => {
        const text = chunk.toString();
        outputBuffer += text;
        res.write(`data: ${JSON.stringify({ text })}\n\n`);
      });
      
      stream.stderr.on('data', (chunk) => {
        const text = chunk.toString();
        outputBuffer += text;
        res.write(`data: ${JSON.stringify({ text, stderr: true })}\n\n`);
      });
      
      stream.on('close', (code) => {
        conn.end();
        
        // Update server status
        server.status = code === 0 ? 'installed' : 'error';
        server.installedAt = new Date().toISOString();
        server.history = server.history || [];
        server.history.unshift({
          action: update ? 'update' : (reinstall ? 'reinstall' : 'install'),
          source,
          timestamp: new Date().toISOString(),
          success: code === 0
        });
        saveServers(data);
        
        // Post-install logic (API Key parsing)
        if (code === 0) {
          try {
             const apiKeyMatch = outputBuffer.match(/API_KEY:\s+([a-zA-Z0-9]+)/);
             if (apiKeyMatch && apiKeyMatch[1]) {
                const apiKey = apiKeyMatch[1];
                const envContent = `VITE_API_URL=http://${config.vpnIp || '10.99.0.1'}:8080\nVITE_API_KEY=${apiKey}\n`;
                const dockerPath = '/project_root/web/.env';
                const localPath = path.join(__dirname, '..', 'web', '.env');
                const envPath = fs.existsSync('/project_root') ? dockerPath : localPath;
                
                fs.writeFileSync(envPath, envContent);
                res.write(`data: ${JSON.stringify({ text: '\n[INFO] Local web/.env file updated! 🚀\n' })}\n\n`);
             }
          } catch (e) {
            console.error('Error updating web/.env:', e);
            res.write(`data: ${JSON.stringify({ text: `\n[WARN] Failed to update web/.env: ${e.message}\n` })}\n\n`);
          }
        }

        res.write(`data: ${JSON.stringify({ done: true, success: code === 0 })}\n\n`);
        res.end();
      });
    });
    
  } catch (err) {
    if (archivePath && fs.existsSync(archivePath)) {
      fs.unlinkSync(archivePath);
    }
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/:id/command - Run custom command
app.post('/api/servers/:id/command', async (req, res) => {
  const { command } = req.body;
  
  if (!command) {
    return res.status(400).json({ error: 'Command is required' });
  }
  
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    const result = await execSSH(conn, command);
    conn.end();
    
    res.json({
      success: result.code === 0,
      code: result.code,
      stdout: result.stdout,
      stderr: result.stderr
    });
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/:id/join-vpn - Join server to VPN
app.post('/api/servers/:id/join-vpn', async (req, res) => {
  const { networkId, controlPlaneUrl, apiKey } = req.body;
  
  if (!networkId || !controlPlaneUrl || !apiKey) {
    return res.status(400).json({ error: 'NetworkId, ControlPlaneUrl and ApiKey are required' });
  }

  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server tapılmadı' });
  }

  try {
    const conn = await createSSHConnection(server);
    
    // 1. Install WireGuard
    await execSSH(conn, 'apt-get update && apt-get install -y wireguard curl');
    
    // 2. Generate Keys
    const privKeyResult = await execSSH(conn, 'wg genkey');
    const privateKey = privKeyResult.stdout.trim();
    const pubKeyResult = await execSSH(conn, `echo "${privateKey}" | wg pubkey`);
    const publicKey = pubKeyResult.stdout.trim();
    
    // 3. Register with Control Plane
    // We need to make an HTTP request from the Installer Service to the Control Plane
    // Or we can do it via curl from the target server? 
    // Let's do it from the Installer Service using fetch/axios (need to install axios or use fetch if node 18+)
    // But easier via curl on target to avoid connectivity issues from Installer -> CP
    
    // Construct curl command to register and get config
    // POST /api/v1/networks/{networkId}/servers
    const registerCmd = `curl -s -X POST "${controlPlaneUrl}/api/v1/networks/${networkId}/servers" \
      -H "X-API-Key: ${apiKey}" \
      -H "Content-Type: application/json" \
      -d '{"name":"${server.name}","publicKey":"${publicKey}","labels":{"installer":"true"}}'`;
      
    const registerResult = await execSSH(conn, registerCmd);
    if (registerResult.code !== 0) {
      throw new Error(`Registration failed: ${registerResult.stderr}`);
    }
    
    const response = JSON.parse(registerResult.stdout);
    if (!response.config) {
        // Access config via dedicated endpoint if not returned directly (our API returns full object?)
        // Our config_handlers.go createServerWithConfig returns: { node: ..., config: ... }
        throw new Error('No config received from Control Plane');
    }
    
    const wgConfig = response.config;
    
    // 4. Write Config
    await execSSH(conn, `echo "${wgConfig}" > /etc/wireguard/wg0.conf`);
    
    // 5. Enable IP Forwarding
    await execSSH(conn, 'sysctl -w net.ipv4.ip_forward=1');
    await execSSH(conn, 'echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf');
    
    // 6. Start WireGuard
    await execSSH(conn, 'systemctl enable --now wg-quick@wg0');
    
    conn.end();
    
    server.history = server.history || [];
    server.history.unshift({
      action: 'join-vpn',
      timestamp: new Date().toISOString(),
      success: true
    });
    saveServers(data);
    
    res.json({ success: true, message: 'Successfully joined VPN!' });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ INSTALL SCRIPTS ============

const GENERATE_INSTALL_SCRIPT = (config) => `
#!/bin/bash
set -e

INSTALL_DIR="/opt/NovusGate"
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

# Configuration Variables
ADMIN_USERNAME="${config.adminUsername || 'admin'}"
ADMIN_PASSWORD="${config.adminPassword || ''}" # Empty means auto-generate
VPN_IP="${config.vpnIp || '10.99.0.1'}"
VPN_SUBNET="${config.vpnIp ? config.vpnIp.replace(/\.\d+$/, '.0/24') : '10.99.0.0/24'}"
VPN_CLIENT_IP="${config.vpnIp ? config.vpnIp.replace(/\.\d+$/, '.2') : '10.99.0.2'}"

# Database Config
DB_NAME="${config.dbName || 'NovusGate'}"
DB_USER="${config.dbUser || 'NovusGate'}"
DB_PASSWORD="${config.dbPassword || ''}" # Empty means auto-generate

log_info() { echo -e "\${GREEN}[INFO]\${NC} $1"; }
log_warn() { echo -e "\${YELLOW}[WARN]\${NC} $1"; }
log_error() { echo -e "\${RED}[ERROR]\${NC} $1"; }

echo "=========================================="
echo "  NovusGate Server Installer"
echo "=========================================="

# Update system
log_info "Updating system..."
apt-get update -qq

# Install Docker if not present
if ! command -v docker &> /dev/null; then
  log_info "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
else
  log_info "Docker already installed ✓"
fi

# Install Docker Compose
if ! command -v docker-compose &> /dev/null; then
  log_info "Installing Docker Compose..."
  apt-get install -y docker-compose
else
  log_info "Docker Compose already installed ✓"
fi

# Extract archive
log_info "Extracting archive..."
mkdir -p "$INSTALL_DIR"
tar -xzf /tmp/NovusGate.tar.gz -C "$INSTALL_DIR"
rm -f /tmp/NovusGate.tar.gz

# Generate secrets
log_info "Generating security keys..."
generate_secret() {
  openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -t x1 | tr -d ' \n'
}

API_KEY=$(generate_secret)
JWT_SECRET=$(generate_secret)

if [ -z "$DB_PASSWORD" ]; then
  DB_PASSWORD=$(generate_secret)
fi

if [ -z "$ADMIN_PASSWORD" ]; then
  ADMIN_PASSWORD=$(generate_secret)
fi

# Detect Server Public IP
log_info "Detecting Server IP..."
SERVER_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
log_info "Server IP: $SERVER_IP"


# ==========================================
# ADMIN VPN SETUP (MOVED BEFORE DOCKER START)
# ==========================================
log_info "Configuring Admin VPN Security Layer..."

# Pre-flight Cleanup (Prevent existing wg0 conflicts)
log_info "Cleaning up previous VPN state..."
# Pre-flight Cleanup (Prevent existing wg0 conflicts)
log_info "Cleaning up previous VPN state..."

# 1. Stop existing Docker containers holding ports
if command -v docker &> /dev/null; then
  docker ps -q --filter name=NovusGate | xargs -r docker stop || true
  docker ps -q --filter name=NovusGate | xargs -r docker rm || true
fi

# 2. Stop Systemd Services
systemctl stop wg-quick@wg0 2>/dev/null || true
systemctl disable wg-quick@wg0 2>/dev/null || true

# 3. Force remove interface if it exists (e.g. from stuck container)
ip link delete wg0 2>/dev/null || true

# 4. Clean Configs
rm -f /etc/wireguard/wg0.conf
rm -f /etc/wireguard/wg1.conf # Clean old wg1 if exists

# Install WireGuard
if ! command -v wg &> /dev/null; then
  log_info "Installing WireGuard..."
  apt-get install -y wireguard
fi

# Install Fail2Ban for SSH protection
if ! command -v fail2ban-client &> /dev/null; then
  log_info "Installing Fail2Ban..."
  apt-get install -y fail2ban
  
  # Create SSH jail config
  cat <<F2B > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
F2B

  # Enable and start fail2ban
  systemctl enable fail2ban
  systemctl restart fail2ban
  log_info "Fail2Ban installed and configured ✓"
else
  log_info "Fail2Ban already installed ✓"
fi

# Generate Keys
umask 077
WG_SERVER_PRIVATE_KEY=$(wg genkey)
WG_SERVER_PUBLIC_KEY=$(echo "$WG_SERVER_PRIVATE_KEY" | wg pubkey)
WG_CLIENT_PRIVATE_KEY=$(wg genkey)
WG_CLIENT_PUBLIC_KEY=$(echo "$WG_CLIENT_PRIVATE_KEY" | wg pubkey)

# Create Server Config (wg0)
mkdir -p /etc/wireguard
cat <<WG0 > /etc/wireguard/wg0.conf
[Interface]
Address = $VPN_IP/24
ListenPort = 51820
PrivateKey = $WG_SERVER_PRIVATE_KEY
SaveConfig = false

[Peer]
PublicKey = $WG_CLIENT_PUBLIC_KEY
AllowedIPs = $VPN_CLIENT_IP/32
WG0

# Enable and Start wg0
systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

# Generate Client Config
cat <<CLIENT > /tmp/admin-vpn.conf
[Interface]
PrivateKey = $WG_CLIENT_PRIVATE_KEY
Address = $VPN_CLIENT_IP/32
DNS = 8.8.8.8

[Peer]
PublicKey = $WG_SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:51820
AllowedIPs = $VPN_SUBNET
PersistentKeepalive = 25
CLIENT

# Also save to permanent location
cp /tmp/admin-vpn.conf $INSTALL_DIR/admin-vpn.conf

log_info "Admin VPN configured."

# Apply Firewall (MOVED BEFORE DOCKER START)
# This includes 'systemctl restart docker' which fixes the chain issues
log_info "Applying Firewall Rules..."
if [ -f "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh" ]; then
  if command -v sed &> /dev/null; then
    sed -i 's/\r$//' "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  fi
  chmod +x "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
elif [ -f "$INSTALL_DIR/deployments/docker/setup-firewall.sh" ]; then
  chmod +x "$INSTALL_DIR/deployments/docker/setup-firewall.sh"
  "$INSTALL_DIR/deployments/docker/setup-firewall.sh"
else
  log_warn "setup-firewall.sh not found. Skipping firewall step."
fi


# Create Server .env
# Ensure directory exists
mkdir -p "$INSTALL_DIR/server/deployments/docker"

cat <<EOF > "$INSTALL_DIR/server/deployments/docker/.env"
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
JWT_SECRET=$JWT_SECRET

API_KEY=$API_KEY
ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_PASSWORD=$ADMIN_PASSWORD
WG_SERVER_ENDPOINT=$SERVER_IP
ADMIN_CIDR=$VPN_SUBNET
EOF
chmod 600 "$INSTALL_DIR/server/deployments/docker/.env"

# Create Web .env
# Ensure directory exists
mkdir -p "$INSTALL_DIR/web"


cat <<EOF > "$INSTALL_DIR/web/.env"
VITE_API_URL=http://$VPN_IP:8080
VITE_API_KEY=$API_KEY
EOF
chmod 600 "$INSTALL_DIR/web/.env"


# Start services
log_info "Starting services..."
cd "$INSTALL_DIR"
docker-compose -f server/deployments/docker/docker-compose.yml up -d --build

# Wait
log_info "Waiting 30 seconds..."
sleep 30

# Initialize
log_info "Skipping default network creation (Admin Network is auto-created)..."
# We DO NOT run init anymore, because we only want the Admin Network initially.
# INIT_OUTPUT=$(docker-compose -f server/deployments/docker/docker-compose.yml exec -T control-plane ./NovusGate-server init --name "$NETWORK_NAME" --cidr "$NETWORK_CIDR" 2>&1 || true)
# echo "$INIT_OUTPUT"

SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "=========================================="
echo -e "\${GREEN}  INSTALLATION COMPLETE!\${NC}"
echo "=========================================="
echo "Server IP: $SERVER_IP"
echo ""
echo "------------------------------------------"
echo "  🔒 ADMIN VPN CONFIG (REQUIRED)  "
echo "------------------------------------------"
echo "The Admin Dashboard is now HIDDEN behind this VPN."
echo "You MUST connect to this VPN to access the dashboard."
echo ""
echo "BEGIN_VPN_CONFIG"
cat /tmp/admin-vpn.conf
echo "END_VPN_CONFIG"
echo ""
echo "Save this as 'admin-vpn.conf' and import into WireGuard."
echo "------------------------------------------"
echo ""
echo "Admin Dashboard: http://$VPN_IP:3007"
echo "API Endpoint:    http://$VPN_IP:8080"
echo ""
echo "------------------------------------------"
echo "  SECURITY KEYS (SAVE THESE!)"
echo "------------------------------------------"
echo "ADMIN USER:  $ADMIN_USERNAME"
echo "ADMIN PASS:  $ADMIN_PASSWORD"
echo "------------------------------------------"
echo "API_KEY:     $API_KEY"
echo "------------------------------------------"
echo "INTERNAL SECRETS (.env):"
echo "DB_PASSWORD: $DB_PASSWORD"
echo "JWT_SECRET:  $JWT_SECRET"

echo "------------------------------------------"
echo "These keys were automatically written to deployments/docker/.env"
echo ""
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep NovusGate || true
`;


const GENERATE_REINSTALL_SCRIPT = (config) => {
  // Config Defaults
  const DB_NAME = config.dbName || 'NovusGate';
  const DB_USER = config.dbUser || 'NovusGate';
  const DB_PASS = config.dbPassword || ''; // If empty, generate or keep old?
  const ADMIN_USER = config.adminUsername || 'admin';
  const ADMIN_PASS = config.adminPassword || '';
  // Removed unused NET_NAME/CIDR
  // Calculate ADMIN_CIDR for .env
  const VPN_IP = config.vpnIp || '10.99.0.1'; 
  const ADMIN_CIDR = VPN_IP.replace(/\.\d+$/, '.0/24');

  return `
#!/bin/bash
set -e

INSTALL_DIR="/opt/NovusGate"

echo "=========================================="
echo "  NovusGate REINSTALL"
echo "=========================================="

# Backup .env before deleting
if [ -f "$INSTALL_DIR/server/deployments/docker/.env" ]; then
  echo "Preserving old config..."
  cp "$INSTALL_DIR/server/deployments/docker/.env" /tmp/NovusGate.env.bak
fi

# Stop and remove existing
if [ -f "$INSTALL_DIR/server/deployments/docker/docker-compose.yml" ]; then
  cd "$INSTALL_DIR"
  # NO -v flag here, keep volumes!
  docker-compose -f server/deployments/docker/docker-compose.yml down --rmi local 2>/dev/null || true
fi

# Remove files but KEEP the data directory
if [ -d "$INSTALL_DIR" ]; then
  echo "Cleaning files (preserving data)..."
  find "$INSTALL_DIR" -maxdepth 1 ! -name 'data' ! -name '.' -exec rm -rf {} +
fi

# Extract new
mkdir -p "$INSTALL_DIR"
tar -xzf /tmp/NovusGate.tar.gz -C "$INSTALL_DIR"
rm -f /tmp/NovusGate.tar.gz

# Note: In reinstall, we might want to keep old secrets or generate new ones?
# Usually reinstall means "nuclear option", so let's check if .env exists, if so keep it, else generate
cd "$INSTALL_DIR"

# Restore or generate .env
if [ -f "/tmp/NovusGate.env.bak" ]; then
  echo "Restoring configuration..."
  # Creating directory structure if missing after clean
  mkdir -p server/deployments/docker
  mv /tmp/NovusGate.env.bak server/deployments/docker/.env
  
  # Ensure WG_SERVER_ENDPOINT exists
  if ! grep -q "WG_SERVER_ENDPOINT" server/deployments/docker/.env; then
    SERVER_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
    echo "WG_SERVER_ENDPOINT=$SERVER_IP" >> server/deployments/docker/.env
  fi
else
  echo "Generating new keys (Config provided)..."
  generate_secret() { openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -t x1 | tr -d ' \\n'; }
  
  API_KEY=$(generate_secret)
  JWT_SECRET=$(generate_secret)
  
  # Use provided or generate
  DB_PASSWORD="${DB_PASS}"
  if [ -z "$DB_PASSWORD" ]; then
     DB_PASSWORD=$(generate_secret)
  fi

  ADMIN_PASSWORD="${ADMIN_PASS}"
  if [ -z "$ADMIN_PASSWORD" ]; then
     ADMIN_PASSWORD=$(generate_secret)
  fi
  
  SERVER_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
  
  mkdir -p server/deployments/docker
  cat <<EOF > server/deployments/docker/.env
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=$DB_PASSWORD
JWT_SECRET=$JWT_SECRET

API_KEY=$API_KEY
ADMIN_USERNAME=${ADMIN_USER}
ADMIN_PASSWORD=$ADMIN_PASSWORD
WG_SERVER_ENDPOINT=$SERVER_IP
ADMIN_CIDR=${ADMIN_CIDR}
EOF
  
  # Also regenerate web/.env if needed or ensure it has VITE_ prefix
  # For reinstall we might rely on the main install flow to handle web .env but 
  # strictly speaking the server.js script handles the web.env creation in the main flow.
  # The reinstall script logic above creates 'server/deployments/docker/.env'.
  # It does NOT appear to create 'web/.env' in the current script block. 
  # Wait, looking at the code, install script does it at line 918. 
  # Reinstall script currently ONLY touches server/.env.
  # If web/.env exists it might be stale or incorrect format.
  # Let's add web/.env regeneration to Reinstall script for safety.
  
  mkdir -p web
  cat <<EOF > web/.env
VITE_API_URL=http://${VPN_IP}:8080
VITE_API_KEY=$API_KEY
EOF
  chmod 600 web/.env
fi

# Ensure Fail2Ban is installed
if ! command -v fail2ban-client &> /dev/null; then
  echo "Installing Fail2Ban..."
  apt-get update -qq
  apt-get install -y fail2ban
  
  # Create SSH jail config
  cat <<F2B > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
F2B

  systemctl enable fail2ban
  systemctl restart fail2ban
  echo "Fail2Ban installed ✓"
fi

# Setup Firewall (re-run to ensure rules match new config if relevant, though mostly static)
if [ -f "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh" ]; then
  # Fix Windows CRLF line endings
  sed -i 's/\\r$//' "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  chmod +x "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
fi

# Start
echo "Starting services..."
docker-compose -f server/deployments/docker/docker-compose.yml up -d --build

echo "Waiting for DB..."
sleep 20

# Init with dynamic params
echo "Re-Initializing NovusGate Control Plane..."
# Init command skipped (Admin Network auto-bootstrapped)

echo "REINSTALL COMPLETE!"
docker ps | grep NovusGate || true
`;
};

// ============ HELPERS ============

const UNINSTALL_SCRIPT = `
#!/bin/bash
set -e
INSTALL_DIR="/opt/NovusGate"

echo "=========================================="
echo "  NovusGate DEEP UNINSTALL"
echo "  WARNING: This will delete ALL data"
echo "=========================================="

echo "[1/5] Stopping Docker services..."
if [ -f "$INSTALL_DIR/server/deployments/docker/docker-compose.yml" ]; then
  cd "$INSTALL_DIR"
  docker-compose -f server/deployments/docker/docker-compose.yml down -v --rmi all --remove-orphans 2>/dev/null || true
fi

# Fallback: kill any NovusGate containers
docker ps -q --filter name=NovusGate | xargs -r docker stop || true
docker ps -a --format "{{.ID}} {{.Names}}" | grep NovusGate | awk '{print $1}' | xargs -r docker rm -f || true

echo "[2/5] Cleaning WireGuard Interfaces..."
# Stop Admin VPN
systemctl stop wg-quick@wg1 2>/dev/null || true
systemctl disable wg-quick@wg1 2>/dev/null || true
ip link delete wg1 2>/dev/null || true
rm -f /etc/wireguard/wg1.conf

# Stop Node VPN (Admin Network now on wg0)
systemctl stop wg-quick@wg0 2>/dev/null || true
systemctl disable wg-quick@wg0 2>/dev/null || true
ip link delete wg0 2>/dev/null || true
rm -f /etc/wireguard/wg0.conf

echo "[3/5] Flushing Firewall Rules..."
# Reset iptables to default ACCEPT
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X

# Save clean state
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
fi

echo "[4/5] Removing Files..."
rm -rf "$INSTALL_DIR"

echo "[5/5] Cleaning Docker Resources..."
docker system prune -af --volumes 2>/dev/null || true

echo "[DONE] Cleanup Complete!"
echo "Server is ready for a fresh install."
`;

const UPDATE_SCRIPT = `
#!/bin/bash
set -e
INSTALL_DIR="/opt/NovusGate"
TEMP_DIR="/tmp/NovusGate_update"

echo "=========================================="
echo "  NovusGate SMART UPDATE v2.0"
echo "  Only changed files & containers updated"
echo "=========================================="

# 1. Extract new code to temp dir
echo "[1/6] Extracting new files..."
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
tar -xzf /tmp/NovusGate.tar.gz -C "$TEMP_DIR"
rm -f /tmp/NovusGate.tar.gz

# 2. Detect what changed
echo "[2/6] Detecting changes..."

SERVER_CHANGED=false
WEB_CHANGED=false
DOCKER_CHANGED=false

# Check server/ changes (Go code)
if [ -d "$INSTALL_DIR/server" ]; then
  SERVER_DIFF=$(diff -rq "$TEMP_DIR/server" "$INSTALL_DIR/server" \\
    --exclude='.env' \\
    --exclude='data' \\
    --exclude='*.log' \\
    2>/dev/null | grep -v "Only in $INSTALL_DIR" || true)
  if [ -n "$SERVER_DIFF" ]; then
    SERVER_CHANGED=true
    echo "  📦 Server code changed"
  fi
else
  SERVER_CHANGED=true
  echo "  📦 Server code is new"
fi

# Check web/ changes (React code)
if [ -d "$INSTALL_DIR/web" ]; then
  WEB_DIFF=$(diff -rq "$TEMP_DIR/web" "$INSTALL_DIR/web" \\
    --exclude='.env' \\
    --exclude='node_modules' \\
    --exclude='dist' \\
    --exclude='*.log' \\
    2>/dev/null | grep -v "Only in $INSTALL_DIR" || true)
  if [ -n "$WEB_DIFF" ]; then
    WEB_CHANGED=true
    echo "  🌐 Web code changed"
  fi
else
  WEB_CHANGED=true
  echo "  🌐 Web code is new"
fi

# Check docker-compose or Dockerfile changes
if [ -f "$INSTALL_DIR/server/deployments/docker/docker-compose.yml" ]; then
  if ! diff -q "$TEMP_DIR/server/deployments/docker/docker-compose.yml" "$INSTALL_DIR/server/deployments/docker/docker-compose.yml" > /dev/null 2>&1; then
    DOCKER_CHANGED=true
    echo "  🐳 Docker config changed"
  fi
  if ! diff -q "$TEMP_DIR/server/deployments/docker/Dockerfile.control-plane" "$INSTALL_DIR/server/deployments/docker/Dockerfile.control-plane" > /dev/null 2>&1; then
    SERVER_CHANGED=true
    echo "  🐳 Server Dockerfile changed"
  fi
fi

if [ -f "$TEMP_DIR/web/Dockerfile" ] && [ -f "$INSTALL_DIR/web/Dockerfile" ]; then
  if ! diff -q "$TEMP_DIR/web/Dockerfile" "$INSTALL_DIR/web/Dockerfile" > /dev/null 2>&1; then
    WEB_CHANGED=true
    echo "  🐳 Web Dockerfile changed"
  fi
fi

# If nothing changed
if [ "$SERVER_CHANGED" = false ] && [ "$WEB_CHANGED" = false ] && [ "$DOCKER_CHANGED" = false ]; then
  echo ""
  echo "  ✅ No changes detected! System is up to date."
  rm -rf "$TEMP_DIR"
  exit 0
fi

# 3. Copy files (preserving .env and data)
echo "[3/6] Updating files..."
if command -v rsync &> /dev/null; then
  rsync -a --delete \\
    --exclude='.env' \\
    --exclude='server/deployments/docker/.env' \\
    --exclude='web/.env' \\
    --exclude='data/' \\
    --exclude='*.log' \\
    "$TEMP_DIR/" "$INSTALL_DIR/"
else
  # Backup .env files
  [ -f "$INSTALL_DIR/server/deployments/docker/.env" ] && cp "$INSTALL_DIR/server/deployments/docker/.env" /tmp/NovusGate.env.bak
  [ -f "$INSTALL_DIR/web/.env" ] && cp "$INSTALL_DIR/web/.env" /tmp/NovusGate.web.env.bak
  
  # Copy files
  cp -r "$TEMP_DIR"/* "$INSTALL_DIR/"
  
  # Restore .env files
  [ -f "/tmp/NovusGate.env.bak" ] && mv /tmp/NovusGate.env.bak "$INSTALL_DIR/server/deployments/docker/.env"
  [ -f "/tmp/NovusGate.web.env.bak" ] && mv /tmp/NovusGate.web.env.bak "$INSTALL_DIR/web/.env"
fi

rm -rf "$TEMP_DIR"
cd "$INSTALL_DIR"

# 4. Rebuild only changed containers
echo "[4/6] Rebuilding changed containers..."

# Remove dangling images first to avoid conflicts
docker image prune -f 2>/dev/null || true

if [ "$DOCKER_CHANGED" = true ]; then
  echo "  Docker config changed - full rebuild required"
  docker-compose -f server/deployments/docker/docker-compose.yml down --rmi local 2>/dev/null || true
  docker-compose -f server/deployments/docker/docker-compose.yml up -d --build --force-recreate
elif [ "$SERVER_CHANGED" = true ] && [ "$WEB_CHANGED" = true ]; then
  echo "  Rebuilding: control-plane, web"
  docker-compose -f server/deployments/docker/docker-compose.yml stop control-plane web 2>/dev/null || true
  docker-compose -f server/deployments/docker/docker-compose.yml rm -f control-plane web 2>/dev/null || true
  docker-compose -f server/deployments/docker/docker-compose.yml build --no-cache control-plane web
  docker-compose -f server/deployments/docker/docker-compose.yml up -d --force-recreate --no-deps control-plane web
elif [ "$SERVER_CHANGED" = true ]; then
  echo "  Rebuilding: control-plane only"
  docker-compose -f server/deployments/docker/docker-compose.yml stop control-plane 2>/dev/null || true
  docker-compose -f server/deployments/docker/docker-compose.yml rm -f control-plane 2>/dev/null || true
  docker-compose -f server/deployments/docker/docker-compose.yml build --no-cache control-plane
  docker-compose -f server/deployments/docker/docker-compose.yml up -d --force-recreate --no-deps control-plane
elif [ "$WEB_CHANGED" = true ]; then
  echo "  Rebuilding: web only"
  docker-compose -f server/deployments/docker/docker-compose.yml stop web 2>/dev/null || true
  docker-compose -f server/deployments/docker/docker-compose.yml rm -f web 2>/dev/null || true
  docker-compose -f server/deployments/docker/docker-compose.yml build --no-cache web
  docker-compose -f server/deployments/docker/docker-compose.yml up -d --force-recreate --no-deps web
fi

# 5. Run migrations if server changed
echo "[5/6] Checking database..."
if [ "$SERVER_CHANGED" = true ]; then
  sleep 5
  docker-compose -f server/deployments/docker/docker-compose.yml exec -T control-plane ./NovusGate-server migrate 2>&1 || echo "Migration skipped"
else
  echo "  Server unchanged - skipping migration"
fi

# 6. Apply Firewall (only if setup script changed)
echo "[6/6] Checking firewall..."
if [ -f "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh" ]; then
  sed -i 's/\\r$//' "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  chmod +x "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  # Only run if file was in the changed set
  if [ "$SERVER_CHANGED" = true ] || [ "$DOCKER_CHANGED" = true ]; then
    "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  else
    echo "  Firewall unchanged - skipping"
  fi
fi

# Ensure all containers running
docker-compose -f server/deployments/docker/docker-compose.yml up -d

echo ""
echo "=========================================="
echo "  UPDATE COMPLETE!"
if [ "$SERVER_CHANGED" = true ]; then echo "  ✅ Server rebuilt"; fi
if [ "$WEB_CHANGED" = true ]; then echo "  ✅ Web rebuilt"; fi
if [ "$SERVER_CHANGED" = false ] && [ "$WEB_CHANGED" = false ]; then echo "  ✅ Config updated (no rebuild needed)"; fi
echo "  ✅ .env preserved"
echo "  ✅ Database preserved"
echo "=========================================="
docker ps --format "table {{.Names}}\\t{{.Status}}" | grep NovusGate || true
`;

// Database-only migration script (no file changes)
const DATABASE_MIGRATE_SCRIPT = `
#!/bin/bash
set -e
INSTALL_DIR="/opt/NovusGate"

echo "=========================================="
echo "  NovusGate DATABASE MIGRATION"
echo "  Files PRESERVED"
echo "=========================================="

cd "$INSTALL_DIR"

echo "[1/2] Checking database migrations..."
docker-compose -f server/deployments/docker/docker-compose.yml exec -T control-plane ./NovusGate-server migrate

echo ""
echo "=========================================="
echo "  ✅ Database updated!"
echo "=========================================="
`;
function createProjectArchive() {
  return new Promise((resolve, reject) => {
    const archivePath = path.join(__dirname, 'NovusGate.tar.gz');
    
    const excludes = [
      '--exclude=node_modules',
      '--exclude=.git',
      '--exclude=*.exe',
      '--exclude=*.tar.gz',
      '--exclude=*.log',
      '--exclude=.env',
      '--exclude=.idea',
      '--exclude=.vscode',
      '--exclude=server/start_dev.sh', // Exclude dev scripts
      '--exclude=installer/node_modules' // Exclude installer modules from archive
    ].join(' ');
    
    const tarCommand = `tar -czf "${archivePath}" -C "${PROJECT_ROOT}" ${excludes} server web`;
    
    exec(tarCommand, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(stderr || error.message));
      } else {
        resolve(archivePath);
      }
    });
  });
}

function uploadFile(conn, localPath, remotePath) {
  return new Promise((resolve, reject) => {
    conn.sftp((err, sftp) => {
      if (err) return reject(err);
      
      const readStream = fs.createReadStream(localPath);
      const writeStream = sftp.createWriteStream(remotePath);
      
      writeStream.on('close', resolve);
      writeStream.on('error', reject);
      readStream.pipe(writeStream);
    });
  });
}

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '2.0.0' });
});

// Register Fail2ban routes
fail2banModule.registerRoutes(app, loadServers, createSSHConnection);

// Start server
const PORT = process.env.PORT || 3017;
app.listen(PORT, () => {
  console.log(`NovusGate Center: http://localhost:${PORT}`);
  console.log(`Server data: ${SERVERS_FILE}`);
});
