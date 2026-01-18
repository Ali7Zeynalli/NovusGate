/**
 * Fail2ban Module - SSH protection monitoring
 * Provides fail2ban status and banned IPs information
 */

/**
 * Execute SSH command and return result
 */
function execSSH(conn, command) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) return reject(err);
      let stdout = '';
      let stderr = '';
      stream.on('data', (data) => { stdout += data.toString(); });
      stream.stderr.on('data', (data) => { stderr += data.toString(); });
      stream.on('close', (code) => {
        resolve({ stdout, stderr, code });
      });
    });
  });
}

/**
 * Get fail2ban status from server
 * @param {Object} conn - SSH connection
 * @returns {Object} fail2ban status info
 */
async function getFail2banStatus(conn) {
  try {
    // Check if fail2ban is installed
    const installed = await execSSH(conn, 'command -v fail2ban-client >/dev/null 2>&1 && echo "yes" || echo "no"');
    
    if (installed.stdout.trim() !== 'yes') {
      return {
        installed: false,
        running: false,
        jails: [],
        bannedIPs: [],
        totalBanned: 0
      };
    }

    // Check if fail2ban service is running
    const running = await execSSH(conn, 'systemctl is-active fail2ban 2>/dev/null || echo "inactive"');
    const isRunning = running.stdout.trim() === 'active';

    if (!isRunning) {
      return {
        installed: true,
        running: false,
        jails: [],
        bannedIPs: [],
        totalBanned: 0
      };
    }

    // Get jail list
    const jailsResult = await execSSH(conn, 'fail2ban-client status 2>/dev/null | grep "Jail list" | sed "s/.*://;s/,//g"');
    const jails = jailsResult.stdout.trim().split(/\s+/).filter(j => j);

    // Get banned IPs for each jail
    const bannedIPs = [];
    let totalBanned = 0;

    for (const jail of jails) {
      const jailStatus = await execSSH(conn, `fail2ban-client status ${jail} 2>/dev/null`);
      const output = jailStatus.stdout;

      // Parse currently banned
      const bannedMatch = output.match(/Currently banned:\s*(\d+)/);
      const currentBanned = bannedMatch ? parseInt(bannedMatch[1]) : 0;
      totalBanned += currentBanned;

      // Parse banned IP list
      const ipMatch = output.match(/Banned IP list:\s*(.*)/);
      const ips = ipMatch ? ipMatch[1].trim().split(/\s+/).filter(ip => ip) : [];

      // Parse total banned (historical)
      const totalMatch = output.match(/Total banned:\s*(\d+)/);
      const totalJailBanned = totalMatch ? parseInt(totalMatch[1]) : 0;

      // Parse failed attempts
      const failedMatch = output.match(/Currently failed:\s*(\d+)/);
      const currentFailed = failedMatch ? parseInt(failedMatch[1]) : 0;

      bannedIPs.push({
        jail: jail,
        currentBanned: currentBanned,
        totalBanned: totalJailBanned,
        currentFailed: currentFailed,
        ips: ips
      });
    }

    // Get fail2ban log (last 10 ban events)
    const logResult = await execSSH(conn, 'grep "Ban " /var/log/fail2ban.log 2>/dev/null | tail -10');
    const recentBans = logResult.stdout.trim().split('\n').filter(l => l).map(line => {
      // Parse: 2026-01-12 10:30:45,123 fail2ban.actions [12345]: NOTICE [sshd] Ban 192.168.1.1
      const match = line.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*\[(\w+)\] Ban (\S+)/);
      if (match) {
        return {
          timestamp: match[1],
          jail: match[2],
          ip: match[3]
        };
      }
      return null;
    }).filter(b => b);

    return {
      installed: true,
      running: true,
      jails: jails,
      bannedIPs: bannedIPs,
      totalBanned: totalBanned,
      recentBans: recentBans
    };

  } catch (error) {
    console.error('Error getting fail2ban status:', error);
    return {
      installed: false,
      running: false,
      error: error.message
    };
  }
}

/**
 * Unban an IP address
 * @param {Object} conn - SSH connection
 * @param {string} jail - Jail name (e.g., 'sshd')
 * @param {string} ip - IP address to unban
 */
async function unbanIP(conn, jail, ip) {
  try {
    const result = await execSSH(conn, `fail2ban-client set ${jail} unbanip ${ip} 2>&1`);
    return {
      success: result.code === 0,
      message: result.stdout.trim() || result.stderr.trim()
    };
  } catch (error) {
    return {
      success: false,
      message: error.message
    };
  }
}

/**
 * Register fail2ban routes
 * @param {Express} app - Express app instance
 * @param {Function} loadServers - Function to load servers data
 * @param {Function} createSSHConnection - Function to create SSH connection
 */
function registerRoutes(app, loadServers, createSSHConnection) {
  
  // GET /api/servers/:id/fail2ban - Get fail2ban status
  app.get('/api/servers/:id/fail2ban', async (req, res) => {
    const data = loadServers();
    const server = data.servers.find(s => s.id === req.params.id);
    
    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }

    let conn;
    try {
      conn = await createSSHConnection(server);
      const status = await getFail2banStatus(conn);
      res.json(status);
    } catch (error) {
      res.status(500).json({ error: error.message });
    } finally {
      if (conn) conn.end();
    }
  });

  // POST /api/servers/:id/fail2ban/unban - Unban an IP
  app.post('/api/servers/:id/fail2ban/unban', async (req, res) => {
    const { jail, ip } = req.body;
    
    if (!jail || !ip) {
      return res.status(400).json({ error: 'jail and ip are required' });
    }

    const data = loadServers();
    const server = data.servers.find(s => s.id === req.params.id);
    
    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }

    let conn;
    try {
      conn = await createSSHConnection(server);
      const result = await unbanIP(conn, jail, ip);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    } finally {
      if (conn) conn.end();
    }
  });
}

module.exports = {
  getFail2banStatus,
  unbanIP,
  registerRoutes
};
