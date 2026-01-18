const { Client } = require('ssh2');

class LogService {
  constructor() {
    this.activeStreams = new Map();
  }

  // Create SSH connection (Duplicated helper to allow standalone usage if needed, 
  // or we can pass the connection factory from server.js. For now, let's keep it self-contained or exported)
  // BETTER: Receive the server config and create connection here.
  
  createConnection(server) {
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

  async streamContainerLogs(server, container, req, res) {
    let conn;
    try {
      conn = await this.createConnection(server);
      
      // SSE Headers
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no' // Nginx support if needed
      });

      // Send initial message
      res.write(`data: ${JSON.stringify({ text: `Starting log stream for ${container}...\n` })}\n\n`);

      // Run docker logs -f
      // -f: follow (stream)
      // --tail 50: show last 50 lines first
      // -t: show timestamps
      const cmd = `docker logs -f --tail 50 -t ${container}`;
      
      conn.exec(cmd, (err, stream) => {
        if (err) {
          res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
          conn.end();
          return;
        }

        // Handle stream data
        stream.on('data', (data) => {
          // Docker logs can be binary stream multiplexed (stdout/stderr).
          // SSH stream returns raw data.
          // We wrap it in a JSON structure for the frontend 'streamResponse' handler (or similar)
          const lines = data.toString().split('\n');
          for (const line of lines) {
            if (line.trim()) {
              res.write(`data: ${JSON.stringify({ text: line + '\n' })}\n\n`);
            }
          }
        });

        stream.stderr.on('data', (data) => {
          const lines = data.toString().split('\n');
          for (const line of lines) {
            if (line.trim()) {
              res.write(`data: ${JSON.stringify({ text: line + '\n' })}\n\n`);
            }
          }
        });

        stream.on('close', (code, signal) => {
          res.write(`data: ${JSON.stringify({ done: true, success: code === 0 })}\n\n`);
          conn.end();
          res.end();
        });
        
        // Clean up connection on client disconnect
        req.on('close', () => {
           console.log('Client closed log stream');
           conn.end(); // Kill SSH connection, which kills docker logs command
        });
      });

    } catch (err) {
      // If headers not sent yet
      if (!res.headersSent) {
        res.status(500).json({ error: err.message });
      } else {
        res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
        res.end();
      }
      if (conn) conn.end();
    }
  }
}

module.exports = new LogService();
