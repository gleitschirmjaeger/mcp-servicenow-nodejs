import express from 'express';
import dotenv from 'dotenv';
import axios from 'axios';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { ServiceNowClient } from './servicenow-client.js';
import { createMcpServer } from './mcp-server-consolidated.js';
import { configManager } from './config-manager.js';

dotenv.config();

const SSE_KEEPALIVE_INTERVAL = parseInt(process.env.SSE_KEEPALIVE_INTERVAL || '15000', 10);

const app = express();
app.use(express.json());

// In-memory session store (sessionId -> {server, transport, client})
const sessions = {};

// In-memory OAuth token store (state -> token data), single-use
const pendingTokens = new Map();

const defaultInstance = configManager.getDefaultInstance();
console.log(`🔗 Default ServiceNow instance: ${defaultInstance.name} (${defaultInstance.url})`);

/**
 * Helper: create a fresh ServiceNowClient for a session
 */
function createClient(bearerToken = null) {
  const client = new ServiceNowClient(
    defaultInstance.url,
    defaultInstance.username,
    defaultInstance.password
  );
  client.currentInstanceName = defaultInstance.name;
  if (bearerToken) {
    client.setAccessToken(bearerToken);
  }
  return client;
}

/**
 * GET /oauth/callback - ServiceNow redirects here after user authorizes
 */
app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send('Missing code or state parameter');
  }

  try {
    const response = await axios.post(
      `${defaultInstance.url}/oauth_token.do`,
      new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        client_id:     process.env.SN_OAUTH_CLIENT_ID,
        client_secret: process.env.SN_OAUTH_CLIENT_SECRET,
        redirect_uri:  process.env.SN_OAUTH_REDIRECT_URI
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    pendingTokens.set(state, {
      access_token:  response.data.access_token,
      refresh_token: response.data.refresh_token,
      expires_in:    response.data.expires_in,
      created_at:    Date.now()
    });

    // Close the popup and signal success back to the opener window
    res.send(`
      <html><body><script>
        window.opener.postMessage(
          { type: 'SN_OAUTH_SUCCESS', state: '${state}' },
          '${defaultInstance.url}'
        );
        window.close();
      </script></body></html>
    `);
  } catch (err) {
    console.error('❌ OAuth callback error:', err.message);
    res.status(500).send('OAuth token exchange failed: ' + err.message);
  }
});

/**
 * GET /oauth/token/:state - Single-use token retrieval after popup closes
 */
app.get('/oauth/token/:state', (req, res) => {
  const token = pendingTokens.get(req.params.state);
  if (!token) {
    return res.status(404).json({ error: 'Token not found or already consumed' });
  }
  pendingTokens.delete(req.params.state); // Single-use — delete after retrieval
  res.json({ access_token: token.access_token, expires_in: token.expires_in });
});

/**
 * GET /mcp - Establish SSE connection
 * Extracts Bearer token from Authorization header if present
 */
app.get('/mcp', async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('X-Accel-Buffering', 'no');
    res.setHeader('Connection', 'keep-alive');
    req.setTimeout(0);
    res.setTimeout(0);

    // Extract Bearer token if provided
    const authHeader = req.headers['authorization'];
    const bearerToken = authHeader?.startsWith('Bearer ')
      ? authHeader.slice(7)
      : null;

    // Create a per-session client (with or without OAuth token)
    const sessionClient = createClient(bearerToken);

    if (bearerToken) {
      console.log(`🔐 Session using OAuth Bearer token`);
    } else {
      console.log(`🔑 Session using Basic Auth (service account)`);
    }

    const transport = new SSEServerTransport('/mcp', res);
    const server = await createMcpServer(sessionClient);

    const keepaliveInterval = setInterval(() => {
      try {
        res.write(': keepalive\n\n');
      } catch (error) {
        console.error('❌ Keepalive failed:', error.message);
        clearInterval(keepaliveInterval);
      }
    }, SSE_KEEPALIVE_INTERVAL);

    transport.onclose = () => {
      if (sessions[transport.sessionId]) {
        clearInterval(keepaliveInterval);
        delete sessions[transport.sessionId];
        console.log(`🧹 Cleaned up session ${transport.sessionId}`);
      }
    };

    req.on('close', () => {
      clearInterval(keepaliveInterval);
      if (sessions[transport.sessionId]) {
        delete sessions[transport.sessionId];
        console.log(`🔌 Client disconnected: ${transport.sessionId}`);
      }
    });

    req.on('error', (error) => {
      console.error('❌ Request error:', error);
      clearInterval(keepaliveInterval);
    });

    sessions[transport.sessionId] = { server, transport, keepaliveInterval, client: sessionClient };
    console.log(`🔗 New session established: ${transport.sessionId}`);

    await server.connect(transport);

  } catch (error) {
    console.error('❌ Error establishing SSE connection:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to establish SSE connection' });
    }
  }
});

/**
 * POST /mcp - Handle JSON-RPC messages
 */
app.post('/mcp', async (req, res) => {
  try {
    const sessionId = req.query.sessionId;

    if (!sessionId || !sessions[sessionId]) {
      return res.status(400).json({ error: 'Invalid or missing session ID' });
    }

    const { transport } = sessions[sessionId];
    await transport.handlePostMessage(req, res, req.body);

  } catch (error) {
    console.error('❌ Error handling POST message:', error);
    res.status(500).json({ error: 'Failed to process message' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    servicenow_instance: defaultInstance.url,
    instance_name: defaultInstance.name,
    timestamp: new Date().toISOString()
  });
});

// List instances
app.get('/instances', (req, res) => {
  try {
    const instances = configManager.listInstances();
    res.json({ instances });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 ServiceNow MCP Server listening on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔌 MCP SSE endpoint: http://localhost:${PORT}/mcp`);
  console.log(`📋 Available instances: http://localhost:${PORT}/instances`);
  console.log(`🔐 OAuth callback: http://localhost:${PORT}/oauth/callback`);
  console.log(`💓 SSE keepalive interval: ${SSE_KEEPALIVE_INTERVAL}ms`);
});
