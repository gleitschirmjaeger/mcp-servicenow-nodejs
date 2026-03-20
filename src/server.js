/**
 * ServiceNow MCP Server - Express HTTP Server
 *
 * Copyright (c) 2025 Happy Technologies LLC
 * Licensed under the MIT License - see LICENSE file for details
 */

import express from 'express';
import dotenv from 'dotenv';
import axios from 'axios';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { ServiceNowClient } from './servicenow-client.js';
import { createMcpServer } from './mcp-server-consolidated.js';
import { configManager } from './config-manager.js';

// Load environment variables
dotenv.config();

// SSE configuration
const SSE_KEEPALIVE_INTERVAL = parseInt(process.env.SSE_KEEPALIVE_INTERVAL || '15000', 10);

const app = express();
app.use(express.json());

// In-memory session store (sessionId -> {server, transport, client, keepaliveInterval})
const sessions = {};

// In-memory OAuth pending store (state -> {code, created_at}), single-use
const pendingTokens = new Map();

// Get default instance configuration
const defaultInstance = configManager.getDefaultInstance();
console.log(`🔗 Default ServiceNow instance: ${defaultInstance.name} (${defaultInstance.url})`);
console.log(`💡 Use SN-Set-Instance tool to switch instances during session`);

/**
 * Create a fresh ServiceNowClient for a session.
 * If a Bearer token is provided it will be used instead of Basic Auth.
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

// ---------------------------------------------------------------------------
// OAuth routes
// ---------------------------------------------------------------------------

/**
 * GET /oauth/callback
 * ServiceNow redirects here after the user authorizes the OAuth app.
 * We store the authorization code keyed by state, then signal the opener
 * popup to close via postMessage. The token exchange happens separately
 * once the client POSTs the PKCE code_verifier.
 */
app.get('/oauth/callback', (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send('Missing code or state parameter');
  }

  // Store code — token exchange happens when client POSTs code_verifier
  pendingTokens.set(state, {
    code,
    created_at: Date.now()
  });

  // Auto-expire entries after 5 minutes to avoid memory leaks
  setTimeout(() => pendingTokens.delete(state), 5 * 60 * 1000);

  // Close the popup and notify the opener
  res.send(`
    <html><body><script>
      window.opener.postMessage(
        { type: 'SN_OAUTH_SUCCESS', state: '${state}' },
        '*'
      );
      window.close();
    </script></body></html>
  `);
});

/**
 * POST /oauth/token/:state
 * The browser POSTs the PKCE code_verifier here after the popup closes.
 * We complete the authorization code + PKCE token exchange with ServiceNow
 * and return the access token to the caller.
 * Single-use: the pending entry is deleted immediately after retrieval.
 */
app.post('/oauth/token/:state', async (req, res) => {
  const pending = pendingTokens.get(req.params.state);
  if (!pending) {
    return res.status(404).json({ error: 'Token not found or already consumed' });
  }

  // Single-use — delete immediately
  pendingTokens.delete(req.params.state);

  const { code_verifier } = req.body;
  if (!code_verifier) {
    return res.status(400).json({ error: 'Missing code_verifier' });
  }

  try {
    const response = await axios.post(
      `${defaultInstance.url}/oauth_token.do`,
      new URLSearchParams({
        grant_type:    'authorization_code',
        code:          pending.code,
        client_id:     process.env.SN_OAUTH_CLIENT_ID,
        client_secret: process.env.SN_OAUTH_CLIENT_SECRET,
        redirect_uri:  process.env.SN_OAUTH_REDIRECT_URI,
        code_verifier                          // PKCE verifier
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    res.json({
      access_token: response.data.access_token,
      expires_in:   response.data.expires_in
    });
  } catch (err) {
    console.error('❌ Token exchange error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Token exchange failed: ' + err.message });
  }
});

// ---------------------------------------------------------------------------
// MCP routes
// ---------------------------------------------------------------------------

/**
 * GET /mcp - Establish SSE connection.
 * If an Authorization: Bearer <token> header is present the session will
 * use that token for all ServiceNow API calls (acting as that user).
 * Otherwise falls back to the configured service-account Basic Auth.
 */
app.get('/mcp', async (req, res) => {
  try {
    // SSE headers — prevent buffering and timeouts
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

    // Each session gets its own client so tokens are fully isolated
    const sessionClient = createClient(bearerToken);

    if (bearerToken) {
      console.log(`🔐 New session using OAuth Bearer token`);
    } else {
      console.log(`🔑 New session using Basic Auth (service account)`);
    }

    const transport = new SSEServerTransport('/mcp', res);
    const server = await createMcpServer(sessionClient);

    // Keepalive heartbeat — prevents proxy/load-balancer timeouts
    const keepaliveInterval = setInterval(() => {
      try {
        res.write(': keepalive\n\n');
      } catch (error) {
        console.error('❌ Keepalive failed, clearing interval:', error.message);
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
 * POST /mcp - Handle JSON-RPC messages for an existing session.
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

// ---------------------------------------------------------------------------
// Utility routes
// ---------------------------------------------------------------------------

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    servicenow_instance: defaultInstance.url,
    instance_name: defaultInstance.name,
    active_sessions: Object.keys(sessions).length,
    timestamp: new Date().toISOString()
  });
});

app.get('/instances', (req, res) => {
  try {
    const instances = configManager.listInstances();
    res.json({ instances });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Gleitschirmjaeger ServiceNow MCP Server listening on port ${PORT}`);
  console.log(`📊 Health check:       http://localhost:${PORT}/health`);
  console.log(`🔌 MCP SSE endpoint:   http://localhost:${PORT}/mcp`);
  console.log(`📋 Instances:          http://localhost:${PORT}/instances`);
  console.log(`🔐 OAuth callback:     http://localhost:${PORT}/oauth/callback`);
  console.log(`💓 SSE keepalive:      ${SSE_KEEPALIVE_INTERVAL}ms`);

  if (process.env.DEBUG === 'true') {
    console.log('🐛 Debug mode enabled');
    console.log(`🔗 Active instance: ${defaultInstance.name} - ${defaultInstance.url}`);
  }
});
