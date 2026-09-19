const express = require('express');
const http = require('http');
const https = require('https');
const { WebSocketServer } = require('ws');
const path = require('path');
 
const app = express();
const server = http.createServer(app);
 
const SERVICES = {
  goCore: process.env.BROWSERLB_GO_URL || 'http://localhost:8080',
  pythonBackend: process.env.BROWSERLB_PY_URL || 'http://localhost:5000',
  javaSecurity: process.env.BROWSERLB_JAVA_URL || 'http://localhost:8082',
};
 
app.use(express.json());
app.use(express.static(path.join(__dirname)));
 

function fetchJSON(targetUrl) {
  return new Promise((resolve, reject) => {
    const client = targetUrl.startsWith('https') ? https : http;
    const req = client.get(targetUrl, { timeout: 8000 }, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('upstream timeout')));
    req.on('error', reject);
  });
}
 

async function validateWithJava(sessionId, targetUrl) {
  const qs = `session=${encodeURIComponent(sessionId)}&url=${encodeURIComponent(targetUrl)}`;
  try {
    const { body } = await fetchJSON(`${SERVICES.javaSecurity}/api/security/validate?${qs}`);
    return body;
  } catch (err) {
  
    return { allowed: false, reason: `security service unreachable: ${err.message}` };
  }
}
 

 
app.get('/api/search', async (req, res) => {
  const q = req.query.q;
  if (!q) return res.status(400).json({ error: 'missing q param' });
 
  try {
    const { body } = await fetchJSON(`${SERVICES.pythonBackend}/api/search?q=${encodeURIComponent(q)}`);
    res.json(body);
  } catch (err) {
    res.status(502).json({ error: `search backend unreachable: ${err.message}` });
  }
});
 
app.get('/api/navigate', async (req, res) => {
  const { url: targetUrl, session = 'anonymous' } = req.query;
  if (!targetUrl) return res.status(400).json({ error: 'missing url param' });
 
  
  const verdict = await validateWithJava(session, targetUrl);
  if (!verdict.allowed) {
    return res.status(403).json({ error: 'navigation blocked', reason: verdict.reason });
  }
 
  
  try {
    const { body } = await fetchJSON(`${SERVICES.goCore}/search?url=${encodeURIComponent(targetUrl)}`);
    res.json({ navigated: true, result: body });
  } catch (err) {
    res.status(502).json({ error: `go core unreachable: ${err.message}` });
  }
});
 
app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', service: 'browserlb-node' });
});

const wss = new WebSocketServer({ server, path: '/ws-relay' });
 
wss.on('connection', (clientSocket) => {
  clientSocket.on('message', async (raw) => {
    let payload;
    try {
      payload = JSON.parse(raw.toString());
    } catch {
      clientSocket.send(JSON.stringify({ error: 'invalid JSON payload' }));
      return;
    }
    // In a full build this would proxy to the Go core's /ws endpoint;
    // here we relay through the REST search API for simplicity.
    try {
      const { body } = await fetchJSON(`${SERVICES.pythonBackend}/api/search?q=${encodeURIComponent(payload.query || '')}`);
      clientSocket.send(JSON.stringify(body));
    } catch (err) {
      clientSocket.send(JSON.stringify({ error: err.message }));
    }
  });
});
 
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`BrowserLB Node frontend listening on :${PORT}`);
  console.log('Upstream services:', SERVICES);
});
 
module.exports = { app, server, fetchJSON, validateWithJava };
 
