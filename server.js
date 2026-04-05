import { createClient } from '@libsql/client';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { google } from 'googleapis';
import { createHmac } from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Passcode auth ─────────────────────────────────────────────────────────────

const PASSCODE   = process.env.PLATFORM_PASSCODE || '0000';
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'novacor-platform-secret';
const COOKIE_NAME   = 'platform_auth';
const COOKIE_TTL    = 60 * 60 * 24; // 24 hours in seconds

function makeToken() {
  return createHmac('sha256', COOKIE_SECRET).update(PASSCODE).digest('hex');
}

function getCookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k.trim() === name) return v.join('=');
  }
  return null;
}

function isAuthenticated(req) {
  return getCookie(req, COOKIE_NAME) === makeToken();
}

function requireAuth(req, res, next) {
  if (isAuthenticated(req)) return next();
  // API routes → 401 JSON; page requests → redirect to /auth
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.redirect('/auth');
}

const PASSCODE_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Novacor Platform — Login</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #060d1a;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      color: #c8d6e5;
    }
    .gate {
      width: 100%;
      max-width: 360px;
      padding: 48px 36px 40px;
      background: #0a1628;
      border: 1px solid rgba(212,175,55,0.18);
      border-radius: 12px;
      text-align: center;
      box-shadow: 0 8px 40px rgba(0,0,0,0.6);
    }
    .logo {
      font-size: 1.6rem;
      font-weight: 700;
      letter-spacing: .04em;
      color: #d4af37;
      margin-bottom: 6px;
    }
    .logo span { color: #c8d6e5; font-weight: 300; }
    .subtitle {
      font-size: 0.8rem;
      color: #4a6080;
      letter-spacing: .08em;
      text-transform: uppercase;
      margin-bottom: 36px;
    }
    input[type=password], input[type=text] {
      width: 100%;
      padding: 12px 16px;
      background: #060d1a;
      border: 1px solid rgba(212,175,55,0.25);
      border-radius: 6px;
      color: #c8d6e5;
      font-size: 1.1rem;
      letter-spacing: .2em;
      text-align: center;
      outline: none;
      margin-bottom: 14px;
      transition: border-color .2s;
    }
    input:focus { border-color: #d4af37; }
    button {
      width: 100%;
      padding: 12px;
      background: #d4af37;
      border: none;
      border-radius: 6px;
      color: #060d1a;
      font-size: 0.95rem;
      font-weight: 700;
      letter-spacing: .04em;
      cursor: pointer;
      transition: opacity .2s;
    }
    button:hover { opacity: .88; }
    .error {
      margin-top: 14px;
      font-size: 0.82rem;
      color: #e74c3c;
      min-height: 1.2em;
    }
  </style>
</head>
<body>
  <div class="gate">
    <div class="logo">NOVA<span>COR</span></div>
    <div class="subtitle">Platform Access</div>
    <form method="POST" action="/auth/passcode">
      <input type="password" name="passcode" placeholder="Enter PIN" autofocus autocomplete="off" maxlength="32">
      <button type="submit">Enter</button>
    </form>
    <div class="error">{{ERROR}}</div>
  </div>
</body>
</html>`;

// ── Auth routes (public — no requireAuth) ─────────────────────────────────────

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: false, limit: '50mb' }));

app.get('/auth', (req, res) => {
  if (isAuthenticated(req)) return res.redirect('/');
  res.send(PASSCODE_PAGE.replace('{{ERROR}}', ''));
});

app.post('/auth/passcode', (req, res) => {
  const submitted = (req.body.passcode || '').trim();
  if (submitted === PASSCODE) {
    const token = makeToken();
    res.setHeader('Set-Cookie',
      `${COOKIE_NAME}=${token}; HttpOnly; Path=/; Max-Age=${COOKIE_TTL}; SameSite=Strict`);
    return res.redirect('/');
  }
  res.send(PASSCODE_PAGE.replace('{{ERROR}}', 'Incorrect passcode. Try again.'));
});

app.get('/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0`);
  res.redirect('/auth');
});

// ── CRM lead import — server-to-server, authenticated via X-Platform-Secret ───
// Placed before requireAuth so it doesn't need a browser cookie.
// CORS headers allow the Conversion-Lab origin for both preflight and POST.
const CRM_ALLOWED_ORIGIN = 'https://novacor-conversion-lab.onrender.com';

function setCrmCors(res) {
  res.setHeader('Access-Control-Allow-Origin', CRM_ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Platform-Secret');
}

app.options('/api/crm/contacts', (req, res) => {
  setCrmCors(res);
  res.sendStatus(204);
});

app.post('/api/crm/contacts', async (req, res) => {
  setCrmCors(res);

  const secret = process.env.PLATFORM_API_SECRET;
  if (!secret) {
    console.error('[CRM] PLATFORM_API_SECRET not set — rejecting request');
    return res.status(500).json({ error: 'Server misconfigured: PLATFORM_API_SECRET not set' });
  }
  if (req.headers['x-platform-secret'] !== secret) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { name, phone, email, address, type, source, ai_score, motivation_tags, equity, value, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  // Load existing contacts from KV store (client uses 'nc_' prefix)
  let contacts = [];
  try {
    const r = await db.execute({ sql: 'SELECT value FROM kv WHERE key=?', args: ['nc_crm_contacts'] });
    if (r.rows.length) contacts = JSON.parse(r.rows[0].value);
  } catch {}

  const contact = {
    id: `clab_${Date.now()}`,
    name,
    type:   type   || 'Lead',
    source: source || 'conversion_lab',
    phone:  phone  || '',
    email:  email  || '',
    address: address || '',
    status: 'Active',
    ai_score:        ai_score        ?? null,
    motivation_tags: motivation_tags ?? '[]',
    equity:          equity          ?? null,
    value:           value           ?? null,
    notes:           notes           || '',
    added: new Date().toISOString().slice(0, 10),
  };

  contacts.push(contact);

  await db.execute({
    sql: 'INSERT INTO kv (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
    args: ['nc_crm_contacts', JSON.stringify(contacts)],
  });

  res.json({ ok: true, id: contact.id });
});

// GET /auth/google/revoke — clear stored token and force re-authorization
app.get('/auth/google/revoke', async (req, res) => {
  await db.execute({ sql: 'DELETE FROM kv WHERE key=?', args: ['google_tokens'] });
  res.redirect('/auth/google');
});

// GET /auth/google — redirect to consent screen
app.get('/auth/google', (req, res) => {
  const auth = makeOAuth2Client(req);
  const url = auth.generateAuthUrl({
    access_type: 'offline',
    scope: GOOGLE_SCOPES,
    prompt: 'consent',
  });
  res.redirect(url);
});

// GET /auth/google/callback — exchange code for tokens
app.get('/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/?google_error=1');
  try {
    const auth = makeOAuth2Client(req);
    const { tokens } = await auth.getToken(code);
    await saveTokens(tokens);
    res.redirect('/?google_authed=1');
  } catch (e) {
    console.error('[Google OAuth] Callback error:', e.message);
    res.redirect('/?google_error=1');
  }
});

// ── All routes below require auth ─────────────────────────────────────────────
app.use(requireAuth);
app.use(express.static(__dirname));

const db = createClient({
  url: process.env.TURSO_URL,
  authToken: process.env.TURSO_TOKEN,
});

await db.execute(`CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value TEXT
)`);

app.get('/api/store', async (req, res) => {
  const result = await db.execute('SELECT key, value FROM kv');
  const out = {};
  for (const row of result.rows) out[row.key] = row.value;
  res.json(out);
});

app.get('/api/store/:key', async (req, res) => {
  const result = await db.execute({
    sql: 'SELECT value FROM kv WHERE key = ?',
    args: [req.params.key]
  });
  if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ value: result.rows[0].value });
});

app.put('/api/store/:key', async (req, res) => {
  await db.execute({
    sql: 'INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
    args: [req.params.key, JSON.stringify(req.body.value)]
  });
  res.json({ ok: true });
});

app.delete('/api/store/:key', async (req, res) => {
  await db.execute({
    sql: 'DELETE FROM kv WHERE key = ?',
    args: [req.params.key]
  });
  res.json({ ok: true });
});

// ── Google OAuth ──────────────────────────────────────────────────────────────

const GOOGLE_SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/calendar',
];

function makeOAuth2Client(req) {
  const base = process.env.BASE_URL ||
    `${req.protocol}://${req.get('host')}`;
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    `${base}/auth/google/callback`
  );
}

async function getStoredTokens() {
  const r = await db.execute({ sql: 'SELECT value FROM kv WHERE key=?', args: ['google_tokens'] });
  return r.rows.length ? JSON.parse(r.rows[0].value) : null;
}

async function saveTokens(tokens) {
  await db.execute({
    sql: 'INSERT INTO kv (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
    args: ['google_tokens', JSON.stringify(tokens)],
  });
}

async function getAuthedClient(req) {
  const tokens = await getStoredTokens();
  if (!tokens) return null;
  const auth = makeOAuth2Client(req);
  auth.setCredentials(tokens);

  // Persist any refreshed tokens automatically
  auth.on('tokens', async (refreshed) => {
    const merged = { ...tokens, ...refreshed };
    await saveTokens(merged);
    auth.setCredentials(merged);
  });

  // Proactively refresh if access token is expired or about to expire (within 5 min)
  const expiryDate = tokens.expiry_date;
  const isExpired = expiryDate ? Date.now() >= expiryDate - 5 * 60 * 1000 : false;

  if (isExpired && tokens.refresh_token) {
    try {
      console.log('[Google OAuth] Access token expired — refreshing proactively...');
      const { credentials } = await auth.refreshAccessToken();
      const merged = { ...tokens, ...credentials };
      await saveTokens(merged);
      auth.setCredentials(merged);
      console.log('[Google OAuth] Token refreshed successfully. New expiry:', new Date(merged.expiry_date).toISOString());
    } catch (e) {
      console.error('[Google OAuth] Proactive refresh failed:', e.message);
      // Return null so the caller gets a clean not_authenticated error instead of hanging
      return null;
    }
  }

  return auth;
}

// GET /api/google/gmail — last 25 inbox messages (fresh, no cache, excludes trash/spam)
app.get('/api/google/gmail', async (req, res) => {
  try {
    const auth = await getAuthedClient(req);
    if (!auth) return res.status(401).json({ error: 'not_authenticated' });

    const gmail = google.gmail({ version: 'v1', auth });
    const list = await gmail.users.messages.list({
      userId: 'me',
      labelIds: ['INBOX'],
      q: 'in:inbox category:primary -in:trash -in:spam',
      includeSpamTrash: false,
      maxResults: 25,
    });
    const msgs = list.data.messages || [];

    const details = await Promise.all(msgs.map(async (m) => {
      const msg = await gmail.users.messages.get({
        userId: 'me', id: m.id,
        format: 'metadata',
        metadataHeaders: ['From', 'Subject', 'Date'],
      });
      const h = (name) => (msg.data.payload?.headers || []).find(x => x.name === name)?.value || '';
      return { id: m.id, from: h('From'), subject: h('Subject'), date: h('Date'), snippet: msg.data.snippet || '' };
    }));

    res.json(details);
  } catch (e) {
    console.error('[Gmail API]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/google/calendar — next 10 events
app.get('/api/google/calendar', async (req, res) => {
  try {
    const auth = await getAuthedClient(req);
    if (!auth) return res.status(401).json({ error: 'not_authenticated' });

    const cal = google.calendar({ version: 'v3', auth });
    const r = await cal.events.list({
      calendarId: 'primary',
      timeMin: new Date().toISOString(),
      maxResults: 10,
      singleEvents: true,
      orderBy: 'startTime',
    });

    const events = (r.data.items || []).map(e => ({
      id: e.id,
      title: e.summary || '(No title)',
      start: e.start?.dateTime || e.start?.date,
      end: e.end?.dateTime || e.end?.date,
      location: e.location || null,
      allDay: !e.start?.dateTime,
    }));

    res.json(events);
  } catch (e) {
    console.error('[Calendar API]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/google/gmail/send — compose and send a message
app.post('/api/google/gmail/send', async (req, res) => {
  try {
    const auth = await getAuthedClient(req);
    if (!auth) return res.status(401).json({ error: 'not_authenticated' });

    const { to, subject, body } = req.body;
    if (!to || !subject) return res.status(400).json({ error: 'to and subject required' });

    const raw = [
      `To: ${to}`,
      `Subject: ${subject}`,
      'Content-Type: text/plain; charset=utf-8',
      'MIME-Version: 1.0',
      '',
      body || '',
    ].join('\r\n');

    const encoded = Buffer.from(raw).toString('base64url');
    const gmail = google.gmail({ version: 'v1', auth });
    await gmail.users.messages.send({ userId: 'me', requestBody: { raw: encoded } });
    res.json({ ok: true });
  } catch (e) {
    console.error('[Gmail Send]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/google/gmail/:messageId — full message with body
app.get('/api/google/gmail/:messageId', async (req, res) => {
  try {
    const auth = await getAuthedClient(req);
    if (!auth) return res.status(401).json({ error: 'not_authenticated' });
    const gmail = google.gmail({ version: 'v1', auth });
    const msg = await gmail.users.messages.get({ userId: 'me', id: req.params.messageId, format: 'full' });
    const h = (name) => (msg.data.payload?.headers || []).find(x => x.name === name)?.value || '';

    // Recursively extract text/plain body; fall back to text/html with tags stripped
    function extractBody(payload) {
      if (payload.body?.data) {
        return Buffer.from(payload.body.data, 'base64url').toString('utf-8');
      }
      if (payload.parts) {
        for (const part of payload.parts) {
          if (part.mimeType === 'text/plain' && part.body?.data)
            return Buffer.from(part.body.data, 'base64url').toString('utf-8');
        }
        for (const part of payload.parts) {
          if (part.mimeType === 'text/html' && part.body?.data) {
            return Buffer.from(part.body.data, 'base64url').toString('utf-8')
              .replace(/<br\s*\/?>/gi, '\n').replace(/<\/p>/gi, '\n\n')
              .replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ')
              .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').trim();
          }
        }
        for (const part of payload.parts) {
          if (part.parts) { const b = extractBody(part); if (b) return b; }
        }
      }
      return '';
    }

    res.json({
      id: msg.data.id,
      from: h('From'),
      to: h('To'),
      subject: h('Subject'),
      date: h('Date'),
      body: extractBody(msg.data.payload),
    });
  } catch (e) {
    console.error('[Gmail Get]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/google/gmail/:messageId — move to trash
app.delete('/api/google/gmail/:messageId', async (req, res) => {
  try {
    const auth = await getAuthedClient(req);
    if (!auth) return res.status(401).json({ error: 'not_authenticated' });
    const gmail = google.gmail({ version: 'v1', auth });
    await gmail.users.messages.trash({ userId: 'me', id: req.params.messageId });
    res.json({ ok: true });
  } catch (e) {
    console.error('[Gmail Trash]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/google/calendar/:eventId — single event detail
app.get('/api/google/calendar/:eventId', async (req, res) => {
  try {
    const auth = await getAuthedClient(req);
    if (!auth) return res.status(401).json({ error: 'not_authenticated' });
    const cal = google.calendar({ version: 'v3', auth });
    const r = await cal.events.get({ calendarId: 'primary', eventId: req.params.eventId });
    const e = r.data;
    res.json({
      id: e.id,
      title: e.summary || '(No title)',
      start: e.start?.dateTime || e.start?.date,
      end: e.end?.dateTime || e.end?.date,
      location: e.location || null,
      description: e.description || null,
      allDay: !e.start?.dateTime,
    });
  } catch (e) {
    console.error('[Calendar Get Event]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/google/calendar — create new event
app.post('/api/google/calendar', async (req, res) => {
  try {
    const auth = await getAuthedClient(req);
    if (!auth) return res.status(401).json({ error: 'not_authenticated' });

    const { title, start, end, location, description } = req.body;
    if (!title || !start || !end) return res.status(400).json({ error: 'title, start, end required' });

    const cal = google.calendar({ version: 'v3', auth });
    const timeZone = 'America/Phoenix';
    const r = await cal.events.insert({
      calendarId: 'primary',
      requestBody: {
        summary: title,
        start: { dateTime: start, timeZone },
        end: { dateTime: end, timeZone },
        ...(location ? { location } : {}),
        ...(description ? { description } : {}),
      },
    });
    res.json({ ok: true, id: r.data.id });
  } catch (e) {
    console.error('[Calendar Create]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Tasks API ────────────────────────────────────────────────────────────────

await db.execute(`CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  due_date TEXT NOT NULL,
  due_time TEXT DEFAULT NULL,
  status TEXT DEFAULT 'pending',
  calendar_event_id TEXT DEFAULT NULL,
  created_at TEXT DEFAULT (datetime('now'))
)`);

app.get('/api/tasks', async (req, res) => {
  try {
    const { date, week_start, week_end } = req.query;
    let sql, args;
    if (date) {
      sql = "SELECT * FROM tasks WHERE due_date=? AND status!='deleted' ORDER BY due_time ASC";
      args = [date];
    } else if (week_start && week_end) {
      sql = "SELECT * FROM tasks WHERE due_date>=? AND due_date<=? AND status!='deleted' ORDER BY due_date ASC, due_time ASC";
      args = [week_start, week_end];
    } else {
      sql = "SELECT * FROM tasks WHERE status!='deleted' ORDER BY due_date ASC, due_time ASC";
      args = [];
    }
    const r = await db.execute({ sql, args });
    res.json(r.rows);
  } catch (e) { console.error('[Tasks GET]', e.message); res.status(500).json({ error: e.message }); }
});

app.post('/api/tasks', async (req, res) => {
  try {
    const { title, description, due_date, due_time } = req.body;
    if (!title || !due_date) return res.status(400).json({ error: 'title and due_date required' });
    const id = `task_${Date.now()}_${Math.random().toString(36).slice(2,7)}`;
    await db.execute({ sql: 'INSERT INTO tasks (id,title,description,due_date,due_time) VALUES (?,?,?,?,?)', args: [id, title, description||'', due_date, due_time||null] });
    const r = await db.execute({ sql: 'SELECT * FROM tasks WHERE id=?', args: [id] });
    res.json(r.rows[0]);
  } catch (e) { console.error('[Tasks POST]', e.message); res.status(500).json({ error: e.message }); }
});

app.patch('/api/tasks/:id', async (req, res) => {
  try {
    const allowed = ['status','due_date','due_time','title','description','calendar_event_id'];
    const fields = [], args = [];
    for (const k of allowed) { if (req.body[k] !== undefined) { fields.push(`${k}=?`); args.push(req.body[k]); } }
    if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
    args.push(req.params.id);
    await db.execute({ sql: `UPDATE tasks SET ${fields.join(',')} WHERE id=?`, args });
    const r = await db.execute({ sql: 'SELECT * FROM tasks WHERE id=?', args: [req.params.id] });
    res.json(r.rows[0]);
  } catch (e) { console.error('[Tasks PATCH]', e.message); res.status(500).json({ error: e.message }); }
});

app.delete('/api/tasks/:id', async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM tasks WHERE id=?', args: [req.params.id] });
    res.json({ ok: true });
  } catch (e) { console.error('[Tasks DELETE]', e.message); res.status(500).json({ error: e.message }); }
});

// ── Novabooks: Bank Email Parser + Cron ──────────────────────────────────────

// Sync log table
await db.execute(`CREATE TABLE IF NOT EXISTS nb_sync_log (
  id TEXT PRIMARY KEY,
  synced_at TEXT DEFAULT (datetime('now')),
  source TEXT NOT NULL,
  imported INTEGER DEFAULT 0,
  skipped INTEGER DEFAULT 0,
  errors TEXT DEFAULT '',
  summary TEXT DEFAULT ''
)`);

// ── Email parsers ────────────────────────────────────────────────────────────

function parsePncAlert(subject, body, from) {
  // PNC sends from pncalerts@pnc.com
  // Subject patterns: "PNC Alert: Withdrawal", "PNC Alert: Deposit", "PNC Alert: Purchase"
  // Body contains: amount, merchant/description, account ending, date
  if (!from.toLowerCase().includes('pncalerts@pnc.com')) return null;
  const result = { source: 'PNC', raw_subject: subject, raw_body: body };

  // Extract amount — PNC format: "$1,234.56" or "$ 1,234.56"
  const amountMatch = body.match(/\$\s?([\d,]+\.?\d*)/);
  if (!amountMatch) return null;
  result.amount = parseFloat(amountMatch[1].replace(/,/g, ''));

  // Determine type from subject/body
  const lc = (subject + ' ' + body).toLowerCase();
  if (lc.includes('deposit') || lc.includes('credit') || lc.includes('transfer in')) {
    result.type = 'income';
    result.category = 'Other Income';
  } else {
    result.type = 'expense';
    result.category = 'Miscellaneous';
  }

  // Extract merchant/description
  const merchantMatch = body.match(/(?:at|from|to|merchant|description)[:\s]+([^\n\r$]{3,50})/i);
  result.vendor = merchantMatch ? merchantMatch[1].trim() : 'PNC Transaction';

  // Extract date — PNC format: "04/07/2026" or "April 7, 2026"
  const dateMatch = body.match(/(\d{2}\/\d{2}\/\d{4})|(\w+ \d{1,2},? \d{4})/);
  result.date = dateMatch ? new Date(dateMatch[0]).toISOString().slice(0, 10) : new Date().toISOString().slice(0, 10);

  // Extract account — "account ending in 1234"
  const acctMatch = body.match(/ending\s+(?:in\s+)?(\d{4})/i);
  result.account_last4 = acctMatch ? acctMatch[1] : null;

  return result;
}

function parseAmexAlert(subject, body, from) {
  // Amex sends from AmericanExpress@welcome.americanexpress.com or americanexpress.com domains
  // Subject: "A charge has been made", "Your American Express Card Activity"
  if (!from.toLowerCase().includes('americanexpress.com')) return null;
  if (subject.toLowerCase().includes('verification') || subject.toLowerCase().includes('code') || subject.toLowerCase().includes('statement')) return null;

  const result = { source: 'Amex', raw_subject: subject, raw_body: body };

  // Extract amount — Amex format: "$1,234.56"
  const amountMatch = body.match(/\$\s?([\d,]+\.?\d*)/);
  if (!amountMatch) return null;
  result.amount = parseFloat(amountMatch[1].replace(/,/g, ''));

  // Amex charges are always expenses
  const lc = (subject + ' ' + body).toLowerCase();
  if (lc.includes('payment') || lc.includes('credit') || lc.includes('refund')) {
    result.type = 'income';
    result.category = 'Other Income';
  } else {
    result.type = 'expense';
    result.category = 'Miscellaneous';
  }

  // Extract merchant
  const merchantPatterns = [
    /(?:at|from|merchant|where)[:\s]+([^\n\r$]{3,50})/i,
    /Card Member:\s*[^\n]+\n+([^\n$]{3,50})/i,
  ];
  let vendor = 'Amex Transaction';
  for (const p of merchantPatterns) {
    const m = body.match(p);
    if (m) { vendor = m[1].trim(); break; }
  }
  result.vendor = vendor;

  // Extract date
  const dateMatch = body.match(/(\d{2}\/\d{2}\/\d{4})|(\w+ \d{1,2},? \d{4})/);
  result.date = dateMatch ? new Date(dateMatch[0]).toISOString().slice(0, 10) : new Date().toISOString().slice(0, 10);

  // Amex last 4 from subject/body
  const acctMatch = body.match(/(?:ending|card)\s+(?:in\s+)?(\d{5}|\d{4})/i);
  result.account_last4 = acctMatch ? acctMatch[1].slice(-4) : null;

  return result;
}

function parseWellsFargoAlert(subject, body, from) {
  // Wells Fargo sends from various @wellsfargo.com addresses
  if (!from.toLowerCase().includes('wellsfargo.com')) return null;
  if (subject.toLowerCase().includes('security') || subject.toLowerCase().includes('code')) return null;

  const result = { source: 'WellsFargo', raw_subject: subject, raw_body: body };

  const amountMatch = body.match(/\$\s?([\d,]+\.?\d*)/);
  if (!amountMatch) return null;
  result.amount = parseFloat(amountMatch[1].replace(/,/g, ''));

  const lc = (subject + ' ' + body).toLowerCase();
  result.type = (lc.includes('deposit') || lc.includes('credit') || lc.includes('transfer in')) ? 'income' : 'expense';
  result.category = result.type === 'income' ? 'Other Income' : 'Miscellaneous';

  const merchantMatch = body.match(/(?:at|from|to|merchant)[:\s]+([^\n\r$]{3,50})/i);
  result.vendor = merchantMatch ? merchantMatch[1].trim() : 'Wells Fargo Transaction';

  const dateMatch = body.match(/(\d{2}\/\d{2}\/\d{4})|(\w+ \d{1,2},? \d{4})/);
  result.date = dateMatch ? new Date(dateMatch[0]).toISOString().slice(0, 10) : new Date().toISOString().slice(0, 10);

  const acctMatch = body.match(/ending\s+(?:in\s+)?(\d{4})/i);
  result.account_last4 = acctMatch ? acctMatch[1] : null;

  return result;
}

// ── Core sync function ───────────────────────────────────────────────────────

async function runNovabooksSync(req) {
  console.log('[NovaBooks Sync] Starting bank email sync...');

  // ── Auto-backup all critical data before sync ────────────────────────────
  try {
    const backupTimestamp = new Date().toISOString().slice(0, 10);
    const criticalKeys = ['nc_active_deals', 'nc_crm_contacts', 'nc_contractors', 'nc_info_docs'];
    for (const key of criticalKeys) {
      try {
        const r = await db.execute({ sql: 'SELECT value FROM kv WHERE key=?', args: [key] });
        if (r.rows.length && r.rows[0].value) {
          const backupKey = `backup_${key}_${backupTimestamp}`;
          await db.execute({
            sql: 'INSERT INTO kv (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
            args: [backupKey, r.rows[0].value]
          });
          console.log(`[Backup] Saved ${key} → ${backupKey} (${r.rows[0].value.length} chars)`);
        }
      } catch (e) {
        console.error(`[Backup] Failed to backup ${key}:`, e.message);
      }
    }
    // Clean up backups older than 4 weeks (keep only last 4)
    for (const key of criticalKeys) {
      const allBackups = await db.execute({
        sql: "SELECT key FROM kv WHERE key LIKE ? ORDER BY key DESC",
        args: [`backup_${key}_%`]
      });
      const toDelete = allBackups.rows.slice(4); // keep newest 4
      for (const row of toDelete) {
        await db.execute({ sql: 'DELETE FROM kv WHERE key=?', args: [row.key] });
        console.log(`[Backup] Cleaned old backup: ${row.key}`);
      }
    }
    console.log('[Backup] Weekly backup complete');
  } catch (e) {
    console.error('[Backup] Backup process failed:', e.message);
  }
  // ────────────────────────────────────────────────────────────────────────

  const auth = await getAuthedClient(req || { protocol: 'https', get: () => 'novacor-platform.onrender.com' });
  if (!auth) { console.error('[NovaBooks Sync] No Google auth — skipping'); return { imported: 0, skipped: 0, error: 'No Google auth' }; }

  const gmail = google.gmail({ version: 'v1', auth });

  // Search last 8 days of emails from bank senders
  const query = 'from:(pncalerts@pnc.com OR americanexpress.com OR wellsfargo.com) newer_than:8d';
  const list = await gmail.users.messages.list({ userId: 'me', q: query, maxResults: 50 });
  const messages = list.data.messages || [];
  console.log(`[NovaBooks Sync] Found ${messages.length} bank emails to process`);

  // Load accounts for matching
  const accts = await db.execute('SELECT * FROM nb_accounts');
  const accounts = accts.rows;

  let imported = 0, skipped = 0, errors = [];

  for (const msg of messages) {
    try {
      // Check if already processed
      const existing = await db.execute({ sql: "SELECT value FROM kv WHERE key=?", args: [`nb_sync_gmail_${msg.id}`] });
      if (existing.rows.length) { skipped++; continue; }

      const full = await gmail.users.messages.get({ userId: 'me', id: msg.id, format: 'full' });
      const headers = full.data.payload?.headers || [];
      const subject = headers.find(h => h.name === 'Subject')?.value || '';
      const from = headers.find(h => h.name === 'From')?.value || '';

      // Extract body
      function extractBody(payload) {
        if (payload.body?.data) return Buffer.from(payload.body.data, 'base64url').toString('utf-8');
        if (payload.parts) {
          for (const part of payload.parts) {
            if (part.mimeType === 'text/plain' && part.body?.data) return Buffer.from(part.body.data, 'base64url').toString('utf-8');
          }
          for (const part of payload.parts) {
            if (part.body?.data) return Buffer.from(part.body.data, 'base64url').toString('utf-8');
          }
        }
        return '';
      }
      const body = extractBody(full.data.payload);

      // Try each parser
      const parsed = parsePncAlert(subject, body, from) || parseAmexAlert(subject, body, from) || parseWellsFargoAlert(subject, body, from);
      if (!parsed || !parsed.amount || parsed.amount <= 0) { skipped++; continue; }

      // Match to account by last4 or source name
      let account_id = null;
      if (parsed.account_last4) {
        const match = accounts.find(a => a.last4 === parsed.account_last4);
        if (match) account_id = match.id;
      }
      if (!account_id) {
        const sourceMap = { PNC: ['pnc','checking'], Amex: ['amex','amazon','credit'], WellsFargo: ['wells','fargo'] };
        const keywords = sourceMap[parsed.source] || [];
        const match = accounts.find(a => keywords.some(k => a.name.toLowerCase().includes(k) || a.institution.toLowerCase().includes(k)));
        if (match) account_id = match.id;
      }
      if (!account_id && accounts.length > 0) account_id = accounts[0].id;
      if (!account_id) { skipped++; continue; }

      // Insert transaction
      const txn_id = `txn_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
      await db.execute({
        sql: 'INSERT INTO nb_transactions (id,date,account_id,vendor,category,amount,type,description,tax_deductible) VALUES (?,?,?,?,?,?,?,?,?)',
        args: [txn_id, parsed.date, account_id, parsed.vendor, parsed.category, parsed.amount, parsed.type, `[${parsed.source} Auto-Import]`, 1]
      });

      // Mark as processed
      await db.execute({ sql: 'INSERT INTO kv (key,value) VALUES (?,?) ON CONFLICT(key) DO NOTHING', args: [`nb_sync_gmail_${msg.id}`, '1'] });
      imported++;
    } catch (e) {
      console.error('[NovaBooks Sync] Error processing email:', e.message);
      errors.push(e.message);
      skipped++;
    }
  }

  // Log the sync
  const syncId = `sync_${Date.now()}`;
  const summary = `Imported ${imported} transactions, skipped ${skipped}`;
  await db.execute({
    sql: 'INSERT INTO nb_sync_log (id,source,imported,skipped,errors,summary) VALUES (?,?,?,?,?,?)',
    args: [syncId, 'gmail_auto', imported, skipped, errors.join('; '), summary]
  });

  console.log(`[NovaBooks Sync] Complete — ${summary}`);
  return { imported, skipped, errors, summary };
}

// ── Weekly summary email ─────────────────────────────────────────────────────

async function sendNovaBooksSummaryEmail(req) {
  try {
    const auth = await getAuthedClient(req || { protocol: 'https', get: () => 'novacor-platform.onrender.com' });
    if (!auth) return;
    const year = new Date().getFullYear().toString();
    const weekOf = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });

    // Get summary data
    const sumR = await db.execute({ sql: "SELECT type, category, amount FROM nb_transactions WHERE strftime('%Y',date)=?", args: [year] });
    let totalIncome = 0, totalExpenses = 0;
    for (const t of sumR.rows) { if (t.type === 'income') totalIncome += t.amount; else totalExpenses += t.amount; }
    const netProfit = totalIncome - totalExpenses;
    const estTax = netProfit > 0 ? netProfit * 0.9235 * 0.153 + netProfit * 0.22 : 0;

    const milR = await db.execute({ sql: "SELECT SUM(miles) as m, SUM(miles*rate) as d FROM nb_mileage WHERE strftime('%Y',date)=?", args: [year] });
    const taxPaidR = await db.execute({ sql: 'SELECT SUM(amount) as p FROM nb_tax_payments WHERE year=?', args: [year] });

    // Get this week's imports
    const weekAgo = new Date(); weekAgo.setDate(weekAgo.getDate() - 7);
    const recentR = await db.execute({ sql: "SELECT * FROM nb_transactions WHERE description LIKE '%Auto-Import%' AND created_at >= ? ORDER BY date DESC", args: [weekAgo.toISOString()] });

    const fmt = n => '$' + Number(n || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

    const recentRows = recentR.rows.map(t => `
      <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #e8e8e8;font-size:13px;">${t.date}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #e8e8e8;font-size:13px;">${t.vendor || '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #e8e8e8;font-size:13px;">${t.category}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #e8e8e8;font-size:13px;text-align:right;color:${t.type === 'income' ? '#27ae60' : '#e74c3c'};font-weight:600;">${t.type === 'income' ? '+' : '−'}${fmt(t.amount)}</td>
      </tr>`).join('');

    const html = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <div style="max-width:600px;margin:32px auto;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);">
    <div style="background:#060d1a;padding:28px 32px;text-align:center;">
      <div style="font-size:11px;letter-spacing:0.15em;text-transform:uppercase;color:#d4af37;margin-bottom:6px;">Novacor LLC</div>
      <div style="font-size:22px;font-weight:700;color:#ffffff;">NovaBooks Weekly Report</div>
      <div style="font-size:13px;color:#8899aa;margin-top:6px;">Week of ${weekOf}</div>
    </div>
    <div style="padding:24px 32px;background:#f8f9fa;border-bottom:1px solid #e8e8e8;">
      <div style="font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:#8899aa;margin-bottom:16px;">Year-to-Date Snapshot — ${year}</div>
      <div style="display:flex;gap:0;flex-wrap:wrap;">
        <div style="flex:1;min-width:120px;padding:12px 16px;background:#fff;border-radius:6px;margin:4px;border:1px solid #e8e8e8;">
          <div style="font-size:11px;color:#8899aa;margin-bottom:4px;">Total Income</div>
          <div style="font-size:18px;font-weight:700;color:#27ae60;">${fmt(totalIncome)}</div>
        </div>
        <div style="flex:1;min-width:120px;padding:12px 16px;background:#fff;border-radius:6px;margin:4px;border:1px solid #e8e8e8;">
          <div style="font-size:11px;color:#8899aa;margin-bottom:4px;">Total Expenses</div>
          <div style="font-size:18px;font-weight:700;color:#e74c3c;">${fmt(totalExpenses)}</div>
        </div>
        <div style="flex:1;min-width:120px;padding:12px 16px;background:#fff;border-radius:6px;margin:4px;border:1px solid #e8e8e8;">
          <div style="font-size:11px;color:#8899aa;margin-bottom:4px;">Net Profit</div>
          <div style="font-size:18px;font-weight:700;color:${netProfit >= 0 ? '#27ae60' : '#e74c3c'};">${fmt(netProfit)}</div>
        </div>
        <div style="flex:1;min-width:120px;padding:12px 16px;background:#fff;border-radius:6px;margin:4px;border:1px solid #e8e8e8;">
          <div style="font-size:11px;color:#8899aa;margin-bottom:4px;">Est. Tax Owed</div>
          <div style="font-size:18px;font-weight:700;color:#d4af37;">${fmt(estTax)}</div>
        </div>
      </div>
    </div>
    <div style="padding:16px 32px;background:#f8f9fa;border-bottom:1px solid #e8e8e8;display:flex;gap:24px;flex-wrap:wrap;">
      <div><span style="font-size:12px;color:#8899aa;">Mileage Deduction: </span><span style="font-size:13px;font-weight:600;color:#3498db;">${fmt(milR.rows[0]?.d || 0)}</span> <span style="font-size:11px;color:#aaa;">(${(milR.rows[0]?.m || 0).toFixed(1)} mi)</span></div>
      <div><span style="font-size:12px;color:#8899aa;">Tax Paid YTD: </span><span style="font-size:13px;font-weight:600;color:#27ae60;">${fmt(taxPaidR.rows[0]?.p || 0)}</span></div>
    </div>
    <div style="padding:24px 32px;">
      <div style="font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:#8899aa;margin-bottom:16px;">Auto-Imported This Week (${recentR.rows.length} transactions)</div>
      ${recentR.rows.length > 0 ? `
      <table style="width:100%;border-collapse:collapse;border:1px solid #e8e8e8;border-radius:6px;overflow:hidden;">
        <thead>
          <tr style="background:#f8f9fa;">
            <th style="padding:10px 12px;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#8899aa;text-align:left;border-bottom:1px solid #e8e8e8;">Date</th>
            <th style="padding:10px 12px;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#8899aa;text-align:left;border-bottom:1px solid #e8e8e8;">Vendor</th>
            <th style="padding:10px 12px;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#8899aa;text-align:left;border-bottom:1px solid #e8e8e8;">Category</th>
            <th style="padding:10px 12px;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#8899aa;text-align:right;border-bottom:1px solid #e8e8e8;">Amount</th>
          </tr>
        </thead>
        <tbody>${recentRows}</tbody>
      </table>` : '<div style="color:#8899aa;font-size:13px;padding:8px 0;">No new transactions auto-imported this week.</div>'}
    </div>
    <div style="padding:20px 32px;background:#060d1a;text-align:center;">
      <div style="font-size:12px;color:#4a6080;">NovaBooks — Novacor LLC Internal Accounting</div>
      <div style="font-size:11px;color:#3a4a5a;margin-top:4px;">Auto-generated every Monday 8:00 AM MST</div>
    </div>
  </div>
</body>
</html>`;

    const rawEmail = [
      `To: novacor.icaz@gmail.com`,
      `From: Novacor Platform <novacor.icaz@gmail.com>`,
      `Subject: NovaBooks Weekly Report - Novacor LLC | Week of ${weekOf}`,
      `MIME-Version: 1.0`,
      `Content-Type: text/html; charset=utf-8`,
      ``,
      html
    ].join('\r\n');

    const gmail2 = google.gmail({ version: 'v1', auth });
    await gmail2.users.messages.send({ userId: 'me', requestBody: { raw: Buffer.from(rawEmail).toString('base64url') } });
    console.log('[NovaBooks] Weekly summary email sent successfully');
  } catch (e) {
    console.error('[NovaBooks] Failed to send weekly summary email:', e.message);
  }
}

// ── Cron: Every Monday 8am America/Phoenix (MST = UTC-7) ────────────────────
function scheduleNovabooksSync() {
  function msUntilNextMonday8am() {
    const now = new Date();
    const mst = new Date(now.toLocaleString('en-US', { timeZone: 'America/Phoenix' }));
    const day = mst.getDay();
    const daysUntilMonday = day === 1 ? (mst.getHours() < 8 ? 0 : 7) : (8 - day) % 7;
    const nextMonday = new Date(mst);
    nextMonday.setDate(mst.getDate() + daysUntilMonday);
    nextMonday.setHours(8, 0, 0, 0);
    const utcNextMonday = new Date(nextMonday.toLocaleString('en-US', { timeZone: 'UTC' }));
    return utcNextMonday - now;
  }

  function scheduleNext() {
    const ms = msUntilNextMonday8am();
    console.log(`[NovaBooks Sync] Next sync scheduled in ${Math.round(ms/1000/60/60)} hours`);
    setTimeout(async () => {
      await runNovabooksSync(null);
      await sendNovaBooksSummaryEmail(null);
      scheduleNext();
    }, ms);
  }

  scheduleNext();
}

scheduleNovabooksSync();

// ── Manual sync endpoint ─────────────────────────────────────────────────────
app.post('/api/nb/sync', async (req, res) => {
  try {
    const result = await runNovabooksSync(req);
    res.json({ ok: true, ...result });
  } catch (e) {
    console.error('[NovaBooks Sync]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/nb/backups — list available backups
app.get('/api/nb/backups', async (req, res) => {
  try {
    const r = await db.execute("SELECT key, length(value) as size FROM kv WHERE key LIKE 'backup_%' ORDER BY key DESC");
    res.json(r.rows.map(row => ({
      key: row.key,
      size: row.size,
      label: row.key.replace('backup_', '').replace(/_\d{4}-\d{2}-\d{2}$/, '') + ' — ' + row.key.slice(-10)
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/nb/restore — restore a backup by key
app.post('/api/nb/restore', async (req, res) => {
  try {
    const { backup_key } = req.body;
    if (!backup_key || !backup_key.startsWith('backup_')) return res.status(400).json({ error: 'Invalid backup key' });
    const backup = await db.execute({ sql: 'SELECT value FROM kv WHERE key=?', args: [backup_key] });
    if (!backup.rows.length) return res.status(404).json({ error: 'Backup not found' });
    // Derive original key from backup key — e.g. backup_nc_active_deals_2026-04-07 → nc_active_deals
    const originalKey = backup_key.replace(/^backup_/, '').replace(/_\d{4}-\d{2}-\d{2}$/, '');
    await db.execute({
      sql: 'INSERT INTO kv (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
      args: [originalKey, backup.rows[0].value]
    });
    console.log(`[Restore] Restored ${originalKey} from ${backup_key}`);
    res.json({ ok: true, restored: originalKey, from: backup_key });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/nb/sync-log', async (req, res) => {
  try {
    const r = await db.execute('SELECT * FROM nb_sync_log ORDER BY synced_at DESC LIMIT 20');
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/nb/send-weekly-report', async (req, res) => {
  try {
    await sendNovaBooksSummaryEmail(req);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Novabooks API ─────────────────────────────────────────────────────────────

// Create all Novabooks tables
await db.execute(`CREATE TABLE IF NOT EXISTS nb_accounts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  institution TEXT DEFAULT '',
  last4 TEXT DEFAULT '',
  opening_balance REAL DEFAULT 0,
  opening_date TEXT DEFAULT '',
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
)`);

await db.execute(`CREATE TABLE IF NOT EXISTS nb_transactions (
  id TEXT PRIMARY KEY,
  date TEXT NOT NULL,
  account_id TEXT NOT NULL,
  deal_id TEXT DEFAULT NULL,
  vendor TEXT DEFAULT '',
  category TEXT NOT NULL,
  amount REAL NOT NULL,
  type TEXT NOT NULL,
  description TEXT DEFAULT '',
  receipt_url TEXT DEFAULT NULL,
  is_reconciled INTEGER DEFAULT 0,
  is_recurring INTEGER DEFAULT 0,
  tax_deductible INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
)`);

await db.execute(`CREATE TABLE IF NOT EXISTS nb_mileage (
  id TEXT PRIMARY KEY,
  date TEXT NOT NULL,
  from_location TEXT NOT NULL,
  to_location TEXT NOT NULL,
  purpose TEXT NOT NULL,
  miles REAL NOT NULL,
  deal_id TEXT DEFAULT NULL,
  rate REAL DEFAULT 0.67,
  created_at TEXT DEFAULT (datetime('now'))
)`);

await db.execute(`CREATE TABLE IF NOT EXISTS nb_vendors (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  company TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  email TEXT DEFAULT '',
  address TEXT DEFAULT '',
  ein_ssn TEXT DEFAULT '',
  notes TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
)`);

await db.execute(`CREATE TABLE IF NOT EXISTS nb_tax_payments (
  id TEXT PRIMARY KEY,
  quarter TEXT NOT NULL,
  year INTEGER NOT NULL,
  amount REAL NOT NULL,
  payment_date TEXT NOT NULL,
  confirmation TEXT DEFAULT '',
  notes TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
)`);

await db.execute(`CREATE TABLE IF NOT EXISTS nb_deals (
  id TEXT PRIMARY KEY,
  address TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  purchase_date TEXT DEFAULT NULL,
  purchase_price REAL DEFAULT 0,
  sale_date TEXT DEFAULT NULL,
  sale_price REAL DEFAULT 0,
  notes TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
)`);

// ── Novabooks: Accounts ──────────────────────────────────────────────────────
app.get('/api/nb/accounts', async (req, res) => {
  try {
    const r = await db.execute('SELECT * FROM nb_accounts ORDER BY created_at ASC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/nb/accounts', async (req, res) => {
  try {
    const { name, type, institution, last4, opening_balance, opening_date } = req.body;
    if (!name || !type) return res.status(400).json({ error: 'name and type required' });
    const id = `acct_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
    await db.execute({ sql: 'INSERT INTO nb_accounts (id,name,type,institution,last4,opening_balance,opening_date) VALUES (?,?,?,?,?,?,?)', args: [id, name, type, institution||'', last4||'', opening_balance||0, opening_date||''] });
    const r = await db.execute({ sql: 'SELECT * FROM nb_accounts WHERE id=?', args: [id] });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/nb/accounts/:id', async (req, res) => {
  try {
    const allowed = ['name','type','institution','last4','opening_balance','opening_date','is_active'];
    const fields = [], args = [];
    for (const k of allowed) { if (req.body[k] !== undefined) { fields.push(`${k}=?`); args.push(req.body[k]); } }
    if (!fields.length) return res.status(400).json({ error: 'nothing to update' });
    args.push(req.params.id);
    await db.execute({ sql: `UPDATE nb_accounts SET ${fields.join(',')} WHERE id=?`, args });
    const r = await db.execute({ sql: 'SELECT * FROM nb_accounts WHERE id=?', args: [req.params.id] });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/nb/accounts/:id', async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM nb_accounts WHERE id=?', args: [req.params.id] });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Novabooks: Transactions ──────────────────────────────────────────────────
app.get('/api/nb/transactions', async (req, res) => {
  try {
    const { account_id, deal_id, category, type, start_date, end_date, search, year } = req.query;
    let sql = 'SELECT * FROM nb_transactions WHERE 1=1';
    const args = [];
    if (account_id) { sql += ' AND account_id=?'; args.push(account_id); }
    if (deal_id) { sql += ' AND deal_id=?'; args.push(deal_id); }
    if (category) { sql += ' AND category=?'; args.push(category); }
    if (type) { sql += ' AND type=?'; args.push(type); }
    if (start_date) { sql += ' AND date>=?'; args.push(start_date); }
    if (end_date) { sql += ' AND date<=?'; args.push(end_date); }
    if (year) { sql += " AND strftime('%Y', date)=?"; args.push(year); }
    if (search) { sql += ' AND (vendor LIKE ? OR description LIKE ? OR category LIKE ?)'; args.push(`%${search}%`,`%${search}%`,`%${search}%`); }
    sql += ' ORDER BY date DESC, created_at DESC';
    const r = await db.execute({ sql, args });
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/nb/transactions', async (req, res) => {
  try {
    const { date, account_id, deal_id, vendor, category, amount, type, description, receipt_url, is_recurring, tax_deductible } = req.body;
    if (!date || !account_id || !category || amount == null || !type) return res.status(400).json({ error: 'date, account_id, category, amount, type required' });
    const id = `txn_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
    await db.execute({ sql: 'INSERT INTO nb_transactions (id,date,account_id,deal_id,vendor,category,amount,type,description,receipt_url,is_recurring,tax_deductible) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', args: [id, date, account_id, deal_id||null, vendor||'', category, amount, type, description||'', receipt_url||null, is_recurring?1:0, tax_deductible!=null?tax_deductible:1] });
    const r = await db.execute({ sql: 'SELECT * FROM nb_transactions WHERE id=?', args: [id] });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/nb/transactions/:id', async (req, res) => {
  try {
    const allowed = ['date','account_id','deal_id','vendor','category','amount','type','description','receipt_url','is_reconciled','is_recurring','tax_deductible'];
    const fields = [], args = [];
    for (const k of allowed) { if (req.body[k] !== undefined) { fields.push(`${k}=?`); args.push(req.body[k]); } }
    if (!fields.length) return res.status(400).json({ error: 'nothing to update' });
    args.push(req.params.id);
    await db.execute({ sql: `UPDATE nb_transactions SET ${fields.join(',')} WHERE id=?`, args });
    const r = await db.execute({ sql: 'SELECT * FROM nb_transactions WHERE id=?', args: [req.params.id] });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/nb/transactions/:id', async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM nb_transactions WHERE id=?', args: [req.params.id] });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Novabooks: Mileage ───────────────────────────────────────────────────────
app.get('/api/nb/mileage', async (req, res) => {
  try {
    const { year } = req.query;
    let sql = 'SELECT * FROM nb_mileage WHERE 1=1';
    const args = [];
    if (year) { sql += " AND strftime('%Y',date)=?"; args.push(year); }
    sql += ' ORDER BY date DESC';
    const r = await db.execute({ sql, args });
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/nb/mileage', async (req, res) => {
  try {
    const { date, from_location, to_location, purpose, miles, deal_id, rate } = req.body;
    if (!date || !from_location || !to_location || !purpose || !miles) return res.status(400).json({ error: 'all fields required' });
    const id = `mil_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
    await db.execute({ sql: 'INSERT INTO nb_mileage (id,date,from_location,to_location,purpose,miles,deal_id,rate) VALUES (?,?,?,?,?,?,?,?)', args: [id, date, from_location, to_location, purpose, miles, deal_id||null, rate||0.67] });
    const r = await db.execute({ sql: 'SELECT * FROM nb_mileage WHERE id=?', args: [id] });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/nb/mileage/:id', async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM nb_mileage WHERE id=?', args: [req.params.id] });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Novabooks: Vendors ───────────────────────────────────────────────────────
app.get('/api/nb/vendors', async (req, res) => {
  try {
    const r = await db.execute('SELECT * FROM nb_vendors ORDER BY name ASC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/nb/vendors', async (req, res) => {
  try {
    const { name, company, phone, email, address, ein_ssn, notes } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    const id = `vnd_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
    await db.execute({ sql: 'INSERT INTO nb_vendors (id,name,company,phone,email,address,ein_ssn,notes) VALUES (?,?,?,?,?,?,?,?)', args: [id, name, company||'', phone||'', email||'', address||'', ein_ssn||'', notes||''] });
    const r = await db.execute({ sql: 'SELECT * FROM nb_vendors WHERE id=?', args: [id] });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/nb/vendors/:id', async (req, res) => {
  try {
    const allowed = ['name','company','phone','email','address','ein_ssn','notes'];
    const fields = [], args = [];
    for (const k of allowed) { if (req.body[k] !== undefined) { fields.push(`${k}=?`); args.push(req.body[k]); } }
    if (!fields.length) return res.status(400).json({ error: 'nothing to update' });
    args.push(req.params.id);
    await db.execute({ sql: `UPDATE nb_vendors SET ${fields.join(',')} WHERE id=?`, args });
    const r = await db.execute({ sql: 'SELECT * FROM nb_vendors WHERE id=?', args: [req.params.id] });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/nb/vendors/:id', async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM nb_vendors WHERE id=?', args: [req.params.id] });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Novabooks: Tax Payments ──────────────────────────────────────────────────
app.get('/api/nb/tax-payments', async (req, res) => {
  try {
    const r = await db.execute('SELECT * FROM nb_tax_payments ORDER BY year DESC, quarter ASC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/nb/tax-payments', async (req, res) => {
  try {
    const { quarter, year, amount, payment_date, confirmation, notes } = req.body;
    if (!quarter || !year || !amount || !payment_date) return res.status(400).json({ error: 'quarter, year, amount, payment_date required' });
    const id = `tax_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
    await db.execute({ sql: 'INSERT INTO nb_tax_payments (id,quarter,year,amount,payment_date,confirmation,notes) VALUES (?,?,?,?,?,?,?)', args: [id, quarter, year, amount, payment_date, confirmation||'', notes||''] });
    const r = await db.execute({ sql: 'SELECT * FROM nb_tax_payments WHERE id=?', args: [id] });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/nb/tax-payments/:id', async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM nb_tax_payments WHERE id=?', args: [req.params.id] });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Novabooks: Deals ─────────────────────────────────────────────────────────
app.get('/api/nb/deals', async (req, res) => {
  try {
    const r = await db.execute("SELECT * FROM nb_deals ORDER BY created_at DESC");
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/nb/deals', async (req, res) => {
  try {
    const { address, status, purchase_date, purchase_price, sale_date, sale_price, notes } = req.body;
    if (!address) return res.status(400).json({ error: 'address required' });
    const id = `deal_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
    await db.execute({ sql: 'INSERT INTO nb_deals (id,address,status,purchase_date,purchase_price,sale_date,sale_price,notes) VALUES (?,?,?,?,?,?,?,?)', args: [id, address, status||'active', purchase_date||null, purchase_price||0, sale_date||null, sale_price||0, notes||''] });
    const r = await db.execute({ sql: 'SELECT * FROM nb_deals WHERE id=?', args: [id] });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/nb/deals/:id', async (req, res) => {
  try {
    const allowed = ['address','status','purchase_date','purchase_price','sale_date','sale_price','notes'];
    const fields = [], args = [];
    for (const k of allowed) { if (req.body[k] !== undefined) { fields.push(`${k}=?`); args.push(req.body[k]); } }
    if (!fields.length) return res.status(400).json({ error: 'nothing to update' });
    args.push(req.params.id);
    await db.execute({ sql: `UPDATE nb_deals SET ${fields.join(',')} WHERE id=?`, args });
    const r = await db.execute({ sql: 'SELECT * FROM nb_deals WHERE id=?', args: [req.params.id] });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Novabooks: Summary (dashboard stats) ────────────────────────────────────
app.get('/api/nb/summary', async (req, res) => {
  try {
    const { year } = req.query;
    const y = year || new Date().getFullYear().toString();
    const txns = await db.execute({ sql: "SELECT type, category, amount, tax_deductible FROM nb_transactions WHERE strftime('%Y',date)=?", args: [y] });
    let totalIncome = 0, totalExpenses = 0;
    const byCategory = {};
    for (const t of txns.rows) {
      if (t.type === 'income') totalIncome += t.amount;
      else { totalExpenses += t.amount; byCategory[t.category] = (byCategory[t.category]||0) + t.amount; }
    }
    const netProfit = totalIncome - totalExpenses;
    const seTax = netProfit > 0 ? netProfit * 0.9235 * 0.153 : 0;
    const fedTax = netProfit > 0 ? netProfit * 0.22 : 0;
    const estimatedTaxOwed = seTax + fedTax;
    const mileage = await db.execute({ sql: "SELECT SUM(miles) as miles, SUM(miles*rate) as deduction FROM nb_mileage WHERE strftime('%Y',date)=?", args: [y] });
    const taxPaid = await db.execute({ sql: 'SELECT SUM(amount) as paid FROM nb_tax_payments WHERE year=?', args: [y] });
    res.json({ year: y, totalIncome, totalExpenses, netProfit, estimatedTaxOwed, seTax, fedTax, mileageMiles: mileage.rows[0].miles||0, mileageDeduction: mileage.rows[0].deduction||0, taxPaid: taxPaid.rows[0].paid||0, byCategory });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/google/calendar/:eventId — delete event
app.delete('/api/google/calendar/:eventId', async (req, res) => {
  try {
    const auth = await getAuthedClient(req);
    if (!auth) return res.status(401).json({ error: 'not_authenticated' });
    const cal = google.calendar({ version: 'v3', auth });
    await cal.events.delete({ calendarId: 'primary', eventId: req.params.eventId });
    res.json({ ok: true });
  } catch (e) {
    console.error('[Calendar Delete]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port', PORT));
