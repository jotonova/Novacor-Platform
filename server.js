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
  if (req.path.startsWith('/api/') || req.path.startsWith('/auth/google')) {
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
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

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
app.post('/api/crm/contacts', async (req, res) => {
  const secret = process.env.PLATFORM_API_SECRET || '';
  if (!secret || req.headers['x-platform-secret'] !== secret) {
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
    await saveTokens({ ...tokens, ...refreshed });
  });
  return auth;
}

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
    const r = await cal.events.insert({
      calendarId: 'primary',
      requestBody: {
        summary: title,
        start: { dateTime: start },
        end: { dateTime: end },
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
