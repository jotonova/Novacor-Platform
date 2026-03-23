import { createClient } from '@libsql/client';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { google } from 'googleapis';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());
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
  'https://www.googleapis.com/auth/calendar.readonly',
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

// GET /api/google/gmail — last 10 inbox messages
app.get('/api/google/gmail', async (req, res) => {
  try {
    const auth = await getAuthedClient(req);
    if (!auth) return res.status(401).json({ error: 'not_authenticated' });

    const gmail = google.gmail({ version: 'v1', auth });
    const list = await gmail.users.messages.list({ userId: 'me', labelIds: ['INBOX'], maxResults: 10 });
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

// ─────────────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port', PORT));
