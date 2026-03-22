import { createClient } from '@libsql/client';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port', PORT));
