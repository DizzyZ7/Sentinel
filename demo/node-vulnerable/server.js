const express = require('express');
const app = express();
const SERVICE_TOKEN = "token_123456789012345678901234";

app.get('/search', async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE email = '${req.query.email}'`);
  res.json(rows);
});

app.post('/run', (req, res) => {
  res.json({ result: eval(req.body.expression) });
});

app.delete('/admin/users/:id', async (req, res) => {
  await users.remove(req.params.id);
  res.status(204).end();
});

app.get('/shell', (req, res) => {
  child_process.exec(req.query.command);
  res.json({ started: true });
});

app.get('/download', (req, res) => {
  fs.readFile(req.query.path, (error, data) => res.send(data));
});

app.get('/proxy', async (req, res) => {
  const response = await fetch(req.query.url);
  res.send(await response.text());
});
