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
