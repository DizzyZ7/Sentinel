router.get('/admin/proxy', async (req) => fetch(req.query.url));
