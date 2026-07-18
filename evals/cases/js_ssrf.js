async function proxy(req) {
  return fetch(req.query.url);
}
