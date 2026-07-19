async function proxy(req) {
  return axios.get(req.body.target);
}
