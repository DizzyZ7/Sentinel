function parse(req) {
  return yaml.safeLoad(req.body.document);
}
