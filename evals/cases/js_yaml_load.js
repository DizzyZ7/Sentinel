function parse(req) {
  return jsyaml.load(req.body.document);
}
