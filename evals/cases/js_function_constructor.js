function compile(req) {
  return Function(req.body.source)();
}
