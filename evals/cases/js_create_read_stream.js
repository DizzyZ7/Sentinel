function stream(req) {
  return fs.createReadStream(req.params.filename);
}
