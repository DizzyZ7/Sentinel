function download(req, callback) {
  return fs.readFile(req.query.path, callback);
}
