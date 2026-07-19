function ping(req) {
  return child_process.spawn('ping', ['-c', '1', req.query.host], { shell: false });
}
