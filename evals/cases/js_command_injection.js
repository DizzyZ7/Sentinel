function run(req) {
  return child_process.exec(req.query.command);
}
