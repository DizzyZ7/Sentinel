function run(req) {
  return child_process.execSync(req.body.command);
}
