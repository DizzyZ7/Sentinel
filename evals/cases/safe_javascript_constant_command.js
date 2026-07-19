function version() {
  return child_process.exec("git --version");
}
