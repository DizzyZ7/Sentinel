function terms(callback) {
  return fs.readFile('/srv/app/terms.txt', callback);
}
