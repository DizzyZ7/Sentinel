export function runJob(req: any) {
  return Function(req.body.code)();
}
