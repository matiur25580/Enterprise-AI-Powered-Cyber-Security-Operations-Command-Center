export function isAllowedOrigin(origin: string | undefined, allowedOrigin: string): boolean {
  // Non-browser clients commonly omit Origin; browser origins must match exactly.
  return origin === undefined || origin === allowedOrigin;
}
