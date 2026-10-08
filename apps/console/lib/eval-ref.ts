/** `[namespace/]name@version` */
export function parseBlueprintRef(
  ref: string,
): { namespace?: string; name: string; version: string } | undefined {
  const m = /^(?:([a-z][a-z0-9-]{1,62})\/)?([a-z][a-z0-9-]{1,62})@([0-9A-Za-z.+-]+)$/.exec(
    ref.trim(),
  );
  if (!m) return undefined;
  return { ...(m[1] ? { namespace: m[1] } : {}), name: m[2] as string, version: m[3] as string };
}
