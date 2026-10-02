export type DiffOp = { kind: "same" | "add" | "del"; text: string };

/** Line diff by longest common subsequence. Inputs above 2000 lines fall back to full replace. */
export function diffLines(a: string, b: string): DiffOp[] {
  const x = a === "" ? [] : a.split("\n");
  const y = b === "" ? [] : b.split("\n");
  if (x.length > 2000 || y.length > 2000) {
    return [
      ...x.map((t) => ({ kind: "del" as const, text: t })),
      ...y.map((t) => ({ kind: "add" as const, text: t })),
    ];
  }
  const n = x.length;
  const m = y.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i]![j] = x[i] === y[j] ? dp[i + 1]![j + 1]! + 1 : Math.max(dp[i + 1]![j]!, dp[i]![j + 1]!);
    }
  }
  const out: DiffOp[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) {
      out.push({ kind: "same", text: x[i]! });
      i++;
      j++;
    } else if (dp[i + 1]![j]! >= dp[i]![j + 1]!) {
      out.push({ kind: "del", text: x[i++]! });
    } else {
      out.push({ kind: "add", text: y[j++]! });
    }
  }
  while (i < n) out.push({ kind: "del", text: x[i++]! });
  while (j < m) out.push({ kind: "add", text: y[j++]! });
  return out;
}
