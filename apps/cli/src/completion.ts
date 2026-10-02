import { GLOBAL_FLAGS, type Command } from "./cli.js";

export type Shell = "bash" | "zsh" | "fish";

const visible = (cs: readonly Command[]) => cs.filter((c) => c.path[0] !== "docs");

/** Words that may follow a command path: sub-commands, or the flags of a leaf command. */
function wordsAfter(cs: readonly Command[], prefix: readonly string[]): string[] {
  const subs = new Set<string>();
  for (const c of visible(cs)) {
    if (c.path.length > prefix.length && prefix.every((p, i) => c.path[i] === p))
      subs.add(c.path[prefix.length] as string);
  }
  if (subs.size > 0) return [...subs];
  const leaf = cs.find((c) => c.path.join(" ") === prefix.join(" "));
  return [...GLOBAL_FLAGS, ...(leaf?.flags ?? [])].map((f) => `--${f.name}`);
}

function allPaths(cs: readonly Command[]): string[][] {
  const seen = new Set<string>();
  const out: string[][] = [[]];
  for (const c of visible(cs)) {
    for (let n = 1; n <= c.path.length; n++) {
      const p = c.path.slice(0, n);
      if (!seen.has(p.join(" "))) {
        seen.add(p.join(" "));
        out.push(p);
      }
    }
  }
  return out;
}

export function completionScript(shell: Shell, cs: readonly Command[], bin: string): string {
  const paths = allPaths(cs);
  if (shell === "fish") {
    const lines = [`# fish completion for ${bin}`];
    for (const p of paths) {
      const words = wordsAfter(cs, p).filter((w) => !w.startsWith("--"));
      const cond =
        p.length === 0
          ? "__fish_use_subcommand"
          : `__fish_seen_subcommand_from ${p.join("; and __fish_seen_subcommand_from ")}`;
      for (const w of words) lines.push(`complete -c ${bin} -n '${cond}' -a ${w}`);
    }
    for (const f of GLOBAL_FLAGS)
      lines.push(`complete -c ${bin} -l ${f.name} -d '${f.desc.replace(/'/g, "")}'`);
    return `${lines.join("\n")}\n`;
  }
  const cases = paths
    .map((p) => `    "${p.join(" ")}") words="${wordsAfter(cs, p).join(" ")}" ;;`)
    .join("\n");
  if (shell === "bash") {
    return `# bash completion for ${bin}
_${bin}_complete() {
  local cur="\${COMP_WORDS[COMP_CWORD]}" path="" i w words=""
  for ((i = 1; i < COMP_CWORD; i++)); do
    w="\${COMP_WORDS[i]}"
    [[ "$w" == -* ]] && continue
    path="\${path:+$path }$w"
  done
  case "$path" in
${cases}
    *) words="" ;;
  esac
  COMPREPLY=($(compgen -W "$words" -- "$cur"))
}
complete -F _${bin}_complete ${bin}
`;
  }
  return `#compdef ${bin}
# zsh completion for ${bin}
_${bin}() {
  local path="" w words
  for w in \${words[2,CURRENT-1]}; do
    [[ "$w" == -* ]] && continue
    path="\${path:+$path }$w"
  done
  case "$path" in
${cases}
    *) words="" ;;
  esac
  compadd -- \${=words}
}
compdef _${bin} ${bin}
`;
}
