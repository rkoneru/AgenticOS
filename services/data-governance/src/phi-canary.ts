/**
 * PHI canary harness (docs/spec/data-governance.md section 6). A canary is a PHI-shaped value with a known core; `findLeaks` reports
 * every canary whose core is still recognisable in a text after Unicode normalisation (NFKC, format characters removed, digit
 * separators ignored). Obfuscated variants (fullwidth digits, zero-width characters, odd separators) are part of the set because the
 * redaction net must not be defeated by them.
 */
export interface Canary {
  id: string;
  /** What is written through each ingress. */
  text: string;
  /** What must not be recoverable afterwards. */
  core: { kind: "digits" | "word"; value: string };
}

export const CANARIES: readonly Canary[] = [
  {
    id: "ssn-plain",
    text: "patient ssn 123-45-6789 on file",
    core: { kind: "digits", value: "123456789" },
  },
  {
    id: "ssn-spaced",
    text: "ssn 234 56 7890 given verbally",
    core: { kind: "digits", value: "234567890" },
  },
  {
    id: "ssn-fullwidth",
    text: "ssn １３５-７９-２４６８ typed",
    core: { kind: "digits", value: "135792468" },
  },
  { id: "ssn-zwsp", text: "ssn 246-80-13​57 pasted", core: { kind: "digits", value: "246801357" } },
  { id: "ssn-dots", text: "ssn 357.91.2468 scanned", core: { kind: "digits", value: "357912468" } },
  {
    id: "ssn-labelled",
    text: "social security number 468013579",
    core: { kind: "digits", value: "468013579" },
  },
  { id: "mrn", text: "chart MRN: 99887766 reviewed", core: { kind: "digits", value: "99887766" } },
  {
    id: "email",
    text: "contact zelda.canary@clinic-example.org today",
    core: { kind: "word", value: "zelda.canary@clinic-example.org" },
  },
  {
    id: "email-plus",
    text: "mail zelda+rx@clinic-example.org",
    core: { kind: "word", value: "zelda+rx@clinic-example.org" },
  },
  {
    id: "phone",
    text: "call (415) 555-0134 after noon",
    core: { kind: "digits", value: "4155550134" },
  },
  { id: "phone-intl", text: "call +1 415 555 0177", core: { kind: "digits", value: "4155550177" } },
];
/** A name has no pattern the built-in net can know; it is covered only when the tenant supplies a DLP hook (see NEEDS). */
export const NAME_CANARY: Canary = {
  id: "name",
  text: "patient Zelda Quentin Canary admitted",
  core: { kind: "word", value: "zelda quentin canary" },
};

const FMT = /\p{Cf}/gu;
export const normalize = (s: string): string => s.normalize("NFKC").replace(FMT, "").toLowerCase();

/** Does `text` still reveal the canary core? */
export function leaks(text: string, c: Canary): boolean {
  const t = normalize(text);
  if (c.core.kind === "word") return t.includes(c.core.value.toLowerCase());
  // digits: allow separators between the digits of the core
  const re = new RegExp(c.core.value.split("").join("[\\s.\\-\\u2010-\\u2015\\u2212()]*"));
  return re.test(t);
}

export function findLeaks(text: string, canaries: readonly Canary[] = CANARIES): string[] {
  return canaries.filter((c) => leaks(text, c)).map((c) => c.id);
}
