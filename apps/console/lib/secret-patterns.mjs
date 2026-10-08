/* One list of secret shapes for the unit-tested scanner (`secret-scan.ts`) AND the build gate (`scripts/scan-bundle.mjs`): a second copy
   drifted once (the gate lacked the OpenAI-style key and the bearer literal). Plain .mjs so the gate runs without a TypeScript step. */
export const PATTERNS = [
  { rule: "axis-api-key", re: /axk_[0-9a-f]{16}_[A-Za-z0-9_-]{20,}/ },
  { rule: "axis-scim-token", re: /axs_[0-9a-f]{16}_[A-Za-z0-9_-]{20,}/ },
  { rule: "anthropic-key", re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { rule: "openai-style-key", re: /sk-[A-Za-z0-9]{32,}/ },
  { rule: "aws-access-key", re: /AKIA[0-9A-Z]{16}/ },
  { rule: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { rule: "bearer-literal", re: /Bearer\s+[A-Za-z0-9._-]{30,}/ },
];
