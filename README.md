# AgenticOS

AgenticOS

## SDKs and CLI

```bash
node scripts/generate-sdks.mjs            # regenerate the SDKs from the OpenAPI (CI runs --check)
pnpm --filter @axis/cli build && node apps/cli/dist/bin.js --help
```

See `docs/spec/sdk.md` and `docs/spec/cli.md`.
