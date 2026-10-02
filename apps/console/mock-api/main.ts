import { startMockApi } from "./server";

const port = Number(process.env["MOCK_API_PORT"] ?? 4010);
await startMockApi(port);
console.log(`mock control-plane API on http://127.0.0.1:${port}`);
