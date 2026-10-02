import "@testing-library/jest-dom/vitest";
import { expect } from "vitest";
import { toHaveNoViolations } from "jest-axe";

expect.extend(toHaveNoViolations as unknown as Parameters<typeof expect.extend>[0]);

declare module "vitest" {
  interface Assertion {
    toHaveNoViolations(): void;
  }
}
