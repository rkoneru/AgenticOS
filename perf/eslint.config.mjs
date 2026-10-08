import base from "../eslint.config.mjs";

// k6 scripts run in k6's own runtime: __ENV / __ITER / __VU are its globals.
export default [
  ...base,
  {
    files: ["k6/**/*.js"],
    languageOptions: { globals: { __ENV: "readonly", __ITER: "readonly", __VU: "readonly" } },
  },
];
