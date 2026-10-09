export default [
  {
    files: ["src/**/*.js", "tests/**/*.js", "scripts/**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: {
        console: "readonly",
        process: "readonly",
        document: "readonly",
        window: "readonly",
        localStorage: "readonly",
        navigator: "readonly",
        URL: "readonly",
        Date: "readonly"
      }
    },
    rules: {
      "no-unused-vars": ["warn", { "argsIgnorePattern": "^_" }],
      "no-undef": "error",
      "no-constant-condition": "warn"
    }
  }
];
