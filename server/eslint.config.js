// ESLint 9 flat config for the server package (see design.md D9).
import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ignores: [
      'node_modules/**',
      'keys/**',                    // runtime-generated key material, not source
      'public/**/*.html',           // markup, not JavaScript
    ],
  },
  js.configs.recommended,
  {
    // AP8-34 (#215): the sign-in page's ES modules under public/js/ are part of
    // the lint gate. They run in the browser and use the two vendor globals the
    // page loads before them. (The browser extension has its own flat config in
    // extension/eslint.config.js — ESLint refuses files outside this base path;
    // test/unit/extension.test.mjs runs it, AP8-47/#246.)
    files: ['public/js/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.browser, qrcode: 'readonly' },
    },
  },
  {
    // Applies to server code and every test tree, including test/e2e (#25:
    // Playwright specs run under Node — the Node globals are sufficient).
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.node, ...globals.browser },
    },
    rules: {
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-unused-vars': 'warn',
      'no-useless-escape': 'warn',
    },
  },
];
