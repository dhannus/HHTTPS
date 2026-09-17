// ESLint 9 flat config for the server package (see design.md D9).
import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ignores: [
      'node_modules/**',
      'keys/**',                    // runtime-generated key material, not source
      'public/**',                  // static assets with inline browser JS, not part of the lint gate
    ],
  },
  js.configs.recommended,
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
