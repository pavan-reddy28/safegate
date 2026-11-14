import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import { defineConfig, globalIgnores } from "eslint/config";

export default defineConfig([
  globalIgnores(["dist", "android", ".playwright-cli"]),
  {
    files: [
      "src/app.js",
      "src/server.js",
      "src/config/**/*.js",
      "src/controllers/**/*.js",
      "src/middleware/**/*.js",
      "src/routes/**/*.js",
      "src/services/**/*.js",
      "src/utils/**/*.js",
      "src/security/compoundThreatCorrelator.js",
      "src/security/domainAnalyzer.js",
      "src/security/knownSafeDomains.js",
      "src/security/lexicalRiskEngine.js",
      "src/security/localThreatList.js",
      "src/security/offlineThreatFeed.js",
      "src/security/pathAnalyzer.js",
      "src/security/privacyFirstAnalyzer.js",
      "src/security/privacyGuard.js",
      "src/security/queryAnalyzer.js",
      "src/security/redirectToken.js",
      "src/security/scamLureAnalyzer.js",
      "src/security/urlAnalyzer.js",
      "src/security/urlNormalizer.js",
      "tests/**/*.js"
    ],
    extends: [js.configs.recommended],
    languageOptions: {
      sourceType: "commonjs",
      globals: {
        ...globals.node
      }
    },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
      "no-control-regex": "off"
    }
  },
  {
    files: [
      "src/**/*.jsx",
      "src/security/blockStore.js",
      "src/security/sqliteDatabase.js",
      "src/security/verificationService.js",
      "src/security/urlFingerprint.js",
      "src/security/offlineEngine.js",
      "vite.config.mjs",
      "eslint.config.mjs"
    ],
    extends: [
      js.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite
    ],
    languageOptions: {
      sourceType: "module",
      globals: {
        ...globals.browser
      },
      parserOptions: { ecmaFeatures: { jsx: true } }
    },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }]
    }
  }
]);
