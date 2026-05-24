# Copilot Instructions for secure-action-inputs

## Project overview

This is a GitHub Action (Node.js, zero runtime dependencies) that scans GitHub Actions event payloads for security threats: hidden Unicode, BIDI/Trojan-Source, shell injection, path traversal, script injection, template injection, homoglyphs, and AI prompt injection.

## Architecture

- **`src/scanner.js`** — pure detection logic; exports `scanString`, `scanValue`, and individual `check*` functions.
- **`src/main.js`** — action entry point; reads the event payload, calls the scanner, writes `$GITHUB_STEP_SUMMARY`, posts PR/issue comments, and sets the exit code.
- **`dist/index.js`** — bundled output (built with `@vercel/ncc`). **Always rebuild after editing `src/`.**
- **`__tests__/scanner.test.js`** — Jest unit tests for the scanner.

## Conventions

- Zero runtime dependencies. Use only Node.js built-ins (`fs`, `https`, etc.).
- All user-controlled content rendered into Markdown/HTML must be HTML-escaped (`escapeHtml`) to prevent injection.
- Run `npm test` then `npm run build` after every source change.
- Commit `dist/index.js` alongside source changes.
- The action uses `node24` runtime.

## Key env vars (in GitHub Actions context)

| Variable | Purpose |
|---|---|
| `GITHUB_EVENT_PATH` | Path to the JSON event payload |
| `GITHUB_STEP_SUMMARY` | Path to write Job Summary Markdown |
| `GITHUB_REPOSITORY` | `owner/repo` for API calls |
| `INPUT_SHOW-CONTEXT` | Boolean: show context snippets |
| `INPUT_POST-COMMENT` | Boolean: post PR/issue comment |
| `INPUT_GITHUB-TOKEN` | Token for GitHub API calls |
