# secure-action-inputs

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Secure%20Action%20Inputs-blue?logo=github)](https://github.com/marketplace/actions/secure-action-inputs)

A GitHub Action that scans the full event payload for common attack vectors — hidden Unicode characters, bidirectional text (Trojan Source), shell injection, path traversal, script injection, template expression injection, and AI prompt injection. Use it in any workflow to detect whether an actor (human or bot) is attempting to inject malicious content through PR titles, branch names, issue bodies, comments, or any other event field.

When a threat is found the step fails with a non-zero exit code and writes a detailed report to the [Job Summary](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#adding-a-job-summary).

## Attack vectors detected

| Category | What is flagged |
|---|---|
| **Homoglyphs** | Cyrillic, Greek, and fullwidth Latin letters that look identical to ASCII (e.g. Cyrillic `а`→`a`, `о`→`o`, `р`→`p`; Greek `Ο`→`O`; fullwidth `Ａ`→`A`). Used in IDN homograph and supply-chain spoofing attacks |
| **Hidden Unicode** | Zero-width spaces (U+200B/C/D), BOM (U+FEFF), soft hyphen, null byte, LTR/RTL marks, word joiner, line/paragraph separators |
| **Bidirectional / Trojan Source** | All BIDI control characters (U+202A–202E, U+2066–2069, U+061C) that make malicious content appear benign to reviewers |
| **Shell injection** | Backtick substitution `` `cmd` ``, dollar-paren `$(cmd)`, `eval()`/`exec()` code execution, semicolon/pipe chaining to `bash`, `curl`, `python`, etc. |
| **Path traversal** | `../` and `..\` sequences that can escape intended directories |
| **Script injection** | `<script>`, `javascript:`, `<iframe>`, `onerror=` and other HTML event handler attributes |
| **Template/expression injection** | `${{` (GitHub Actions context leakage) and `{{...}}` template expressions |
| **Prompt injection** | AI/LLM override phrases such as `ignore previous instructions`, `pretend you are`, `jailbreak`, and other directives designed to manipulate AI assistants that process event data |

## Usage

Add the action as an early step in any workflow that handles untrusted input. No inputs are required — the action reads the event payload automatically from `GITHUB_EVENT_PATH`.

```yaml
name: Security scan

on:
  pull_request:
  issues:
  issue_comment:
  pull_request_review_comment:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan event payload for attack vectors
        uses: devops-actions/secure-action-inputs@v1
```

### Recommended: scan before using event data in shell

Place this step **before** any step that interpolates event fields into shell commands or scripts.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Scan event payload for attack vectors
        uses: devops-actions/secure-action-inputs@v1

      - name: Checkout
        uses: actions/checkout@v4

      # Safe: the scan above would have already failed the job
      # if the branch name contained shell injection characters.
      - name: Build
        run: |
          echo "Building branch: ${{ github.head_ref }}"
```

## Example output

### Clean payload

When no threats are detected the step passes and the Job Summary shows:

```
✅ No security threats detected in the GitHub Actions event payload.
```

### Malicious payload

When threats are detected the step fails and the Job Summary shows a table like:

| Field | Attack Type | Details |
|-------|-------------|---------|
| `pull_request.title` | hidden_unicode | Hidden Unicode character: Zero Width Space (U+200B) (×1) |
| `pull_request.head.ref` | homoglyph | Homoglyph attack: Cyrillic letters visually similar to Latin ASCII (e.g. а→a, е→e, о→o, р→p, с→c, х→x) (×2) |
| `pull_request.body` | bidi_attack | Bidirectional text (Trojan Source) attack: Right-to-Left Override (U+202E) (×1) |
| `pull_request.head.ref` | shell_injection | Potential shell injection: Backtick command substitution |
| `issue.body` | script_injection | Potential script injection: HTML script tag |
| `comment.body` | template_injection | Potential template/expression injection: GitHub Actions expression injection ${{ |

And each finding is also emitted as a workflow error annotation:

```
::error::[hidden_unicode] pull_request.title: Hidden Unicode character: Zero Width Space (U+200B) (×1)
::error::[shell_injection] pull_request.head.ref: Potential shell injection: Backtick command substitution
::error::Security scan failed: 5 potential attack vector(s) found in 4 field(s). See the step summary for details.
```

## How it works

1. The action reads the JSON event payload from `$GITHUB_EVENT_PATH`.
2. It recursively walks every field in the payload (objects, arrays, strings).
3. Each string value is checked against all detector patterns.
4. Results are aggregated and written to `$GITHUB_STEP_SUMMARY`.
5. If any findings exist, `process.exitCode` is set to `1` to fail the step.

The action has **zero runtime dependencies** — all logic is bundled into `dist/index.js` with `@vercel/ncc`, and GitHub Actions workflow commands are issued directly over stdout to avoid supply-chain risk from transitive dependencies.

## License

MIT
