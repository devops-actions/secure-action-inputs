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

Add the action as an early step in any workflow that handles untrusted input. No required inputs — the action reads the event payload automatically from `GITHUB_EVENT_PATH`.

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
    permissions:
      issues: write          # required for post-comment
      pull-requests: write   # required for post-comment
    steps:
      - name: Scan event payload for attack vectors
        uses: devops-actions/secure-action-inputs@v1
```

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `show-context` | `true` | Show a collapsible context snippet for each finding — the surrounding lines where the issue was detected, with the matched line highlighted. Set to `false` to show only the finding summary table. |
| `post-comment` | `true` | Post (or update) a scan-results comment on the pull request or issue that triggered the workflow. The action checks for write access first and silently skips if unavailable. Set to `false` to disable. |
| `github-token` | `${{ github.token }}` | Token used to post the comment. Must have `issues: write` and `pull-requests: write` permissions for the comment feature to work. |

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

When threats are detected the step fails and the Job Summary shows a table with per-finding context snippets (collapsed by default):

| Field | Attack Type | Details |
|-------|-------------|---------|
| `pull_request.title` | hidden_unicode | Hidden Unicode character: Zero Width Space (U+200B) (×1) |
| `pull_request.head.ref` | homoglyph | Homoglyph attack: Cyrillic letters visually similar to Latin ASCII (×2) |
| `pull_request.body` | bidi_attack | Bidirectional text (Trojan Source) attack: Right-to-Left Override (U+202E) (×1) |

Each finding also includes a collapsible **Location** block showing the matched line ± 2 lines of context:

<details>
<summary>📍 Location: <code>pull_request.title</code> — single-line value</summary>

<pre><code>▶ Fix login bug[ZWSP]
</code></pre>

</details>

And each finding is emitted as a workflow error annotation:

```
::error::[hidden_unicode] pull_request.title: Hidden Unicode character: Zero Width Space (U+200B) (×1)
::error::Security scan failed: 3 potential attack vector(s) found in 3 field(s). See the step summary for details.
```

When the `post-comment` input is enabled (default), the same report is posted (or updated) as a comment on the pull request or issue.

## How it works

1. The action reads the JSON event payload from `$GITHUB_EVENT_PATH`.
2. It recursively walks every field in the payload (objects, arrays, strings).
3. Each string value is checked against all detector patterns.
4. Results are aggregated and written to `$GITHUB_STEP_SUMMARY`.
5. When `show-context: true` (default), each finding includes a collapsible snippet showing the matched line ± 2 lines of surrounding context.
6. When `post-comment: true` (default) and the event is a PR or issue, the same report is posted (or updated) as a comment on the PR/issue.
7. If any findings exist, `process.exitCode` is set to `1` to fail the step.

The action has **zero runtime dependencies** — all logic is bundled into `dist/index.js` with `@vercel/ncc`, and GitHub Actions workflow commands are issued directly over stdout to avoid supply-chain risk from transitive dependencies.

## License

MIT
