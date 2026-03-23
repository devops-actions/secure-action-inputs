'use strict';

const fs = require('fs');
const { scanValue } = require('./scanner');

/**
 * GitHub Actions workflow commands implemented without external dependencies.
 * See: https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions
 */
const core = {
  info: (msg) => process.stdout.write(`${msg}\n`),
  warning: (msg) => process.stdout.write(`::warning::${msg}\n`),
  error: (msg) => process.stdout.write(`::error::${msg}\n`),
  setFailed: (msg) => {
    process.stdout.write(`::error::${msg}\n`);
    process.exitCode = 1;
  },
};

/**
 * Truncates a string to a maximum length for safe display in summaries.
 * @param {string} text - The text to truncate.
 * @param {number} maxLength - Maximum number of characters.
 * @returns {string} Truncated text.
 */
function truncate(text, maxLength = 80) {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength) + '…';
}

/**
 * Escapes characters that have special meaning in Markdown tables.
 * @param {string} text - The text to escape.
 * @returns {string} Markdown-safe text.
 */
function escapeMarkdown(text) {
  return text
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/`/g, '\\`');
}

/**
 * Builds the markdown summary content for the step summary.
 * @param {Array} findings - Array of { path, results } finding objects.
 * @returns {string} Markdown summary.
 */
function buildSummary(findings) {
  if (findings.length === 0) {
    return [
      '## 🛡️ Secure Action Inputs — Security Scan Results',
      '',
      '✅ **No security threats detected in the GitHub Actions event payload.**',
      '',
    ].join('\n');
  }

  const totalIssues = findings.reduce((sum, f) => sum + f.results.length, 0);

  const lines = [
    '## 🛡️ Secure Action Inputs — Security Scan Results',
    '',
    `> ⚠️ **${totalIssues} potential security issue(s) detected across ${findings.length} field(s) in the event payload.**`,
    '',
    '| Field | Attack Type | Details |',
    '|-------|-------------|---------|',
  ];

  for (const finding of findings) {
    for (const result of finding.results) {
      const countNote = result.count ? ` (×${result.count})` : '';
      lines.push(
        `| \`${escapeMarkdown(finding.path)}\` | ${result.type} | ${escapeMarkdown(result.description)}${countNote} |`,
      );
    }
  }

  lines.push('');
  lines.push('### Attack Types Legend');
  lines.push('');
  lines.push('| Type | Description |');
  lines.push('|------|-------------|');
  lines.push('| `hidden_unicode` | Invisible Unicode characters (zero-width spaces, BOM, null bytes, etc.) that can hide malicious content |');
  lines.push('| `bidi_attack` | Bidirectional text control characters (Trojan Source) that alter how code is visually rendered |');
  lines.push('| `shell_injection` | Shell command injection patterns (backticks, `$()`, piping to shell) |');
  lines.push('| `path_traversal` | Directory traversal patterns (`../`) that can escape intended directories |');
  lines.push('| `script_injection` | HTML/JavaScript injection (`<script>`, `javascript:`, event handlers) |');
  lines.push('| `template_injection` | Template/expression injection that may evaluate in workflow contexts |');
  lines.push('');

  return lines.join('\n');
}

/**
 * Main entry point for the GitHub Action.
 */
async function run() {
  try {
    const eventPath = process.env.GITHUB_EVENT_PATH;

    if (!eventPath) {
      core.warning('GITHUB_EVENT_PATH is not set. No event data to scan.');
      return;
    }

    if (!fs.existsSync(eventPath)) {
      core.warning(`Event file not found at: ${eventPath}`);
      return;
    }

    let eventData;
    try {
      const raw = fs.readFileSync(eventPath, 'utf8');
      eventData = JSON.parse(raw);
    } catch (parseError) {
      core.setFailed(`Failed to parse event payload: ${parseError.message}`);
      return;
    }

    core.info('Scanning GitHub Actions event payload for attack vectors…');

    const findings = scanValue(eventData);

    const summary = buildSummary(findings);

    const summaryFile = process.env.GITHUB_STEP_SUMMARY;
    if (summaryFile) {
      fs.appendFileSync(summaryFile, summary);
    }

    if (findings.length === 0) {
      core.info('Security scan complete: No threats detected.');
    } else {
      const totalIssues = findings.reduce((sum, f) => sum + f.results.length, 0);

      for (const finding of findings) {
        for (const result of finding.results) {
          const countNote = result.count ? ` (×${result.count})` : '';
          core.error(
            `[${result.type}] ${finding.path}: ${truncate(result.description)}${countNote}`,
          );
        }
      }

      core.setFailed(
        `Security scan failed: ${totalIssues} potential attack vector(s) found in ${findings.length} field(s). See the step summary for details.`,
      );
    }
  } catch (error) {
    core.setFailed(`Action failed with unexpected error: ${error.message}`);
  }
}

run();
