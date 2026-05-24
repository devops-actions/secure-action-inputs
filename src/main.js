'use strict';

const fs = require('fs');
const https = require('https');
const { scanValue, scanString } = require('./scanner');

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
 * Reads a boolean action input from the environment.
 * Follows the same env-var convention as @actions/core: INPUT_{UPPERCASED_NAME}.
 * Any value other than the string "false" (case-insensitive) is treated as true.
 * @param {string} name - Input name as defined in action.yml.
 * @param {boolean} defaultValue - Value to return when the input is not set.
 * @returns {boolean}
 */
function getBooleanInput(name, defaultValue = false) {
  const envName = `INPUT_${name.replace(/ /g, '_').toUpperCase()}`;
  const val = process.env[envName];
  if (val === undefined || val === '') return defaultValue;
  return val.toLowerCase() !== 'false';
}

/**
 * Reads a string action input from the environment.
 * @param {string} name - Input name as defined in action.yml.
 * @param {string} defaultValue - Value to return when the input is not set.
 * @returns {string}
 */
function getInput(name, defaultValue = '') {
  const envName = `INPUT_${name.replace(/ /g, '_').toUpperCase()}`;
  return (process.env[envName] || defaultValue).trim();
}

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
 * Escapes HTML special characters to prevent injection in <pre><code> blocks.
 * @param {string} text - The text to escape.
 * @returns {string} HTML-safe text.
 */
function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Builds a <details> context snippet for a single finding.
 * Locates the matching line within the field value and shows up to 2 lines of
 * surrounding context to help identify exactly where the issue appears.
 * @param {Object} finding - Finding object with path, results, and value.
 * @returns {string} Markdown/HTML <details> block, or empty string if not applicable.
 */
function buildContextSnippet(finding) {
  const { path, results, value } = finding;
  if (!value || typeof value !== 'string') return '';

  const lines = value.split('\n');
  const targetType = results[0].type;

  // Re-scan individual lines to locate the first line that triggered this finding type.
  let matchLineIndex = 0;
  for (let i = 0; i < lines.length; i++) {
    const lineResults = scanString(lines[i]);
    if (lineResults.some((r) => r.type === targetType)) {
      matchLineIndex = i;
      break;
    }
  }

  const start = Math.max(0, matchLineIndex - 2);
  const end = Math.min(lines.length - 1, matchLineIndex + 2);
  const contextLines = lines.slice(start, end + 1);

  const locationInfo =
    lines.length > 1 ? `line ${matchLineIndex + 1} of ${lines.length}` : 'single-line value';

  // HTML-escape and truncate each context line to prevent injection or runaway output.
  const displayLines = contextLines.map((line) => {
    const safe = escapeHtml(line.length > 200 ? line.slice(0, 200) + '…' : line);
    // Mark the matched line with an arrow prefix for easy visual identification.
    return start + contextLines.indexOf(line) === matchLineIndex ? `▶ ${safe}` : `  ${safe}`;
  });

  return [
    '<details>',
    `<summary>📍 Location: <code>${escapeHtml(path)}</code> — ${locationInfo}</summary>`,
    '',
    '<pre><code>',
    displayLines.join('\n'),
    '</code></pre>',
    '',
    '</details>',
    '',
  ].join('\n');
}

/**
 * Central legend for all known attack types.
 * Only entries whose type appears in the actual findings are included in the summary.
 */
const LEGEND = {
  hidden_unicode:
    '`hidden_unicode` | Invisible Unicode characters (zero-width spaces, BOM, null bytes, Unicode Tag Characters U+E0000–E007F for AI instruction embedding, Variation Selectors Supplement U+E0100–E01EF for Glassworm attacks) that can hide malicious content',
  bidi_attack:
    '`bidi_attack` | Bidirectional text control characters (Trojan Source) that alter how code is visually rendered',
  homoglyph:
    '`homoglyph` | Lookalike characters from Cyrillic, Greek, or fullwidth Latin scripts that visually impersonate ASCII letters (IDN homograph / supply-chain spoofing)',
  shell_injection:
    '`shell_injection` | Shell command injection patterns (backticks, `$()`, piping to shell executables)',
  path_traversal:
    '`path_traversal` | Directory traversal patterns (`../`) that can escape intended directories',
  script_injection:
    '`script_injection` | HTML/JavaScript injection (`<script>`, `javascript:`, event handlers)',
  template_injection:
    '`template_injection` | Template/expression injection that may evaluate in workflow contexts',
  prompt_injection:
    '`prompt_injection` | AI/LLM override phrases designed to manipulate AI assistants that process event data',
};

/**
 * Builds the markdown summary content for the step summary or PR comment.
 * @param {Array} findings - Array of { path, results, value } finding objects.
 * @param {boolean} showContext - Whether to include per-finding context snippets.
 * @returns {string} Markdown summary.
 */
function buildSummary(findings, showContext = true) {
  if (findings.length === 0) {
    return [
      '## 🛡️ Secure Action Inputs — Security Scan Results',
      '',
      '✅ **No security threats detected in the GitHub Actions event payload.**',
      '',
    ].join('\n');
  }

  const totalIssues = findings.reduce((sum, f) => sum + f.results.length, 0);
  const foundTypes = new Set(findings.flatMap((f) => f.results.map((r) => r.type)));

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
    if (showContext) {
      lines.push(buildContextSnippet(finding));
    }
  }

  lines.push('');
  lines.push('### Attack Types Legend');
  lines.push('');
  lines.push('| Type | Description |');
  lines.push('|------|-------------|');
  for (const [type, description] of Object.entries(LEGEND)) {
    if (foundTypes.has(type)) {
      lines.push(`| ${description} |`);
    }
  }
  lines.push('');

  return lines.join('\n');
}

/**
 * Makes an HTTPS request to the GitHub API.
 * @param {string} method - HTTP method.
 * @param {string} urlPath - API path (e.g. /repos/owner/repo/issues/1/comments).
 * @param {Object|null} body - Request body (JSON-serialised) or null.
 * @param {string} token - GitHub token for authorisation.
 * @returns {Promise<{status: number, data: Object}>}
 */
function apiRequest(method, urlPath, body, token) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: urlPath,
      method,
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'User-Agent': 'devops-actions/secure-action-inputs',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    };

    let bodyStr;
    if (body) {
      bodyStr = JSON.stringify(body);
      options.headers['Content-Type'] = 'application/json';
      options.headers['Content-Length'] = Buffer.byteLength(bodyStr);
    }

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        let parsed = {};
        try {
          parsed = JSON.parse(data);
        } catch (_) {}
        resolve({ status: res.statusCode, data: parsed });
      });
    });

    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

/**
 * Searches paginated issue/PR comments for one that starts with the given marker.
 * Only matches comments authored by a Bot user to avoid false positives.
 * @param {string} owner - Repository owner.
 * @param {string} repo - Repository name.
 * @param {number} issueNumber - Issue or PR number.
 * @param {string} marker - HTML comment marker to search for.
 * @param {string} token - GitHub token.
 * @returns {Promise<number|null>} Comment ID if found, null otherwise.
 */
async function findExistingComment(owner, repo, issueNumber, marker, token) {
  for (let page = 1; page <= 3; page++) {
    const res = await apiRequest(
      'GET',
      `/repos/${owner}/${repo}/issues/${issueNumber}/comments?per_page=100&page=${page}`,
      null,
      token,
    );
    if (res.status !== 200 || !Array.isArray(res.data) || res.data.length === 0) break;
    for (const comment of res.data) {
      if (
        comment.body &&
        comment.body.startsWith(marker) &&
        comment.user &&
        comment.user.type === 'Bot'
      ) {
        return comment.id;
      }
    }
    if (res.data.length < 100) break;
  }
  return null;
}

/**
 * Posts or updates a scan-results comment on a pull request or issue.
 * If write access is unavailable the function logs a warning and returns without
 * throwing so that the security findings are still surfaced via the step summary.
 * @param {Array} findings - Scan findings (may be empty for a clean re-scan).
 * @param {Object} eventData - Parsed GitHub event payload.
 * @param {boolean} showContext - Whether the comment should include context snippets.
 */
async function postFindingsComment(findings, eventData, showContext) {
  const token = getInput('github-token');
  const repo = process.env.GITHUB_REPOSITORY;

  if (!token || !repo) {
    core.info('Skipping PR/issue comment: github-token or GITHUB_REPOSITORY not available.');
    return;
  }

  // Determine whether the event is associated with a PR or issue.
  let issueNumber;
  if (eventData.pull_request) {
    issueNumber = eventData.pull_request.number;
  } else if (eventData.issue) {
    issueNumber = eventData.issue.number;
  } else {
    core.info('Skipping PR/issue comment: event is not a pull request or issue.');
    return;
  }

  const [owner, repoName] = repo.split('/');
  const MARKER = '<!-- secure-action-inputs-scan -->';

  // Build the comment body. For a clean re-scan we still update an existing comment.
  const commentBody = MARKER + '\n' + buildSummary(findings, showContext);

  // Enforce a safe maximum length for GitHub comments (65 536-char limit).
  const MAX_COMMENT_LENGTH = 60000;
  const safeBody =
    commentBody.length > MAX_COMMENT_LENGTH
      ? commentBody.slice(0, MAX_COMMENT_LENGTH) +
        '\n\n> ⚠️ _Output truncated — see the step summary for the full report._'
      : commentBody;

  try {
    const existingId = await findExistingComment(owner, repoName, issueNumber, MARKER, token);

    let res;
    if (existingId) {
      res = await apiRequest(
        'PATCH',
        `/repos/${owner}/${repoName}/issues/comments/${existingId}`,
        { body: safeBody },
        token,
      );
    } else {
      res = await apiRequest(
        'POST',
        `/repos/${owner}/${repoName}/issues/${issueNumber}/comments`,
        { body: safeBody },
        token,
      );
    }

    if (res.status === 403) {
      core.warning(
        'Could not post scan comment: token lacks write access to issues/pull-requests. ' +
          'Add `issues: write` and `pull-requests: write` to the workflow permissions, ' +
          'or set `post-comment: false` to suppress this message.',
      );
    } else if (res.status === 404) {
      core.warning(
        'Could not post scan comment: issue/PR not found or token lacks access (HTTP 404).',
      );
    } else if (res.status >= 400) {
      core.warning(`Could not post scan comment: GitHub API returned HTTP ${res.status}.`);
    } else {
      core.info(
        existingId
          ? `Updated existing scan comment on ${repo}#${issueNumber}.`
          : `Posted scan comment on ${repo}#${issueNumber}.`,
      );
    }
  } catch (err) {
    core.warning(`Could not post scan comment: ${err.message}`);
  }
}

/**
 * Main entry point for the GitHub Action.
 */
async function run() {
  try {
    const showContext = getBooleanInput('show-context', true);
    const postComment = getBooleanInput('post-comment', true);

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

    const summary = buildSummary(findings, showContext);

    const summaryFile = process.env.GITHUB_STEP_SUMMARY;
    if (summaryFile) {
      fs.appendFileSync(summaryFile, summary);
    }

    if (postComment) {
      // Post/update a comment even on a clean scan so existing findings comments are updated.
      await postFindingsComment(findings, eventData, showContext);
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

