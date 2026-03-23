/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ 863:
/***/ ((module) => {



/**
 * Hidden/invisible Unicode characters that can be used to obfuscate content.
 * These characters are typically invisible to the human eye but can be used
 * to hide malicious payloads or bypass security filters.
 */
const HIDDEN_UNICODE_CHARS = [
  { pattern: /\u200B/g, name: 'Zero Width Space', codepoint: 'U+200B' },
  { pattern: /\u200C/g, name: 'Zero Width Non-Joiner', codepoint: 'U+200C' },
  { pattern: /\u200D/g, name: 'Zero Width Joiner', codepoint: 'U+200D' },
  { pattern: /\uFEFF/g, name: 'Zero Width No-Break Space / BOM', codepoint: 'U+FEFF' },
  { pattern: /\u00AD/g, name: 'Soft Hyphen', codepoint: 'U+00AD' },
  { pattern: /\u200E/g, name: 'Left-to-Right Mark', codepoint: 'U+200E' },
  { pattern: /\u200F/g, name: 'Right-to-Left Mark', codepoint: 'U+200F' },
  { pattern: /\u2060/g, name: 'Word Joiner', codepoint: 'U+2060' },
  { pattern: /\u180E/g, name: 'Mongolian Vowel Separator', codepoint: 'U+180E' },
  { pattern: /\u0000/g, name: 'Null Character', codepoint: 'U+0000' },
  { pattern: /\u2028/g, name: 'Line Separator', codepoint: 'U+2028' },
  { pattern: /\u2029/g, name: 'Paragraph Separator', codepoint: 'U+2029' },
  { pattern: /\uFFFC/g, name: 'Object Replacement Character', codepoint: 'U+FFFC' },
];

/**
 * Bidirectional Unicode control characters used in Trojan Source attacks.
 * These characters alter the visual rendering of code, making malicious code
 * appear as comments or strings to human reviewers.
 * See: https://trojansource.codes/
 */
const BIDI_CHARS = [
  { pattern: /\u202A/g, name: 'Left-to-Right Embedding', codepoint: 'U+202A' },
  { pattern: /\u202B/g, name: 'Right-to-Left Embedding', codepoint: 'U+202B' },
  { pattern: /\u202C/g, name: 'Pop Directional Formatting', codepoint: 'U+202C' },
  { pattern: /\u202D/g, name: 'Left-to-Right Override', codepoint: 'U+202D' },
  { pattern: /\u202E/g, name: 'Right-to-Left Override', codepoint: 'U+202E' },
  { pattern: /\u2066/g, name: 'Left-to-Right Isolate', codepoint: 'U+2066' },
  { pattern: /\u2067/g, name: 'Right-to-Left Isolate', codepoint: 'U+2067' },
  { pattern: /\u2068/g, name: 'First Strong Isolate', codepoint: 'U+2068' },
  { pattern: /\u2069/g, name: 'Pop Directional Isolate', codepoint: 'U+2069' },
  { pattern: /\u061C/g, name: 'Arabic Letter Mark', codepoint: 'U+061C' },
];

/**
 * Shell injection patterns that may indicate command injection attempts.
 * These are particularly dangerous in fields like branch names or PR titles
 * that might be interpolated into shell commands in workflows.
 */
const SHELL_INJECTION_PATTERNS = [
  { pattern: /`[^`]+`/, name: 'Backtick command substitution' },
  { pattern: /\$\([^)]+\)/, name: 'Dollar-paren command substitution $()' },
  {
    pattern: /[;&|]\s*(rm|curl|wget|bash|sh|python|python3|perl|ruby|nc|netcat|ncat|powershell|pwsh)\b/i,
    name: 'Semicolon/pipe chaining to shell command',
  },
  { pattern: /\|\|\s*\w/, name: 'OR operator command chaining' },
  { pattern: /&&\s*(rm|curl|wget|bash|sh|python|python3|perl|ruby)\b/i, name: 'AND operator chaining to shell command' },
];

/**
 * Script injection patterns such as HTML/JS injection.
 */
const SCRIPT_INJECTION_PATTERNS = [
  { pattern: /<script[^>]*>/i, name: 'HTML script tag' },
  { pattern: /javascript\s*:/i, name: 'JavaScript protocol handler' },
  { pattern: /on\w+\s*=\s*["']?\s*\w+\s*\(/i, name: 'HTML event handler attribute' },
  { pattern: /<iframe[^>]*>/i, name: 'HTML iframe injection' },
  { pattern: /<img[^>]+onerror\s*=/i, name: 'Image onerror handler injection' },
];

/**
 * Template/expression injection patterns.
 * These can be used to escape template contexts or inject expressions.
 */
const TEMPLATE_INJECTION_PATTERNS = [
  { pattern: /\$\{\{/, name: 'GitHub Actions expression injection ${{' },
  { pattern: /\{\{[^}]+\}\}/, name: 'Template expression injection {{...}}' },
];

/**
 * Checks a string for hidden/invisible Unicode characters.
 * @param {string} text - The string to check.
 * @returns {Array} Array of finding objects.
 */
function checkHiddenUnicode(text) {
  const findings = [];
  for (const { pattern, name, codepoint } of HIDDEN_UNICODE_CHARS) {
    const matches = text.match(pattern);
    if (matches) {
      findings.push({
        type: 'hidden_unicode',
        description: `Hidden Unicode character: ${name} (${codepoint})`,
        count: matches.length,
      });
    }
  }
  return findings;
}

/**
 * Checks for bidirectional text attacks (Trojan Source).
 * @param {string} text - The string to check.
 * @returns {Array} Array of finding objects.
 */
function checkBidiAttack(text) {
  const findings = [];
  for (const { pattern, name, codepoint } of BIDI_CHARS) {
    const matches = text.match(pattern);
    if (matches) {
      findings.push({
        type: 'bidi_attack',
        description: `Bidirectional text (Trojan Source) attack: ${name} (${codepoint})`,
        count: matches.length,
      });
    }
  }
  return findings;
}

/**
 * Checks for shell injection patterns.
 * @param {string} text - The string to check.
 * @returns {Array} Array of finding objects.
 */
function checkShellInjection(text) {
  const findings = [];
  for (const { pattern, name } of SHELL_INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      findings.push({
        type: 'shell_injection',
        description: `Potential shell injection: ${name}`,
      });
    }
  }
  return findings;
}

/**
 * Checks for path traversal patterns.
 * @param {string} text - The string to check.
 * @returns {Array} Array of finding objects.
 */
function checkPathTraversal(text) {
  const findings = [];
  if (/\.\.\//.test(text) || /\.\.\\/.test(text)) {
    findings.push({
      type: 'path_traversal',
      description: 'Path traversal pattern detected (../ or ..\\)',
    });
  }
  return findings;
}

/**
 * Checks for script/HTML injection patterns.
 * @param {string} text - The string to check.
 * @returns {Array} Array of finding objects.
 */
function checkScriptInjection(text) {
  const findings = [];
  for (const { pattern, name } of SCRIPT_INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      findings.push({
        type: 'script_injection',
        description: `Potential script injection: ${name}`,
      });
    }
  }
  return findings;
}

/**
 * Checks for template/expression injection patterns.
 * @param {string} text - The string to check.
 * @returns {Array} Array of finding objects.
 */
function checkTemplateInjection(text) {
  const findings = [];
  for (const { pattern, name } of TEMPLATE_INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      findings.push({
        type: 'template_injection',
        description: `Potential template/expression injection: ${name}`,
      });
    }
  }
  return findings;
}

/**
 * Scans a string value for all known attack vectors.
 * @param {string} text - The string to scan.
 * @returns {Array} Array of finding objects.
 */
function scanString(text) {
  const findings = [];
  findings.push(...checkHiddenUnicode(text));
  findings.push(...checkBidiAttack(text));
  findings.push(...checkShellInjection(text));
  findings.push(...checkPathTraversal(text));
  findings.push(...checkScriptInjection(text));
  findings.push(...checkTemplateInjection(text));
  return findings;
}

/**
 * Recursively scans an object or value for attack vectors in all string fields.
 * @param {*} value - The value to scan (string, array, or object).
 * @param {string} path - The dot-notation path to the current value.
 * @param {Array} findings - Accumulated findings array.
 * @returns {Array} Array of objects with { path, results } for each affected field.
 */
function scanValue(value, path = '', findings = []) {
  if (typeof value === 'string') {
    const results = scanString(value);
    if (results.length > 0) {
      findings.push({ path, results });
    }
  } else if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      scanValue(value[i], `${path}[${i}]`, findings);
    }
  } else if (value !== null && typeof value === 'object') {
    for (const key of Object.keys(value)) {
      scanValue(value[key], path ? `${path}.${key}` : key, findings);
    }
  }
  return findings;
}

module.exports = {
  scanString,
  scanValue,
  checkHiddenUnicode,
  checkBidiAttack,
  checkShellInjection,
  checkPathTraversal,
  checkScriptInjection,
  checkTemplateInjection,
};


/***/ }),

/***/ 896:
/***/ ((module) => {

module.exports = require("fs");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};


const fs = __nccwpck_require__(896);
const { scanValue } = __nccwpck_require__(863);

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

module.exports = __webpack_exports__;
/******/ })()
;