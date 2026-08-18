'use strict';

/**
 * Severity tiers for findings.
 * BLOCKING — the action fails the job (current behavior for all findings).
 * WARNING — reported in the step summary and as job annotations, but the job
 * succeeds. Used for context-free pattern matches in Markdown body fields
 * (e.g. "../" or "exec()" appearing in quoted upstream changelog text), where
 * the field never flows into a shell or filesystem context.
 */
const SEVERITY = { BLOCKING: 'blocking', WARNING: 'warning' };

/**
 * Returns true when a field path points to a Markdown body field:
 * "body", "pull_request.body", "comment.body", or the old-body snapshot
 * "changes.body.from". Body fields are free-form Markdown prose, so some
 * patterns (inline backticks, quoted "../", "exec()" prose) are benign there.
 * @param {string} fieldPath - Dot-notation path to the field.
 * @returns {boolean}
 */
function isMarkdownField(fieldPath) {
  return /(^|\.)body(\.|$)/.test(fieldPath);
}

/**
 * Hidden/invisible Unicode characters that can be used to obfuscate content.
 * These characters are typically invisible to the human eye but can be used
 * to hide malicious payloads or bypass security filters.
 *
 * CRITICAL additions based on known attack research:
 * - Unicode Tag Characters (U+E0000–U+E007F): Used to embed invisible AI instructions
 *   in PR titles, issue bodies, and branch names. Tokenized and followed by LLMs but
 *   completely invisible to human reviewers and GitHub's PR review UI.
 *   Reference: Pillar Security "Rules File Backdoor" (March 2025), EmbraceTheRed (Jan 2024)
 * - Variation Selectors Supplement (U+E0100–U+E01EF): The "Glassworm" attack vector
 *   that encodes hidden data inside visible text using invisible variation selectors.
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
  // CRITICAL: Unicode Tag Characters — invisible AI instruction embedding
  // Attackers encode hidden LLM directives using these chars (U+E0020–U+E007E are
  // invisible lookalikes of printable ASCII, e.g. U+E0068 = invisible 'h').
  {
    pattern: /[\u{E0000}-\u{E007F}]/gu,
    name: 'Unicode Tag Character (invisible AI instruction embedding)',
    codepoint: 'U+E0000–U+E007F',
  },
  // CRITICAL: Variation Selectors Supplement — Glassworm steganographic attack
  // Hides arbitrary data inside normal-looking text using invisible variation selectors.
  {
    pattern: /[\u{E0100}-\u{E01EF}]/gu,
    name: 'Variation Selector Supplement (Glassworm steganographic attack)',
    codepoint: 'U+E0100–U+E01EF',
  },
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
    pattern: /[;&|]\s*(rm|curl|wget|bash|sh|python|python3|perl|ruby|nc|netcat|ncat|powershell|pwsh|node)\b/i,
    name: 'Semicolon/pipe chaining to shell command',
  },
  { pattern: /\|\|\s*\w/, name: 'OR operator command chaining' },
  {
    pattern: /&&\s*(rm|curl|wget|bash|sh|python|python3|perl|ruby|node)\b/i,
    name: 'AND operator chaining to shell command',
  },
  { pattern: /\beval\s*\(/, name: 'eval() code execution', bareInMarkdown: true },
  { pattern: /\bexec\s*\(/, name: 'exec() code execution', bareInMarkdown: true },
];

/**
 * High-signal: exec()/eval() invoked with a command-like payload, e.g.
 * exec("rm -rf ..."), exec('sh -c ...'), exec(`curl ...`). This is blocking on
 * ALL fields including Markdown bodies — it is never benign prose.
 */
const EXEC_EVAL_COMMAND_PAYLOAD =
  /\b(?:exec|eval)\s*\(\s*[`'"]?\s*(rm|sh|bash|zsh|curl|wget|nc|ncat|netcat|powershell|pwsh|python3?|perl|ruby|node|cmd)\b/i;

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
 * Homoglyph (lookalike) characters from non-Latin scripts.
 * Attackers replace ASCII letters with visually identical Unicode characters
 * from other scripts (Cyrillic, Greek, fullwidth Latin) to spoof identifiers,
 * URLs, branch names, or commands while bypassing string-equality checks.
 * Common IDN homograph / supply-chain attack vector.
 */
const HOMOGLYPH_RANGES = [
  {
    // Cyrillic lowercase: а е о р с х (look like a e o p c x)
    // Cyrillic uppercase: А В Е К М Н О Р С Т Х (look like A B E K M H O P C T X)
    pattern: /[\u0430\u0435\u043E\u0440\u0441\u0445\u0410\u0412\u0415\u041A\u041C\u041D\u041E\u0420\u0421\u0422\u0425]/g,
    script: 'Cyrillic',
    description: 'Cyrillic letters visually similar to Latin ASCII (e.g. а→a, е→e, о→o, р→p, с→c, х→x)',
  },
  {
    // Greek uppercase: Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ (look like A B E Z H I K M N O P T Y X)
    // Greek lowercase: ο ν ρ (look like o v p)
    pattern: /[\u0391\u0392\u0395\u0396\u0397\u0399\u039A\u039C\u039D\u039F\u03A1\u03A4\u03A5\u03A7\u03BF\u03BD\u03C1]/g,
    script: 'Greek',
    description: 'Greek letters visually similar to Latin ASCII (e.g. Α→A, Ο→O, Ρ→P, ο→o)',
  },
  {
    // Fullwidth Latin: Ａ–Ｚ (U+FF21–U+FF3A) and ａ–ｚ (U+FF41–U+FF5A)
    pattern: /[\uFF21-\uFF3A\uFF41-\uFF5A]/g,
    script: 'Fullwidth Latin',
    description: 'Fullwidth Latin letters that look like ASCII (e.g. Ａ→A, ａ→a)',
  },
];

/**
 * Prompt injection patterns targeting AI/LLM systems.
 * Attackers craft event fields (PR titles, branch names, issue bodies, comments)
 * with directives designed to override or manipulate AI assistants that process
 * GitHub event data — for example Copilot, GitHub Actions AI steps, or any
 * workflow that feeds event payload strings into an LLM.
 * Inspired by attack patterns identified by the PromptShield project:
 * https://github.com/Zero-Harm-AI-LLC/promptshield
 */
const PROMPT_INJECTION_PATTERNS = [
  {
    pattern: /ignore\s+(all\s+)?previous\s+instructions/i,
    name: 'Ignore previous instructions override',
  },
  {
    pattern: /disregard\s+(all\s+|your\s+)?(previous\s+|prior\s+)?(instructions|system\s+prompt|rules|guidelines|constraints)/i,
    name: 'Disregard instructions override',
  },
  {
    pattern: /forget\s+(all\s+|your\s+)?(previous\s+|prior\s+)?(instructions|system\s+prompt|rules|guidelines|context)/i,
    name: 'Forget instructions override',
  },
  {
    pattern: /override\s+(the\s+|your\s+)?(previous\s+|prior\s+)?(instructions|system\s+prompt|rules|guidelines)/i,
    name: 'Override instructions attack',
  },
  {
    pattern: /\bpretend\s+you\s+are\b/i,
    name: 'Identity override (pretend you are)',
  },
  {
    pattern: /\byour\s+new\s+(task|instructions?|rules?|directive)\s+(is|are)\b/i,
    name: 'New task/instructions injection',
  },
  {
    pattern: /\bnew\s+instructions?\s*:/i,
    name: 'New instructions injection',
  },
  {
    pattern: /\bsystem\s+prompt\s*:/i,
    name: 'System prompt injection attempt',
  },
  {
    pattern: /\bjailbreak\s+(mode|prompt|bypass|override)\b|\benable\s+jailbreak\b/i,
    name: 'Jailbreak attempt',
  },
  {
    pattern: /\bDAN\s+(mode|jailbreak|prompt)\b/i,
    name: 'DAN (Do Anything Now) jailbreak',
  },
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
 * Matches the common "anti-mention" pattern used by bots like Dependabot and
 * Renovate in auto-generated changelog/release-note text: a Zero Width Space
 * inserted right after "@" and before a username (e.g. "@<ZWSP>octocat") so
 * GitHub doesn't render a clickable/notifying mention. This is a benign,
 * intentional formatting trick, not an attack, so it is excluded from the
 * Zero Width Space finding to avoid false positives on dependency-bump PRs.
 */
const ZWSP_ANTI_MENTION_PATTERN = /@\u200B(?=[A-Za-z0-9-]+\b)/g;

/**
 * Checks a string for hidden/invisible Unicode characters.
 * @param {string} text - The string to check.
 * @returns {Array} Array of finding objects.
 */
function checkHiddenUnicode(text) {
  const findings = [];
  for (const { pattern, name, codepoint } of HIDDEN_UNICODE_CHARS) {
    let scanText = text;
    if (codepoint === 'U+200B') {
      // Ignore Zero Width Spaces that are part of the "@<ZWSP>username"
      // anti-mention pattern; count/flag only the remaining occurrences.
      scanText = text.replace(ZWSP_ANTI_MENTION_PATTERN, '@');
    }
    const matches = scanText.match(pattern);
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
 * @param {string} [fieldPath] - Dot-notation path to the field (e.g. "pull_request.body").
 *   Body fields (see isMarkdownField) are Markdown prose, so the backtick
 *   command-substitution pattern is skipped there, and bare eval()/exec()
 *   mentions (e.g. "fixed a bug in exec()" in a changelog) are downgraded to
 *   WARNING. exec()/eval() with a command-like payload stays BLOCKING on all
 *   fields.
 * @returns {Array} Array of finding objects.
 */
function checkShellInjection(text, fieldPath = '') {
  const markdown = isMarkdownField(fieldPath);
  const findings = [];
  const hasCommandPayload = EXEC_EVAL_COMMAND_PAYLOAD.test(text);
  if (hasCommandPayload) {
    findings.push({
      type: 'shell_injection',
      description: 'Potential shell injection: exec()/eval() with command payload',
      severity: SEVERITY.BLOCKING,
    });
  }
  for (const { pattern, name, bareInMarkdown } of SHELL_INJECTION_PATTERNS) {
    if (markdown && name === 'Backtick command substitution') continue;
    // The command-payload finding above already covers these matches.
    if (hasCommandPayload && bareInMarkdown) continue;
    if (pattern.test(text)) {
      findings.push({
        type: 'shell_injection',
        description: `Potential shell injection: ${name}`,
        severity: markdown && bareInMarkdown ? SEVERITY.WARNING : SEVERITY.BLOCKING,
      });
    }
  }
  return findings;
}

/**
 * High-signal path traversal patterns — BLOCKING on all fields, including
 * Markdown bodies: URL-encoded/double-encoded traversal, chains of 2+
 * traversals, and traversal reaching sensitive targets.
 */
const PATH_TRAVERSAL_HIGH_SIGNAL = [
  { pattern: /%2e%2e/i, name: 'URL-encoded path traversal (%2e%2e)' },
  { pattern: /%252e/i, name: 'Double URL-encoded path traversal (%252e)' },
  { pattern: /\.\.%(2f|5c|252f|255c)/i, name: 'Mixed encoded path traversal (..%2f / ..%5c)' },
  { pattern: /(\.\.[\\/]){2,}/, name: 'Chained path traversal (../../…)' },
  {
    pattern: /(\.\.[\\/]).*(etc[\\/]passwd|\.env\b|\.ssh\b|id_rsa|node_modules)/i,
    name: 'Path traversal reaching sensitive target (/etc/passwd, .env, .ssh, id_rsa, node_modules)',
  },
];

/**
 * Checks for path traversal patterns.
 * @param {string} text - The string to check.
 * @param {string} [fieldPath] - Dot-notation path to the field. A bare "../" or
 *   "..\" in a Markdown body field (e.g. a quoted relative path in a changelog)
 *   is downgraded to WARNING; high-signal traversal (encoded, chained, or
 *   reaching sensitive targets) stays BLOCKING everywhere.
 * @returns {Array} Array of finding objects.
 */
function checkPathTraversal(text, fieldPath = '') {
  const findings = [];
  let highSignal = false;
  for (const { pattern, name } of PATH_TRAVERSAL_HIGH_SIGNAL) {
    if (pattern.test(text)) {
      highSignal = true;
      findings.push({
        type: 'path_traversal',
        description: `Path traversal pattern detected: ${name}`,
        severity: SEVERITY.BLOCKING,
      });
    }
  }
  if (!highSignal && (/\.\.\//.test(text) || /\.\.\\/.test(text))) {
    findings.push({
      type: 'path_traversal',
      description: 'Path traversal pattern detected (../ or ..\\)',
      severity: isMarkdownField(fieldPath) ? SEVERITY.WARNING : SEVERITY.BLOCKING,
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
 * Checks for homoglyph (lookalike) characters from non-Latin scripts.
 * @param {string} text - The string to check.
 * @returns {Array} Array of finding objects.
 */
function checkHomoglyphs(text) {
  const findings = [];
  for (const { pattern, script, description } of HOMOGLYPH_RANGES) {
    const matches = text.match(pattern);
    if (matches) {
      findings.push({
        type: 'homoglyph',
        description: `Homoglyph attack: ${description}`,
        count: matches.length,
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
 * Checks for AI/LLM prompt injection patterns.
 * These are phrases designed to override or manipulate AI assistants that
 * process GitHub event data (e.g. PR titles, branch names, issue bodies).
 * @param {string} text - The string to check.
 * @returns {Array} Array of finding objects.
 */
function checkPromptInjection(text) {
  const findings = [];
  for (const { pattern, name } of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      findings.push({
        type: 'prompt_injection',
        description: `Potential AI prompt injection: ${name}`,
      });
    }
  }
  return findings;
}

/**
 * Scans a string value for all known attack vectors.
 * @param {string} text - The string to scan.
 * @param {string} [fieldPath] - Dot-notation path to the field, forwarded to checks that
 *   need field context (e.g. to skip backtick detection on Markdown body fields).
 * @returns {Array} Array of finding objects.
 */
function scanString(text, fieldPath = '') {
  const findings = [];
  findings.push(...checkHiddenUnicode(text));
  findings.push(...checkBidiAttack(text));
  findings.push(...checkShellInjection(text, fieldPath));
  findings.push(...checkPathTraversal(text, fieldPath));
  findings.push(...checkScriptInjection(text));
  findings.push(...checkHomoglyphs(text));
  findings.push(...checkTemplateInjection(text));
  findings.push(...checkPromptInjection(text));
  // All other checks are high-signal and stay blocking on every field.
  for (const finding of findings) {
    if (!finding.severity) finding.severity = SEVERITY.BLOCKING;
  }
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
    const results = scanString(value, path);
    if (results.length > 0) {
      findings.push({ path, results, value });
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
  SEVERITY,
  isMarkdownField,
  scanString,
  scanValue,
  checkHiddenUnicode,
  checkBidiAttack,
  checkShellInjection,
  checkPathTraversal,
  checkScriptInjection,
  checkHomoglyphs,
  checkTemplateInjection,
  checkPromptInjection,
};
