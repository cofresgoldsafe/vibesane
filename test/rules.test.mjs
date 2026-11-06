import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  SECRET_RULES,
  KNOWN_SECRET_PREFIXES,
  STRIPE_SECRET_RE,
  GOOGLE_API_KEY_RE,
  PROVIDER_TOKEN_RE,
  ENV_SECRET_RE,
  DATABASE_URL_RE,
  PASSWORD_FIELD_RE,
  PEM_PRIVATE_KEY_RE,
  INLINE_CONN_URI_RE,
  EXTRA_TOKENS_RE,
} from '../dist/rules/secrets.js';
import { MASKED_ERROR_RULES } from '../dist/rules/masked-errors.js';
import {
  scanSecrets,
  detectMaskedError,
  sanitizeSecretsInText,
} from '../dist/scanner/security-scan.js';

describe('declarative catalog contract (SECRET_RULES & MASKED_ERROR_RULES)', () => {
  it('enforces unique rule IDs across SECRET_RULES and MASKED_ERROR_RULES', () => {
    const secretIds = SECRET_RULES.map((r) => r.id);
    const maskedIds = MASKED_ERROR_RULES.map((r) => r.id);
    assert.equal(new Set(secretIds).size, secretIds.length, 'SECRET_RULES IDs must be unique');
    assert.equal(new Set(maskedIds).size, maskedIds.length, 'MASKED_ERROR_RULES IDs must be unique');

    const combined = [...secretIds, ...maskedIds];
    assert.equal(
      new Set(combined).size,
      combined.length,
      'Rule IDs across SECRET_RULES and MASKED_ERROR_RULES must not collide',
    );
  });

  it('requires global (g) flag and forbids sticky (y) flag on every SECRET_RULES regex and exported engine regex', () => {
    for (const rule of SECRET_RULES) {
      assert.equal(
        rule.regex.global,
        true,
        `Rule ${rule.id} regex must include the global ('g') flag to avoid infinite while(exec) loops`,
      );
      assert.equal(
        rule.regex.sticky,
        false,
        `Rule ${rule.id} regex must not include the sticky ('y') flag`,
      );
    }

    const exportedEngineRegexes = [
      ['STRIPE_SECRET_RE', STRIPE_SECRET_RE],
      ['GOOGLE_API_KEY_RE', GOOGLE_API_KEY_RE],
      ['PROVIDER_TOKEN_RE', PROVIDER_TOKEN_RE],
      ['ENV_SECRET_RE', ENV_SECRET_RE],
      ['DATABASE_URL_RE', DATABASE_URL_RE],
      ['PASSWORD_FIELD_RE', PASSWORD_FIELD_RE],
      ['PEM_PRIVATE_KEY_RE', PEM_PRIVATE_KEY_RE],
      ['INLINE_CONN_URI_RE', INLINE_CONN_URI_RE],
      ['EXTRA_TOKENS_RE', EXTRA_TOKENS_RE],
    ];

    for (const [name, re] of exportedEngineRegexes) {
      assert.equal(re.global, true, `Exported regex ${name} must include the global ('g') flag`);
      assert.equal(re.sticky, false, `Exported regex ${name} must not include the sticky ('y') flag`);
    }
  });

  it('derives KNOWN_SECRET_PREFIXES strictly from SECRET_RULES', () => {
    const expectedPrefixes = [
      ['sk', '_live_'].join(''),
      ['sk', '_test_'].join(''),
      ['rk', '_live_'].join(''),
      ['rk', '_test_'].join(''),
      ['AIza', 'Sy'].join(''),
      ['ghp', '_'].join(''),
      ['sk-', 'proj-'].join(''),
      ['sk-', 'ant-'].join(''),
    ];
    assert.deepEqual([...KNOWN_SECRET_PREFIXES], expectedPrefixes);

    const derivedFromRules = SECRET_RULES.flatMap((r) => r.tokenPrefixes ?? []);
    assert.deepEqual([...KNOWN_SECRET_PREFIXES], derivedFromRules);
  });

  it('preserves exact v0.1.1 static and dynamic labels in SECRET_RULES', () => {
    const byId = new Map(SECRET_RULES.map((r) => [r.id, r]));

    assert.equal(byId.get('stripe-secret-key')?.label, 'Stripe secret key');
    assert.equal(byId.get('google-api-key')?.label, 'Google API key');
    assert.equal(byId.get('database-url')?.label, 'DATABASE_URL');

    const providerRule = byId.get('provider-tokens');
    assert.equal(typeof providerRule?.label, 'function');
    const ghpSample = `const t = "${['ghp', '_', '1234567890abcdefghij1234'].join('')}";`;
    const oaiSample = `const t = "${['sk-', 'proj-', '1234567890abcdef1234'].join('')}";`;
    const antSample = `const t = "${['sk-', 'ant-', '1234567890abcdef1234'].join('')}";`;

    for (const [sample, expectedLabel] of [
      [ghpSample, 'GitHub token'],
      [oaiSample, 'OpenAI API key'],
      [antSample, 'Anthropic API key'],
    ]) {
      providerRule.regex.lastIndex = 0;
      const m = providerRule.regex.exec(sample);
      assert.ok(m, `Expected provider-tokens regex to match ${expectedLabel}`);
      assert.equal(providerRule.label(m), expectedLabel);
    }

    const envRule = byId.get('env-secret');
    assert.equal(typeof envRule?.label, 'function');
    envRule.regex.lastIndex = 0;
    const envMatch = envRule.regex.exec('const JWT_SECRET = "super_secret_val_99";');
    assert.ok(envMatch);
    assert.equal(envRule.label(envMatch), 'JWT_SECRET');

    const pwdRule = byId.get('hardcoded-password');
    assert.equal(typeof pwdRule?.label, 'function');
    for (const [field, expectedLabel] of [
      ['password', 'Hardcoded password'],
      ['passwd', 'Hardcoded passwd'],
      ['pwd', 'Hardcoded pwd'],
      ['senha', 'Hardcoded senha'],
    ]) {
      pwdRule.regex.lastIndex = 0;
      const m = pwdRule.regex.exec(`const cfg = { ${field}: "RealPass99!" };`);
      assert.ok(m, `Expected password-field regex to match ${field}`);
      assert.equal(pwdRule.label(m), expectedLabel);
    }
  });

  it('preserves all 10 MASKED_ERROR_RULES labels in the exact v0.1.1 order', () => {
    const expectedLabels = [
      'nextjs__container_errors',
      'Unhandled Runtime Error',
      'Application error: a client-side exception has occurred',
      '__next_error__',
      '<nextjs-portal',
      '__NEXT_DATA__ error payload',
      'vite-error-overlay',
      '[plugin:vite:',
      'Pre-transform error:',
      'HTML 500 / Internal Server Error heading',
    ];
    assert.deepEqual(
      MASKED_ERROR_RULES.map((r) => r.label),
      expectedLabels,
    );
  });
});

describe('automated rule examples verification', () => {
  it('validates shouldDetect and shouldIgnore examples for every SECRET_RULES entry', () => {
    for (const rule of SECRET_RULES) {
      assert.ok(
        Array.isArray(rule.examples?.shouldDetect) && rule.examples.shouldDetect.length >= 1,
        `Rule ${rule.id} must have at least 1 shouldDetect example`,
      );
      assert.ok(
        Array.isArray(rule.examples?.shouldIgnore) && rule.examples.shouldIgnore.length >= 1,
        `Rule ${rule.id} must have at least 1 shouldIgnore example`,
      );

      for (const sample of rule.examples.shouldDetect) {
        rule.regex.lastIndex = 0;
        const match = rule.regex.exec(sample);
        assert.ok(match, `Rule ${rule.id} regex failed to match shouldDetect sample: ${sample}`);
        const expectedLabel = typeof rule.label === 'function' ? rule.label(match) : rule.label;

        const issues = scanSecrets(sample, '/src/sample.ts');
        assert.ok(
          issues.length >= 1,
          `scanSecrets returned no issues for rule ${rule.id} sample: ${sample}`,
        );
        assert.ok(
          issues.some(
            (issue) =>
              issue.kind === 'secret_leak' && issue.detail.includes(`: ${expectedLabel} (`),
          ),
          `Expected issue with label "${expectedLabel}" for rule ${rule.id}, got: ${JSON.stringify(issues)}`,
        );
      }

      for (const sample of rule.examples.shouldIgnore) {
        const issues = scanSecrets(sample, '/src/sample.ts');
        if (rule.id === 'env-secret' && sample.includes(['sk', '_live_'].join(''))) {
          assert.equal(issues.length, 1);
          assert.match(issues[0].detail, /Stripe secret key/);
          assert.doesNotMatch(issues[0].detail, /STRIPE_SECRET/);
        } else {
          assert.equal(
            issues.length,
            0,
            `Expected scanSecrets to ignore sample for rule ${rule.id}: ${sample}, got: ${JSON.stringify(issues)}`,
          );
        }
      }
    }
  });

  it('validates shouldDetect and shouldIgnore examples for every MASKED_ERROR_RULES entry', () => {
    for (const rule of MASKED_ERROR_RULES) {
      assert.ok(
        Array.isArray(rule.examples?.shouldDetect) && rule.examples.shouldDetect.length >= 1,
        `Rule ${rule.id} must have at least 1 shouldDetect example`,
      );
      assert.ok(
        Array.isArray(rule.examples?.shouldIgnore) && rule.examples.shouldIgnore.length >= 1,
        `Rule ${rule.id} must have at least 1 shouldIgnore example`,
      );

      for (const sample of rule.examples.shouldDetect) {
        assert.equal(
          rule.matches(sample),
          true,
          `Expected rule ${rule.id}.matches() to be true for: ${sample}`,
        );
        const issues = detectMaskedError(sample, '/');
        assert.equal(issues.length, 1);
        assert.equal(issues[0].kind, 'masked_error');
        assert.equal(issues[0].maskedSnippet, rule.label);
      }

      for (const sample of rule.examples.shouldIgnore) {
        assert.equal(
          rule.matches(sample),
          false,
          `Expected rule ${rule.id}.matches() to be false for: ${sample}`,
        );
      }
    }
  });
});

describe('behavioral equivalence with v0.1.1 (provider-tokens order & sanitizeSecretsInText)', () => {
  it('preserves positional order when sk-ant- appears before ghp_ and sk-proj-', () => {
    const antToken = ['sk-', 'ant-', 'api03_abcdefghij1234567890'].join('');
    const ghpToken = ['ghp', '_', '1234567890abcdefghij1234'].join('');
    const oaiToken = ['sk-', 'proj-', '1234567890abcdef1234'].join('');

    const source = [
      `const first = "${antToken}";`,
      `const second = "${ghpToken}";`,
      `const third = "${oaiToken}";`,
    ].join('\n');

    const issues = scanSecrets(source, '/src/tokens.ts');
    assert.equal(issues.length, 3);
    assert.match(issues[0].detail, /Anthropic API key/);
    assert.match(issues[1].detail, /GitHub token/);
    assert.match(issues[2].detail, /OpenAI API key/);
  });

  it('maintains fixed sanitization order and v0.1.1 conditions in sanitizeSecretsInText', () => {
    const pemBlock = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEA1234567890',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n');
    const inlineUri = ['postgres://admin:', 'SuperSecretDbPass99', '@db.internal:5432/prod'].join(
      '',
    );
    const customEnvSecret = 'WEBHOOK_SECRET="my_webhook_secret_token_99"';
    const htmlAttrPassword = '<input type="password" placeholder="password: \\"AdminPass99!\\"" />';

    const raw = [pemBlock, `URI=${inlineUri}`, customEnvSecret, htmlAttrPassword].join('\n');
    const sanitized = sanitizeSecretsInText(raw);

    assert.ok(sanitized.includes('[REDACTED PRIVATE KEY]'));
    assert.ok(sanitized.includes('postgres://admin:****@db.internal:5432/prod'));
    assert.ok(!sanitized.includes('SuperSecretDbPass99'));
    assert.ok(sanitized.includes('WEBHOOK_SECRET="my_****99"'));
    assert.ok(!sanitized.includes('my_webhook_secret_token_99'));
    assert.ok(sanitized.includes('A***'));
    assert.ok(!sanitized.includes('AdminPass99!'));
  });
});
