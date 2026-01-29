// Secrets & Credentials Detection Rules
// Covers: AWS keys, private keys, JWT tokens, database connection strings

import type { Finding, FindingCategory, FindingSeverity } from '@/types/scanner';

// ========== SHARED HELPERS ==========

function extractSnippet(content: string, matchIndex: number, matchLength: number): string {
  const start = Math.max(0, matchIndex - 30);
  const end = Math.min(content.length, matchIndex + matchLength + 50);
  let snippet = content.substring(start, end);
  if (start > 0) snippet = '...' + snippet;
  if (end < content.length) snippet = snippet + '...';
  return snippet.substring(0, 200);
}

function redactSecret(secret: string): string {
  if (secret.length <= 8) return '***REDACTED***';
  return secret.substring(0, 4) + '***REDACTED***' + secret.substring(secret.length - 4);
}

// ========== AWS CREDENTIALS ==========

/**
 * Detect exposed AWS credentials
 */
export function detectAWSCredentials(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Skip test/mock files
  if (/\.(test|spec|mock)\./i.test(filePath) || /fixtures?|mocks?|examples?/i.test(filePath)) {
    return findings;
  }
  
  // AWS Access Key ID patterns
  const accessKeyPatterns = [
    /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g, // Standard AWS keys
  ];
  
  for (const pattern of accessKeyPatterns) {
    const matches = content.matchAll(pattern);
    for (const match of matches) {
      findings.push({
        id: 'secrets-aws-access-key',
        category: 'SECRETS' as FindingCategory,
        severity: 'critical' as FindingSeverity,
        scoreDelta: 45,
        file: filePath,
        evidence: {
          snippet: `AWS Access Key: ${redactSecret(match[0])}`,
          note: 'AWS Access Key ID detected in source code',
        },
        remediation: 'Remove AWS credentials from code. Use environment variables or IAM roles.',
      });
    }
  }
  
  // AWS Secret Access Key patterns (40-char base64-ish)
  const secretKeyMatch = content.match(/(?:aws_secret_access_key|secret_?key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i);
  if (secretKeyMatch) {
    findings.push({
      id: 'secrets-aws-secret-key',
      category: 'SECRETS' as FindingCategory,
      severity: 'critical' as FindingSeverity,
      scoreDelta: 45,
      file: filePath,
      evidence: {
        snippet: `AWS Secret Key: ${redactSecret(secretKeyMatch[1])}`,
        note: 'AWS Secret Access Key detected in source code',
      },
      remediation: 'Remove AWS credentials from code. Rotate the exposed key immediately.',
    });
  }
  
  return findings;
}

// ========== PRIVATE KEYS ==========

/**
 * Detect exposed private keys (RSA, ECDSA, Ed25519, etc.)
 */
export function detectPrivateKeys(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Skip example/template files
  if (/example|sample|template|\.example\./i.test(filePath)) {
    return findings;
  }
  
  const privateKeyPatterns = [
    { pattern: /-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----/i, type: 'RSA' },
    { pattern: /-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----/i, type: 'DSA' },
    { pattern: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----/i, type: 'ECDSA' },
    { pattern: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/i, type: 'OpenSSH' },
    { pattern: /-----BEGIN\s+PRIVATE\s+KEY-----/i, type: 'Generic' },
    { pattern: /-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----/i, type: 'Encrypted' },
    { pattern: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/i, type: 'PGP' },
  ];
  
  for (const { pattern, type } of privateKeyPatterns) {
    const match = content.match(pattern);
    if (match) {
      const severity = type === 'Encrypted' ? 'medium' : 'critical';
      findings.push({
        id: 'secrets-private-key',
        category: 'SECRETS' as FindingCategory,
        severity: severity as FindingSeverity,
        scoreDelta: severity === 'critical' ? 45 : 20,
        file: filePath,
        evidence: {
          snippet: `${type} Private Key detected`,
          note: `${type} private key found in source code`,
        },
        remediation: type === 'Encrypted' 
          ? 'Encrypted private keys are safer, but still should not be in code.'
          : 'CRITICAL: Remove private key from code immediately. Rotate the key.',
      });
      break; // One finding per file is enough
    }
  }
  
  return findings;
}

// ========== JWT TOKENS ==========

/**
 * Detect exposed JWT tokens
 */
export function detectJWTTokens(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Skip test files
  if (/\.(test|spec)\./i.test(filePath)) {
    return findings;
  }
  
  // JWT pattern: base64.base64.base64
  const jwtPattern = /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+/g;
  
  const matches = content.matchAll(jwtPattern);
  for (const match of matches) {
    const jwt = match[0];
    
    // Try to decode the payload to check for suspicious claims
    try {
      const payloadB64 = jwt.split('.')[1];
      const payload = atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'));
      const claims = JSON.parse(payload);
      
      // Check for admin/elevated privileges
      const hasElevated = 
        claims.admin === true ||
        claims.role === 'admin' ||
        claims.roles?.includes('admin') ||
        claims.scope?.includes('admin');
      
      // Check if token is expired (might be test data)
      const isExpired = claims.exp && claims.exp * 1000 < Date.now();
      
      if (!isExpired) {
        findings.push({
          id: 'secrets-jwt-token',
          category: 'SECRETS' as FindingCategory,
          severity: hasElevated ? 'critical' : 'high' as FindingSeverity,
          scoreDelta: hasElevated ? 40 : 25,
          file: filePath,
          evidence: {
            snippet: `JWT: ${redactSecret(jwt)}`,
            note: hasElevated 
              ? 'JWT with admin/elevated privileges found in code'
              : 'Valid JWT token found in code',
          },
          remediation: 'Remove JWT tokens from code. These should be obtained at runtime.',
        });
      }
    } catch {
      // Invalid JWT, still flag it
      findings.push({
        id: 'secrets-jwt-token',
        category: 'SECRETS' as FindingCategory,
        severity: 'medium' as FindingSeverity,
        scoreDelta: 15,
        file: filePath,
        evidence: {
          snippet: `JWT-like token: ${redactSecret(jwt)}`,
          note: 'JWT-like token found in code',
        },
        remediation: 'Review this token. It appears to be a JWT.',
      });
    }
    break; // One finding per file
  }
  
  return findings;
}

// ========== DATABASE CONNECTION STRINGS ==========

/**
 * Detect exposed database connection strings
 */
export function detectDatabaseSecrets(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Skip example files
  if (/example|sample|template|\.example\./i.test(filePath)) {
    return findings;
  }
  
  const dbPatterns = [
    { pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^/\s]+/i, type: 'MongoDB' },
    { pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^/\s]+/i, type: 'PostgreSQL' },
    { pattern: /mysql:\/\/[^:]+:[^@]+@[^/\s]+/i, type: 'MySQL' },
    { pattern: /redis:\/\/[^:]+:[^@]+@[^/\s]+/i, type: 'Redis' },
    { pattern: /amqp:\/\/[^:]+:[^@]+@[^/\s]+/i, type: 'RabbitMQ' },
  ];
  
  for (const { pattern, type } of dbPatterns) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        id: 'secrets-database-uri',
        category: 'SECRETS' as FindingCategory,
        severity: 'critical' as FindingSeverity,
        scoreDelta: 40,
        file: filePath,
        evidence: {
          snippet: `${type} connection string with credentials`,
          note: `${type} connection string with embedded password`,
        },
        remediation: 'Remove database credentials from code. Use environment variables.',
      });
      break;
    }
  }
  
  return findings;
}

// ========== API KEYS ==========

/**
 * Detect various API keys
 */
export function detectAPIKeys(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Skip test/example files
  if (/\.(test|spec|mock)\./i.test(filePath) || /fixtures?|mocks?|examples?/i.test(filePath)) {
    return findings;
  }
  
  const apiKeyPatterns = [
    { pattern: /sk-[A-Za-z0-9]{48}/g, provider: 'OpenAI' }, // OpenAI secret keys
    { pattern: /sk_live_[A-Za-z0-9]{24,}/g, provider: 'Stripe' }, // Stripe live keys
    { pattern: /rk_live_[A-Za-z0-9]{24,}/g, provider: 'Stripe Restricted' },
    { pattern: /ghp_[A-Za-z0-9]{36}/g, provider: 'GitHub Personal' }, // GitHub PAT
    { pattern: /github_pat_[A-Za-z0-9_]{22,}/g, provider: 'GitHub Fine-grained' },
    { pattern: /gho_[A-Za-z0-9]{36}/g, provider: 'GitHub OAuth' },
    { pattern: /ghs_[A-Za-z0-9]{36}/g, provider: 'GitHub App' },
    { pattern: /npm_[A-Za-z0-9]{36}/g, provider: 'npm' }, // npm tokens
    { pattern: /AIza[A-Za-z0-9_-]{35}/g, provider: 'Google API' }, // Google API keys
    { pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, provider: 'SendGrid' },
    { pattern: /xox[baprs]-[A-Za-z0-9-]+/g, provider: 'Slack' }, // Slack tokens
    { pattern: /sq0csp-[A-Za-z0-9_-]{43}/g, provider: 'Square' },
    { pattern: /EAAG[A-Za-z0-9]+/g, provider: 'Facebook' }, // Facebook access tokens
  ];
  
  for (const { pattern, provider } of apiKeyPatterns) {
    const matches = content.matchAll(pattern);
    for (const match of matches) {
      findings.push({
        id: `secrets-api-key-${provider.toLowerCase().replace(/\s+/g, '-')}`,
        category: 'SECRETS' as FindingCategory,
        severity: 'critical' as FindingSeverity,
        scoreDelta: 40,
        file: filePath,
        evidence: {
          snippet: `${provider} API Key: ${redactSecret(match[0])}`,
          note: `${provider} API key detected in source code`,
        },
        remediation: `Remove ${provider} API key from code. Rotate the key and use environment variables.`,
      });
      break; // One finding per provider per file
    }
  }
  
  return findings;
}

// ========== ENV FILES ==========

/**
 * Detect suspicious .env files with actual values
 */
export function detectEnvFileSecrets(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Only check .env files
  if (!/\.env(\.[^/]+)?$/i.test(filePath)) {
    return findings;
  }
  
  // Skip .env.example files
  if (/\.env\.example|\.env\.sample|\.env\.template/i.test(filePath)) {
    return findings;
  }
  
  // Check for actual values (not placeholders)
  const sensitiveVars = [
    /^(?:API_KEY|APIKEY)\s*=\s*['"]?[A-Za-z0-9_-]{16,}['"]?/im,
    /^(?:SECRET|SECRET_KEY)\s*=\s*['"]?[A-Za-z0-9_-]{16,}['"]?/im,
    /^(?:PASSWORD|DB_PASSWORD|DATABASE_PASSWORD)\s*=\s*['"]?[^\s'"]{4,}['"]?/im,
    /^(?:PRIVATE_KEY)\s*=\s*['"]?[A-Za-z0-9+/=_-]{16,}['"]?/im,
    /^(?:AWS_SECRET_ACCESS_KEY)\s*=\s*['"]?[A-Za-z0-9+/=]{40}['"]?/im,
  ];
  
  for (const pattern of sensitiveVars) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        id: 'secrets-env-file',
        category: 'SECRETS' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 30,
        file: filePath,
        evidence: {
          snippet: `.env file contains secrets`,
          note: 'Environment file with sensitive values committed to repository',
        },
        remediation: 'Remove .env files from git. Add to .gitignore and use .env.example for templates.',
      });
      break;
    }
  }
  
  return findings;
}

// ========== MAIN DETECTION FUNCTION ==========

/**
 * Run all secrets detection rules on a file
 */
export function detectSecretsExposure(filePath: string, content: string): Finding[] {
  return [
    ...detectAWSCredentials(filePath, content),
    ...detectPrivateKeys(filePath, content),
    ...detectJWTTokens(filePath, content),
    ...detectDatabaseSecrets(filePath, content),
    ...detectAPIKeys(filePath, content),
    ...detectEnvFileSecrets(filePath, content),
  ];
}
