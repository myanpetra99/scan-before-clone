// Serverless Security Rules
// Covers: AWS SAM/Lambda, Serverless Framework, Vercel, Netlify, CloudFlare Workers

import type { Finding, FindingCategory, FindingSeverity } from '@/types/scanner';

// ========== SHARED HELPERS ==========

function extractSnippet(content: string, matchIndex: number, matchLength: number): string {
  const start = Math.max(0, matchIndex - 50);
  const end = Math.min(content.length, matchIndex + matchLength + 200);
  let snippet = content.substring(start, end);
  if (start > 0) snippet = '...' + snippet;
  if (end < content.length) snippet = snippet + '...';
  return snippet.substring(0, 400);
}

// ========== AWS SAM/LAMBDA DETECTION ==========

/**
 * Detect security risks in AWS SAM templates
 */
export function detectAWSSAMRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check if this is a SAM/CloudFormation template
  const isSAM = /AWSTemplateFormatVersion|AWS::Serverless/i.test(content) ||
    /sam\.ya?ml$/i.test(filePath) ||
    /template\.ya?ml$/i.test(filePath);
  
  if (!isSAM) {
    return findings;
  }
  
  // Inline Lambda code (suspicious)
  const inlineCodeMatch = content.match(/InlineCode:\s*\|/i);
  if (inlineCodeMatch) {
    // Check for dangerous patterns in inline code
    if (/curl|wget|eval|exec|child_process/i.test(content)) {
      findings.push({
        id: 'sam-inline-code-exec',
        category: 'SERVERLESS_RISK' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, inlineCodeMatch.index || 0, 100),
          note: 'SAM template contains inline Lambda code with execution patterns',
        },
        remediation: 'Review inline Lambda code. Prefer external code packages for auditability.',
      });
    }
  }
  
  // Overly permissive IAM policies
  const wildcardMatch = content.match(/Action:\s*['"]?\*['"]?/i);
  if (wildcardMatch) {
    findings.push({
      id: 'sam-wildcard-iam',
      category: 'SERVERLESS_RISK' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 25,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, wildcardMatch.index || 0, wildcardMatch[0].length),
        note: 'SAM template uses wildcard (*) IAM action',
      },
      remediation: 'Use least-privilege IAM policies. Specify exact actions needed.',
    });
  }
  
  // Admin policy attachment
  const adminMatch = content.match(/arn:aws:iam::aws:policy\/AdministratorAccess/i);
  if (adminMatch) {
    findings.push({
      id: 'sam-admin-policy',
      category: 'SERVERLESS_RISK' as FindingCategory,
      severity: 'critical' as FindingSeverity,
      scoreDelta: 40,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, adminMatch.index || 0, adminMatch[0].length),
        note: 'Lambda function has AdministratorAccess policy',
      },
      remediation: 'Never attach AdministratorAccess to Lambda. Use specific permissions.',
    });
  }
  
  // Function URL with no auth
  const noAuthMatch = content.match(/AuthType:\s*['"]?NONE['"]?/i);
  if (noAuthMatch) {
    findings.push({
      id: 'sam-function-url-noauth',
      category: 'SERVERLESS_RISK' as FindingCategory,
      severity: 'medium' as FindingSeverity,
      scoreDelta: 15,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, noAuthMatch.index || 0, noAuthMatch[0].length),
        note: 'Lambda Function URL has no authentication',
      },
      remediation: 'Consider using AWS_IAM auth type for Function URLs.',
    });
  }
  
  return findings;
}

// ========== SERVERLESS FRAMEWORK DETECTION ==========

/**
 * Detect security risks in Serverless Framework configs
 */
export function detectServerlessFrameworkRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check if this is a Serverless Framework config
  const isServerless = /serverless\.ya?ml$/i.test(filePath) ||
    (content.includes('service:') && content.includes('provider:'));
  
  if (!isServerless) {
    return findings;
  }
  
  // Custom plugins from unknown sources
  const pluginMatch = content.match(/plugins:\s*\n([\s\S]*?)(?:\n[a-z]|\n$)/i);
  if (pluginMatch) {
    // Check for non-official plugins
    if (/serverless-[a-z-]+/i.test(pluginMatch[1]) && 
        !/serverless-offline|serverless-webpack|serverless-plugin-typescript/i.test(pluginMatch[1])) {
      findings.push({
        id: 'sls-custom-plugin',
        category: 'SERVERLESS_RISK' as FindingCategory,
        severity: 'medium' as FindingSeverity,
        scoreDelta: 15,
        file: filePath,
        evidence: {
          snippet: pluginMatch[0].substring(0, 200),
          note: 'Serverless config uses custom plugins',
        },
        remediation: 'Audit custom Serverless plugins before use. They execute during deployment.',
      });
    }
  }
  
  // Wildcard IAM
  const wildcardMatch = content.match(/Action:\s*['"]\*['"]/i);
  if (wildcardMatch) {
    findings.push({
      id: 'sls-wildcard-iam',
      category: 'SERVERLESS_RISK' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 25,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, wildcardMatch.index || 0, wildcardMatch[0].length),
        note: 'Serverless config uses wildcard IAM actions',
      },
      remediation: 'Use specific IAM actions instead of wildcards.',
    });
  }
  
  // Environment variables with secrets
  const envSecretMatch = content.match(/(?:API_KEY|SECRET|PASSWORD|TOKEN):\s*['"][^'"]+['"]/i);
  if (envSecretMatch) {
    findings.push({
      id: 'sls-hardcoded-secret',
      category: 'SECRETS' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 25,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, envSecretMatch.index || 0, Math.min(envSecretMatch[0].length, 50)),
        note: 'Serverless config contains hardcoded secrets',
      },
      remediation: 'Use SSM, Secrets Manager, or environment-specific config files.',
    });
  }
  
  return findings;
}

// ========== VERCEL/NETLIFY DETECTION ==========

/**
 * Detect security risks in Vercel/Netlify configs
 */
export function detectEdgePlatformRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check if this is a Vercel or Netlify config
  const isVercel = /vercel\.json$/i.test(filePath);
  const isNetlify = /netlify\.toml$/i.test(filePath) || /netlify\.ya?ml$/i.test(filePath);
  
  if (!isVercel && !isNetlify) {
    return findings;
  }
  
  // Build commands with network access
  const buildPatterns = [
    { pattern: /(?:build|command).*curl/i, cmd: 'curl' },
    { pattern: /(?:build|command).*wget/i, cmd: 'wget' },
    { pattern: /(?:build|command).*npm\s+install\s+[^"'\s]+/i, cmd: 'npm install <package>' },
  ];
  
  for (const { pattern, cmd } of buildPatterns) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        id: 'edge-build-network',
        category: 'SERVERLESS_RISK' as FindingCategory,
        severity: 'medium' as FindingSeverity,
        scoreDelta: 15,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: `Build command uses ${cmd} - downloads content during build`,
        },
        remediation: 'Audit build commands that access the network. Prefer checked-in dependencies.',
      });
    }
  }
  
  // Vercel: functions with external packages
  if (isVercel) {
    const functionsMatch = content.match(/"functions":\s*\{[^}]*"includeFiles"/i);
    if (functionsMatch) {
      findings.push({
        id: 'vercel-include-files',
        category: 'SERVERLESS_RISK' as FindingCategory,
        severity: 'low' as FindingSeverity,
        scoreDelta: 5,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, functionsMatch.index || 0, functionsMatch[0].length),
          note: 'Vercel config includes external files in functions',
        },
        remediation: 'Review included files to ensure no sensitive data is bundled.',
      });
    }
  }
  
  // Netlify: dangerous plugins
  if (isNetlify) {
    const pluginMatch = content.match(/\[\[plugins\]\][^[]*package\s*=\s*["']([^"']+)/i);
    if (pluginMatch) {
      findings.push({
        id: 'netlify-plugin',
        category: 'SERVERLESS_RISK' as FindingCategory,
        severity: 'low' as FindingSeverity,
        scoreDelta: 5,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, pluginMatch.index || 0, pluginMatch[0].length),
          note: `Netlify uses plugin: ${pluginMatch[1]}`,
        },
        remediation: 'Audit Netlify plugins before deployment. They run during builds.',
      });
    }
  }
  
  return findings;
}

// ========== CLOUDFLARE WORKERS DETECTION ==========

/**
 * Detect security risks in CloudFlare Workers
 */
export function detectCloudFlareWorkerRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check if this is a CloudFlare Worker config or code
  const isWrangler = /wrangler\.toml$/i.test(filePath);
  const isWorker = /addEventListener\s*\(\s*['"]fetch['"]/i.test(content);
  
  if (!isWrangler && !isWorker) {
    return findings;
  }
  
  // Fetch-and-eval patterns
  const fetchEvalMatch = content.match(/fetch\s*\([^)]+\)[\s\S]{0,100}(?:eval|Function\s*\()/i);
  if (fetchEvalMatch) {
    findings.push({
      id: 'cf-worker-fetch-eval',
      category: 'SERVERLESS_RISK' as FindingCategory,
      severity: 'critical' as FindingSeverity,
      scoreDelta: 40,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, fetchEvalMatch.index || 0, fetchEvalMatch[0].length),
        note: 'CloudFlare Worker fetches and evaluates remote code',
      },
      remediation: 'Never fetch and eval remote code. Bundle all code at build time.',
    });
  }
  
  // Wrangler with compatibility flags that might be risky
  if (isWrangler) {
    const compatMatch = content.match(/compatibility_flags\s*=\s*\[[^\]]*nodejs_compat/i);
    if (compatMatch) {
      findings.push({
        id: 'cf-worker-nodejs-compat',
        category: 'SERVERLESS_RISK' as FindingCategory,
        severity: 'low' as FindingSeverity,
        scoreDelta: 5,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, compatMatch.index || 0, compatMatch[0].length),
          note: 'Worker uses nodejs_compat flag (expanded API surface)',
        },
        remediation: 'Node.js compatibility expands attack surface. Use only if needed.',
      });
    }
  }
  
  return findings;
}

// ========== MAIN DETECTION FUNCTION ==========

/**
 * Run all serverless security rules on a file
 */
export function detectServerlessRisks(filePath: string, content: string): Finding[] {
  return [
    ...detectAWSSAMRisks(filePath, content),
    ...detectServerlessFrameworkRisks(filePath, content),
    ...detectEdgePlatformRisks(filePath, content),
    ...detectCloudFlareWorkerRisks(filePath, content),
  ];
}
