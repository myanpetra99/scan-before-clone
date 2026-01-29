// Browser Extension Security Rules - Detects malicious patterns in browser extensions
// Covers: Chrome/Firefox manifest.json, background scripts, content scripts

import type { Finding, FindingCategory, FindingSeverity } from '@/types/scanner';
import { parseJsonc } from './jsonc';

// ========== SHARED HELPERS ==========

function extractSnippet(content: string, matchIndex: number, matchLength: number): string {
  const start = Math.max(0, matchIndex - 50);
  const end = Math.min(content.length, matchIndex + matchLength + 200);
  let snippet = content.substring(start, end);
  if (start > 0) snippet = '...' + snippet;
  if (end < content.length) snippet = snippet + '...';
  return snippet.substring(0, 400);
}

// ========== DANGEROUS PERMISSIONS ==========

const DANGEROUS_PERMISSIONS = [
  'nativeMessaging',
  'debugger',
  'cookies',
  'webRequest',
  'webRequestBlocking',
  '<all_urls>',
  'file://*/*',
  'clipboardRead',
  'clipboardWrite',
  'management',
  'proxy',
  'privacy',
  'identity',
];

const HIGH_RISK_PERMISSIONS = [
  'nativeMessaging', // Can communicate with native apps
  'debugger', // Full debugger access
  '<all_urls>', // Access to all sites
  'file://*/*', // Local file access
];

// ========== SUSPICIOUS CONTENT SCRIPT TARGETS ==========

const SENSITIVE_TARGETS = [
  /\*:\/\/\*\.\w+bank\.\w+\//i,
  /\*:\/\/\*\.paypal\.com\//i,
  /\*:\/\/\*\.venmo\.com\//i,
  /\*:\/\/\*\.coinbase\.com\//i,
  /\*:\/\/\*\.binance\.com\//i,
  /\*:\/\/\*\.kraken\.com\//i,
  /\*:\/\/\*\.metamask\.io\//i,
  /\*:\/\/\*\.blockchain\.com\//i,
  /\*:\/\/accounts\.google\.com\//i,
  /\*:\/\/login\.live\.com\//i,
  /\*:\/\/\*\.amazon\.com\//i,
];

// ========== MANIFEST.JSON ANALYSIS ==========

interface ExtensionManifest {
  manifest_version?: number;
  name?: string;
  permissions?: string[];
  optional_permissions?: string[];
  host_permissions?: string[];
  content_scripts?: Array<{
    matches?: string[];
    js?: string[];
    run_at?: string;
  }>;
  background?: {
    service_worker?: string;
    scripts?: string[];
    persistent?: boolean;
  };
  externally_connectable?: {
    matches?: string[];
    ids?: string[];
    accepts_tls_channel_id?: boolean;
  };
  content_security_policy?: {
    extension_pages?: string;
    sandbox?: string;
  } | string;
}

/**
 * Detect dangerous patterns in browser extension manifests
 */
export function detectManifestRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check if this is a browser extension manifest
  if (!filePath.endsWith('manifest.json')) {
    return findings;
  }
  
  // Try to parse as extension manifest
  const manifest = parseJsonc<ExtensionManifest>(content);
  if (!manifest || !manifest.manifest_version) {
    return findings; // Not a browser extension manifest
  }
  
  // Collect all permissions
  const allPermissions = [
    ...(manifest.permissions || []),
    ...(manifest.optional_permissions || []),
    ...(manifest.host_permissions || []),
  ];
  
  // Check for high-risk permissions
  const highRisk = allPermissions.filter(p => HIGH_RISK_PERMISSIONS.includes(p));
  if (highRisk.length > 0) {
    findings.push({
      id: 'browser-ext-high-risk-perms',
      category: 'BROWSER_EXTENSION' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 30,
      file: filePath,
      evidence: {
        snippet: `"permissions": ${JSON.stringify(highRisk)}`,
        note: `Extension requests high-risk permissions: ${highRisk.join(', ')}`,
      },
      remediation: 'Review why these permissions are needed. nativeMessaging and debugger are particularly dangerous.',
    });
  }
  
  // Check for dangerous permission combinations
  const dangerousPerms = allPermissions.filter(p => DANGEROUS_PERMISSIONS.includes(p));
  if (dangerousPerms.length >= 3 && !highRisk.length) {
    findings.push({
      id: 'browser-ext-many-perms',
      category: 'BROWSER_EXTENSION' as FindingCategory,
      severity: 'medium' as FindingSeverity,
      scoreDelta: 15,
      file: filePath,
      evidence: {
        snippet: `"permissions": ${JSON.stringify(dangerousPerms)}`,
        note: `Extension requests ${dangerousPerms.length} sensitive permissions`,
      },
      remediation: 'Review each permission and ensure they are necessary for the extension\'s stated purpose.',
    });
  }
  
  // Check content scripts targeting sensitive sites
  for (const cs of manifest.content_scripts || []) {
    for (const match of cs.matches || []) {
      for (const sensitivePattern of SENSITIVE_TARGETS) {
        if (sensitivePattern.test(match)) {
          findings.push({
            id: 'browser-ext-sensitive-target',
            category: 'BROWSER_EXTENSION' as FindingCategory,
            severity: 'high' as FindingSeverity,
            scoreDelta: 25,
            file: filePath,
            evidence: {
              snippet: `"matches": ["${match}"]`,
              note: `Content script targets sensitive site: ${match}`,
            },
            remediation: 'Content scripts on banking/crypto sites are high-risk. Verify this is legitimate.',
          });
          break;
        }
      }
    }
  }
  
  // Check for externally_connectable (can receive messages from web pages)
  if (manifest.externally_connectable) {
    const ec = manifest.externally_connectable;
    if (ec.matches?.includes('<all_urls>') || ec.matches?.includes('*://*/*')) {
      findings.push({
        id: 'browser-ext-external-all',
        category: 'BROWSER_EXTENSION' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: `"externally_connectable": { "matches": ["*://*/*"] }`,
          note: 'Extension accepts messages from any website',
        },
        remediation: 'Restrict externally_connectable to specific trusted domains.',
      });
    }
  }
  
  // Check for weak CSP
  const csp = manifest.content_security_policy;
  if (csp) {
    const cspStr = typeof csp === 'string' ? csp : csp.extension_pages || '';
    if (/unsafe-eval/i.test(cspStr) || /unsafe-inline/i.test(cspStr)) {
      findings.push({
        id: 'browser-ext-weak-csp',
        category: 'BROWSER_EXTENSION' as FindingCategory,
        severity: 'medium' as FindingSeverity,
        scoreDelta: 15,
        file: filePath,
        evidence: {
          snippet: `"content_security_policy": "${cspStr.substring(0, 100)}..."`,
          note: 'Extension uses unsafe-eval or unsafe-inline in CSP',
        },
        remediation: 'Remove unsafe-eval and unsafe-inline from CSP for better security.',
      });
    }
  }
  
  return findings;
}

// ========== BACKGROUND SCRIPT ANALYSIS ==========

/**
 * Detect malicious patterns in extension background scripts
 */
export function detectBackgroundScriptRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for typical background script patterns
  const isBackground = /service[_-]?worker|background/i.test(filePath) ||
    /chrome\.runtime\.onInstalled/i.test(content) ||
    /browser\.runtime\.onInstalled/i.test(content);
  
  if (!isBackground) {
    return findings;
  }
  
  // Keylogger patterns
  const keyloggerPatterns = [
    /addEventListener\s*\(\s*['"]keydown['"]/i,
    /addEventListener\s*\(\s*['"]keypress['"]/i,
    /addEventListener\s*\(\s*['"]keyup['"]/i,
    /onkeydown\s*=/i,
    /document\.on(?:key(?:down|up|press))/i,
  ];
  
  for (const pattern of keyloggerPatterns) {
    const match = content.match(pattern);
    if (match) {
      // Check if it's also sending data
      if (/fetch|XMLHttpRequest|sendMessage|postMessage/i.test(content)) {
        findings.push({
          id: 'browser-ext-keylogger',
          category: 'EXFILTRATION' as FindingCategory,
          severity: 'critical' as FindingSeverity,
          scoreDelta: 45,
          file: filePath,
          evidence: {
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Extension captures keystrokes and sends data externally',
          },
          remediation: 'This is a keylogger pattern. Do not install this extension.',
        });
        break;
      }
    }
  }
  
  // Form capture patterns
  const formCapturePatterns = [
    /document\.forms/i,
    /\.getElementsByTagName\s*\(\s*['"]form['"]/i,
    /querySelectorAll\s*\(\s*['"]form/i,
    /input\[type=['"]password['"]\]/i,
  ];
  
  for (const pattern of formCapturePatterns) {
    const match = content.match(pattern);
    if (match) {
      if (/fetch|XMLHttpRequest|sendMessage|postMessage/i.test(content)) {
        findings.push({
          id: 'browser-ext-form-capture',
          category: 'EXFILTRATION' as FindingCategory,
          severity: 'high' as FindingSeverity,
          scoreDelta: 35,
          file: filePath,
          evidence: {
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Extension captures form data and sends it externally',
          },
          remediation: 'Review form capture logic. This may steal credentials.',
        });
        break;
      }
    }
  }
  
  // Cookie stealing
  const cookiePatterns = [
    /chrome\.cookies\.getAll/i,
    /browser\.cookies\.getAll/i,
    /document\.cookie/i,
  ];
  
  for (const pattern of cookiePatterns) {
    const match = content.match(pattern);
    if (match) {
      if (/fetch|XMLHttpRequest|sendMessage/i.test(content)) {
        findings.push({
          id: 'browser-ext-cookie-theft',
          category: 'EXFILTRATION' as FindingCategory,
          severity: 'high' as FindingSeverity,
          scoreDelta: 30,
          file: filePath,
          evidence: {
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Extension accesses cookies and sends data externally',
          },
          remediation: 'Cookie access with external transmission is high-risk.',
        });
        break;
      }
    }
  }
  
  // Native messaging host
  const nativePattern = /chrome\.runtime\.connectNative|browser\.runtime\.connectNative/i;
  const nativeMatch = content.match(nativePattern);
  if (nativeMatch) {
    findings.push({
      id: 'browser-ext-native-messaging',
      category: 'BROWSER_EXTENSION' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 25,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, nativeMatch.index || 0, nativeMatch[0].length),
        note: 'Extension uses native messaging to communicate with local applications',
      },
      remediation: 'Native messaging can execute local code. Verify the native host is trustworthy.',
    });
  }
  
  return findings;
}

// ========== MAIN DETECTION FUNCTION ==========

/**
 * Run all browser extension security rules on a file
 */
export function detectBrowserExtensionMalware(filePath: string, content: string): Finding[] {
  return [
    ...detectManifestRisks(filePath, content),
    ...detectBackgroundScriptRisks(filePath, content),
  ];
}
