// Rule Engine - Deterministic security rules for repository scanning
// Version 4.2.1 - Enhanced: Social Engineering, Phishing, Fake Installers, Office Macros, PII Harvesting

import type { Finding, FindingCategory, FindingSeverity } from '@/types/scanner';
import { detectVSCodeMalware } from './vscodeRules';
import { detectGitTrickery } from './gitTrickeryRules';
import { runAdvancedRules } from './advancedRules';
import { runExtendedRules } from './extendedRules';
import { detectIDEMalware } from './ideRules';
import { detectBrowserExtensionMalware } from './browserExtRules';
import { detectContainerOrchRisks } from './containerOrchRules';
import { detectServerlessRisks } from './serverlessRules';
import { detectSecretsExposure } from './secretsRules';
import { detectAIMLRisks } from './aiMlRules';
import { detectMobileDevRisks } from './mobileDevRules';
import { detectSocialEngineering } from './socialEngRules';

interface RuleMatch {
  matched: boolean;
  snippet?: string;
  lineRange?: [number, number];
  note?: string;
}

interface Rule {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  scoreDelta: number;
  name: string;
  description: string;
  remediation: string;
  filePatterns: RegExp[];
  contentPatterns?: RegExp[];
  check: (filePath: string, content: string) => RuleMatch;
}

// Helper to find line numbers for a match
function findLineRange(content: string, matchIndex: number): [number, number] {
  const lines = content.substring(0, matchIndex).split('\n');
  const startLine = lines.length;
  return [startLine, startLine + 2];
}

// Helper to extract snippet around match
function extractSnippet(content: string, matchIndex: number, matchLength: number): string {
  const start = Math.max(0, matchIndex - 50);
  const end = Math.min(content.length, matchIndex + matchLength + 200);
  let snippet = content.substring(start, end);
  if (start > 0) snippet = '...' + snippet;
  if (end < content.length) snippet = snippet + '...';
  return snippet.substring(0, 400);
}

// ========== RULES DEFINITION ==========

export const RULES: Rule[] = [
  // ===== EXECUTION_TRIGGER Rules =====
  {
    id: 'exec-npm-preinstall',
    category: 'EXECUTION_TRIGGER',
    severity: 'high',
    scoreDelta: 25,
    name: 'Dangerous preinstall script',
    description: 'package.json contains a preinstall script that runs automatically',
    remediation: 'Remove or audit the preinstall script before running npm install',
    filePatterns: [/package\.json$/],
    check: (filePath, content) => {
      const match = content.match(/"preinstall"\s*:\s*"([^"]+)"/);
      if (match) {
        const script = match[1];
        const dangerous = /curl|wget|bash|sh\s+-c|node\s+-e|python\s+-c|powershell/i.test(script);
        if (dangerous) {
          return {
            matched: true,
            snippet: match[0],
            note: `Preinstall script executes shell commands: ${script.substring(0, 100)}`,
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exec-npm-postinstall',
    category: 'EXECUTION_TRIGGER',
    severity: 'high',
    scoreDelta: 25,
    name: 'Dangerous postinstall script',
    description: 'package.json contains a postinstall script that runs automatically',
    remediation: 'Remove or audit the postinstall script. Use --ignore-scripts flag',
    filePatterns: [/package\.json$/],
    check: (filePath, content) => {
      const match = content.match(/"postinstall"\s*:\s*"([^"]+)"/);
      if (match) {
        const script = match[1];
        const dangerous = /curl|wget|bash|sh\s+-c|node\s+-e|python\s+-c|powershell|exec|eval/i.test(script);
        if (dangerous) {
          return {
            matched: true,
            snippet: match[0],
            note: `Postinstall script with dangerous commands: ${script.substring(0, 100)}`,
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exec-npm-prepare',
    category: 'EXECUTION_TRIGGER',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Prepare script with network access',
    description: 'Prepare script may download and execute code',
    remediation: 'Review the prepare script for unexpected network calls',
    filePatterns: [/package\.json$/],
    check: (filePath, content) => {
      const match = content.match(/"prepare"\s*:\s*"([^"]+)"/);
      if (match && /curl|wget|fetch|download/i.test(match[1])) {
        return {
          matched: true,
          snippet: match[0],
          note: 'Prepare script downloads external resources',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'exec-setup-py',
    category: 'EXECUTION_TRIGGER',
    severity: 'high',
    scoreDelta: 25,
    name: 'Setup.py with command execution',
    description: 'Python setup file contains code execution patterns',
    remediation: 'Audit setup.py before pip install. Use virtual environments',
    filePatterns: [/setup\.py$/],
    check: (filePath, content) => {
      const patterns = [
        /os\.system\s*\(/,
        /subprocess\.(run|call|Popen)/,
        /exec\s*\(/,
        /eval\s*\(/,
        /urllib.*urlopen.*read.*exec/s,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Setup.py executes arbitrary code during installation',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exec-makefile-download',
    category: 'EXECUTION_TRIGGER',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Makefile downloads and executes',
    description: 'Makefile contains download-and-execute patterns',
    remediation: 'Review Makefile targets before running make',
    filePatterns: [/^Makefile$|^makefile$/],
    check: (filePath, content) => {
      const pattern = /(curl|wget).*\|\s*(bash|sh)|\.\/[a-zA-Z0-9_-]+\.sh/;
      const match = content.match(pattern);
      if (match) {
        return {
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: 'Makefile downloads and executes remote scripts',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'exec-shell-download-execute',
    category: 'EXECUTION_TRIGGER',
    severity: 'high',
    scoreDelta: 20,
    name: 'Shell script downloads and executes',
    description: 'Shell script downloads and immediately executes code',
    remediation: 'Download scripts first, inspect them, then execute if safe',
    filePatterns: [/\.(sh|bash)$/],
    check: (filePath, content) => {
      const pattern = /(curl|wget)\s+[^\n]*\|\s*(bash|sh|python|node)|eval\s*\$\((curl|wget)/;
      const match = content.match(pattern);
      if (match) {
        return {
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: 'Script pipes downloaded content directly to shell',
        };
      }
      return { matched: false };
    },
  },

  // ===== CI_CD_RISK Rules =====
  {
    id: 'cicd-unpinned-action',
    category: 'CI_CD_RISK',
    severity: 'medium',
    scoreDelta: 10,
    name: 'Unpinned GitHub Action',
    description: 'GitHub workflow uses action without pinned SHA',
    remediation: 'Pin actions to specific commit SHA for reproducibility',
    filePatterns: [/\.github\/workflows\/.*\.ya?ml$/],
    check: (filePath, content) => {
      const pattern = /uses:\s+([^@\n]+)@(main|master|latest|v\d+)\s*$/m;
      const match = content.match(pattern);
      if (match) {
        return {
          matched: true,
          snippet: match[0],
          note: `Action ${match[1]} uses unpinned ref: ${match[2]}`,
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'cicd-curl-bash',
    category: 'CI_CD_RISK',
    severity: 'high',
    scoreDelta: 20,
    name: 'CI/CD curl | bash pattern',
    description: 'Workflow downloads and executes scripts without verification',
    remediation: 'Download scripts first, verify checksums, then execute',
    filePatterns: [/\.github\/workflows\/.*\.ya?ml$/],
    check: (filePath, content) => {
      const pattern = /(curl|wget)\s+[^\n]*\|\s*(bash|sh)/;
      const match = content.match(pattern);
      if (match) {
        return {
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: 'Workflow pipes curl output to shell',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'cicd-secrets-exposure',
    category: 'CI_CD_RISK',
    severity: 'high',
    scoreDelta: 25,
    name: 'Potential secrets exposure',
    description: 'Workflow may expose secrets in logs or artifacts',
    remediation: 'Avoid echoing secrets. Use secret masking',
    filePatterns: [/\.github\/workflows\/.*\.ya?ml$/],
    check: (filePath, content) => {
      const pattern = /echo\s+.*\$\{\{\s*secrets\./;
      const match = content.match(pattern);
      if (match) {
        return {
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: 'Workflow echoes secrets which may appear in logs',
        };
      }
      return { matched: false };
    },
  },

  // ===== EXFILTRATION Rules =====
  {
    id: 'exfil-ssh-read',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 30,
    name: 'SSH key access',
    description: 'Code reads SSH keys or config',
    remediation: 'Legitimate tools rarely need SSH key access. Review carefully',
    filePatterns: [/\.(js|ts|py|rb|go|sh)$/],
    check: (filePath, content) => {
      const patterns = [
        /\.ssh\/(id_rsa|id_ed25519|id_dsa|authorized_keys|known_hosts|config)/,
        /readFile.*\.ssh/,
        /open\(.*\.ssh/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code accesses SSH credentials directory',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exfil-cloud-creds',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 30,
    name: 'Cloud credentials access',
    description: 'Code reads AWS, GCP, or Azure credential files',
    remediation: 'Review why this tool needs cloud credential access',
    filePatterns: [/\.(js|ts|py|rb|go|sh)$/],
    check: (filePath, content) => {
      const patterns = [
        /\.aws\/(credentials|config)/,
        /\.gcloud|gcloud.*auth|application_default_credentials/,
        /\.azure|azure.*credentials/,
        /GOOGLE_APPLICATION_CREDENTIALS/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code accesses cloud provider credentials',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exfil-browser-wallet',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 35,
    name: 'Crypto wallet access',
    description: 'Code accesses browser extension wallet data',
    remediation: 'This is a major red flag. Do not run this code',
    filePatterns: [/\.(js|ts|py|rb)$/],
    check: (filePath, content) => {
      const patterns = [
        /metamask|phantom|exodus|coinbase.wallet|Trust.Wallet/i,
        /Local.Extension.Settings.*nkbihfbeogaeaoehlefnkodbefgpgknn/,
        /chrome.*User.Data.*Local.Extension/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code targets cryptocurrency wallet extensions',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exfil-env-sweep',
    category: 'EXFILTRATION',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Environment variable sweep',
    description: 'Code collects all environment variables',
    remediation: 'Review why full env access is needed. Could leak secrets',
    filePatterns: [/\.(js|ts|py|rb)$/],
    check: (filePath, content) => {
      const patterns = [
        /process\.env\s*[,\)}\]]/,
        /Object\.keys\(process\.env\)/,
        /os\.environ(?!\[)/,
        /JSON\.stringify\(process\.env\)/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code accesses entire environment variable set',
          };
        }
      }
      return { matched: false };
    },
  },

  // ===== OBFUSCATION Rules =====
  {
    id: 'obfusc-base64-exec',
    category: 'OBFUSCATION',
    severity: 'high',
    scoreDelta: 25,
    name: 'Base64 decoded execution',
    description: 'Code decodes base64 and executes it',
    remediation: 'Decode and inspect the base64 content before running',
    filePatterns: [/\.(js|ts|py|rb|sh)$/],
    check: (filePath, content) => {
      const patterns = [
        /atob\([^)]+\).*eval/s,
        /Buffer\.from\([^,]+,\s*['"]base64['"]\).*eval/s,
        /base64.*-d.*\|\s*(bash|sh|python|node)/,
        /base64\.b64decode.*exec/s,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Base64 content is decoded and executed',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'obfusc-large-blob',
    category: 'OBFUSCATION',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Large encoded blob',
    description: 'File contains large base64 or hex encoded strings',
    remediation: 'Decode and inspect the content. Could hide malicious code',
    filePatterns: [/\.(js|ts|py|rb)$/],
    check: (filePath, content) => {
      // Look for very long base64-like strings
      const pattern = /['"`][A-Za-z0-9+/=]{500,}['"`]/;
      const match = content.match(pattern);
      if (match) {
        return {
          matched: true,
          snippet: `Large encoded blob (${match[0].length} chars): ${match[0].substring(0, 100)}...`,
          note: 'File contains suspiciously large encoded string',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'obfusc-eval-string',
    category: 'OBFUSCATION',
    severity: 'high',
    scoreDelta: 20,
    name: 'Eval with string manipulation',
    description: 'Code uses eval with constructed or obfuscated strings',
    remediation: 'Trace the eval input. This is a common malware pattern',
    filePatterns: [/\.(js|ts)$/],
    check: (filePath, content) => {
      const patterns = [
        /eval\s*\(\s*\w+\.join/,
        /eval\s*\(\s*String\.fromCharCode/,
        /eval\s*\(\s*\w+\.replace/,
        /new\s+Function\s*\(\s*['"`]return/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Eval with dynamically constructed code',
          };
        }
      }
      return { matched: false };
    },
  },

  // ===== SOCIAL_ENGINEERING Rules =====
  {
    id: 'social-disable-security',
    category: 'SOCIAL_ENGINEERING',
    severity: 'high',
    scoreDelta: 25,
    name: 'Instructions to disable security',
    description: 'README instructs users to disable security features',
    remediation: 'Never disable system security. Find alternative solutions',
    filePatterns: [/README\.md$/i, /\.md$/],
    check: (filePath, content) => {
      const patterns = [
        /disable.*(antivirus|defender|firewall|gatekeeper)/i,
        /turn.off.*(antivirus|defender|firewall|security)/i,
        /--no-sandbox/,
        /sudo.*chmod\s+777/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Documentation asks user to disable security features',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'social-run-as-admin',
    category: 'SOCIAL_ENGINEERING',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Requests admin/root access',
    description: 'Instructions request running with elevated privileges',
    remediation: 'Question why admin access is needed. Run with minimal privileges',
    filePatterns: [/README\.md$/i, /\.md$/],
    check: (filePath, content) => {
      const patterns = [
        /run.as.administrator/i,
        /right.click.*run.as.admin/i,
        /sudo\s+bash\s+.*\.sh/,
        /must.run.*root/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Documentation requests elevated privileges',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'social-copy-paste-oneliner',
    category: 'SOCIAL_ENGINEERING',
    severity: 'medium',
    scoreDelta: 10,
    name: 'Copy-paste one-liner',
    description: 'README contains curl|bash installation pattern',
    remediation: 'Download and inspect scripts before executing',
    filePatterns: [/README\.md$/i],
    check: (filePath, content) => {
      const pattern = /```[^`]*\n\s*(curl|wget)\s+[^\n]+\|\s*(sudo\s+)?(bash|sh)/;
      const match = content.match(pattern);
      if (match) {
        return {
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: 'README promotes dangerous curl|bash installation',
        };
      }
      return { matched: false };
    },
  },

  // ===== BINARY_SUSPICION Rules =====
  {
    id: 'binary-eicar-test',
    category: 'BINARY_SUSPICION',
    severity: 'high',
    scoreDelta: 30,
    name: 'EICAR test file detected',
    description: 'Repository contains EICAR antivirus test files which mimic malware signatures',
    remediation: 'This is an antivirus test repository. Contents trigger AV detection by design',
    filePatterns: [/.*/], // Match any file
    check: (filePath, content) => {
      // EICAR standard test string
      const eicarPattern = /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/;
      // Also check for EICAR in filename
      const filenamePattern = /eicar/i;
      
      if (eicarPattern.test(content)) {
        return {
          matched: true,
          snippet: 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE detected',
          note: 'Contains EICAR test signature - designed to trigger antivirus software',
        };
      }
      
      if (filenamePattern.test(filePath) && (content.length < 500 || /test.*file|antivirus/i.test(content))) {
        return {
          matched: true,
          snippet: `Suspicious file: ${filePath}`,
          note: 'File appears to be an antivirus test file',
        };
      }
      
      return { matched: false };
    },
  },
  {
    id: 'binary-macro-document',
    category: 'BINARY_SUSPICION',
    severity: 'high',
    scoreDelta: 25,
    name: 'Office document with macros',
    description: 'Repository contains Office documents that may contain macros',
    remediation: 'Office documents with macros are a common malware vector. Do not enable macros',
    filePatterns: [/\.(doc|docx|docm|xls|xlsx|xlsm|ppt|pptx|pptm)$/i],
    check: (filePath, content) => {
      // Macro-enabled file extensions
      if (/\.(docm|xlsm|pptm)$/i.test(filePath)) {
        return {
          matched: true,
          snippet: `Macro-enabled document: ${filePath}`,
          note: 'Macro-enabled Office document - high malware risk',
        };
      }
      // Check for macro indicators in older .doc/.xls files
      if (/\.(doc|xls)$/i.test(filePath) && (
        /macro|vba|AutoOpen|Document_Open|Workbook_Open/i.test(filePath) ||
        content.includes('VBA') || content.includes('macro')
      )) {
        return {
          matched: true,
          snippet: `Possible macro document: ${filePath}`,
          note: 'Office document may contain executable macros',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'binary-executable',
    category: 'BINARY_SUSPICION',
    severity: 'high',
    scoreDelta: 20,
    name: 'Executable binary in source',
    description: 'Repository contains executable binaries in source directories',
    remediation: 'Binaries should be built from source, not committed. High risk',
    filePatterns: [/\.(exe|dll|so|dylib|bin|scr|com|bat|cmd|ps1|vbs|wsf)$/i],
    check: (filePath) => {
      return {
        matched: true,
        snippet: `Executable file: ${filePath}`,
        note: 'Executable file committed to repository',
      };
    },
  },
  {
    id: 'binary-archive-executable',
    category: 'BINARY_SUSPICION',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Archive potentially containing executables',
    description: 'Compressed archives may hide malicious executables',
    remediation: 'Extract and inspect archive contents before use',
    filePatterns: [/\.(zip|rar|7z|tar\.gz|tgz)$/i],
    check: (filePath) => {
      // Archives in source are suspicious
      return {
        matched: true,
        snippet: `Archive file: ${filePath}`,
        note: 'Archive file could contain hidden executables or malware',
      };
    },
  },
  {
    id: 'binary-large-opaque',
    category: 'BINARY_SUSPICION',
    severity: 'medium',
    scoreDelta: 10,
    name: 'Large opaque file',
    description: 'Large file that cannot be easily inspected',
    remediation: 'Verify the file purpose. Could hide malicious payloads',
    filePatterns: [/\.(dat|db|sqlite|pack)$/],
    check: (filePath) => {
      // File exists in source paths
      if (/^(src|lib|scripts|app)\//i.test(filePath)) {
        return {
          matched: true,
          snippet: `Opaque data file: ${filePath}`,
          note: 'Data file in source directory cannot be easily inspected',
        };
      }
      return { matched: false };
    },
  },

  // ===== DEPENDENCY_RISK Rules =====
  {
    id: 'dep-git-url',
    category: 'DEPENDENCY_RISK',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Git URL dependency',
    description: 'Package.json uses git URL instead of npm registry',
    remediation: 'Prefer npm packages. Git URLs bypass npm security checks',
    filePatterns: [/package\.json$/],
    check: (filePath, content) => {
      const pattern = /"[^"]+"\s*:\s*"(git\+https?:\/\/|git:\/\/|github:)/;
      const match = content.match(pattern);
      if (match) {
        return {
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: 'Dependency installed from git URL, not npm registry',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'dep-url-dependency',
    category: 'DEPENDENCY_RISK',
    severity: 'high',
    scoreDelta: 20,
    name: 'Direct URL dependency',
    description: 'Package uses direct URL for dependency installation',
    remediation: 'Avoid URL dependencies. Use npm packages with version pinning',
    filePatterns: [/package\.json$/],
    check: (filePath, content) => {
      const pattern = /"[^"]+"\s*:\s*"https?:\/\/[^"]+\.(tgz|tar\.gz|zip)"/;
      const match = content.match(pattern);
      if (match) {
        return {
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: 'Dependency downloaded directly from URL',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'dep-typosquat-suspicion',
    category: 'DEPENDENCY_RISK',
    severity: 'low',
    scoreDelta: 8,
    name: 'Possible typosquat package',
    description: 'Package name similar to popular package but slightly different',
    remediation: 'Verify package name spelling. Typosquatting is common',
    filePatterns: [/package\.json$/],
    check: (filePath, content) => {
      // Common typosquat targets
      const popular = ['lodash', 'express', 'react', 'axios', 'moment', 'chalk'];
      const suspiciousPatterns = popular.map(pkg => 
        new RegExp(`"(${pkg}[0-9]|${pkg}[_-]|${pkg.slice(0, -1)}|.${pkg})":`)
      );
      for (const pattern of suspiciousPatterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: match[0],
            note: 'Package name resembles popular package',
          };
        }
      }
      return { matched: false };
    },
  },
  // ===== ADVANCED EXECUTION RISKS =====
  {
    id: 'exec-dynamic-require',
    category: 'EXECUTION_TRIGGER',
    severity: 'high',
    scoreDelta: 20,
    name: 'Dynamic require/import',
    description: 'Code dynamically constructs module paths which may load malicious code',
    remediation: 'Review what modules are being loaded. Avoid dynamic import paths',
    filePatterns: [/\.(js|ts|mjs|cjs)$/],
    check: (filePath, content) => {
      const patterns = [
        /require\s*\(\s*\w+\s*\+/,
        /require\s*\(\s*`\$\{/,
        /import\s*\(\s*\w+\s*\+/,
        /import\s*\(\s*`\$\{/,
        /module\.constructor/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Module path constructed dynamically - could load arbitrary code',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exec-child-process',
    category: 'EXECUTION_TRIGGER',
    severity: 'high',
    scoreDelta: 20,
    name: 'Child process execution',
    description: 'Code spawns child processes which can execute arbitrary commands',
    remediation: 'Review what commands are being executed and their inputs',
    filePatterns: [/\.(js|ts|mjs|cjs)$/],
    check: (filePath, content) => {
      const patterns = [
        /child_process.*exec\s*\(/,
        /child_process.*spawn\s*\(/,
        /execSync\s*\(/,
        /spawnSync\s*\(/,
        /exec\s*\(\s*`/,
        /exec\s*\(\s*\w+\s*\+/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Child process execution detected',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exec-vm-context',
    category: 'EXECUTION_TRIGGER',
    severity: 'high',
    scoreDelta: 25,
    name: 'VM context code execution',
    description: 'Code uses Node.js VM module to execute arbitrary code',
    remediation: 'VM contexts can be escaped. Review code being executed',
    filePatterns: [/\.(js|ts|mjs|cjs)$/],
    check: (filePath, content) => {
      const patterns = [
        /vm\.runInContext/,
        /vm\.runInNewContext/,
        /vm\.runInThisContext/,
        /vm\.Script/,
        /vm\.createContext/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code uses VM module for arbitrary execution',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exec-python-dangerous',
    category: 'EXECUTION_TRIGGER',
    severity: 'high',
    scoreDelta: 25,
    name: 'Python dangerous execution',
    description: 'Python code uses eval/exec/compile or pickle (unsafe deserialization)',
    remediation: 'Avoid eval/exec. Use ast.literal_eval for safe parsing. Never unpickle untrusted data',
    filePatterns: [/\.py$/],
    check: (filePath, content) => {
      const patterns = [
        /\beval\s*\(/,
        /\bexec\s*\(/,
        /\bcompile\s*\(/,
        /pickle\.loads?\s*\(/,
        /marshal\.loads?\s*\(/,
        /yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.UnsafeLoader/,
        /yaml\.unsafe_load/,
        /__import__\s*\(/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Python code uses dangerous execution or deserialization',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exec-php-dangerous',
    category: 'EXECUTION_TRIGGER',
    severity: 'high',
    scoreDelta: 25,
    name: 'PHP dangerous execution',
    description: 'PHP code uses eval, assert, or shell execution functions',
    remediation: 'Avoid eval/assert. Use parameterized commands for shell operations',
    filePatterns: [/\.php$/],
    check: (filePath, content) => {
      const patterns = [
        /\beval\s*\(/,
        /\bassert\s*\(\s*\$/,
        /\bcreate_function\s*\(/,
        /preg_replace\s*\([^)]*\/[a-z]*e[a-z]*['"],/,
        /\bsystem\s*\(/,
        /\bshell_exec\s*\(/,
        /\bpassthru\s*\(/,
        /\bpopen\s*\(/,
        /\bproc_open\s*\(/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'PHP code uses dangerous execution functions',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exec-ruby-dangerous',
    category: 'EXECUTION_TRIGGER',
    severity: 'high',
    scoreDelta: 20,
    name: 'Ruby code execution',
    description: 'Ruby code uses eval, system, or backticks for command execution',
    remediation: 'Avoid eval. Use parameterized commands for shell operations',
    filePatterns: [/\.rb$/],
    check: (filePath, content) => {
      const patterns = [
        /\beval\s*\(/,
        /\binstance_eval\b/,
        /\bclass_eval\b/,
        /\bmodule_eval\b/,
        /\bsend\s*\(\s*:/,
        /`[^`]*\$\{/,
        /system\s*\(/,
        /Open3\./,
        /%x\{/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Ruby code uses dynamic execution or shell commands',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exec-go-dangerous',
    category: 'EXECUTION_TRIGGER',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Go command execution',
    description: 'Go code uses os/exec or syscall for command execution',
    remediation: 'Review what commands are being executed and their inputs',
    filePatterns: [/\.go$/],
    check: (filePath, content) => {
      const patterns = [
        /exec\.Command\s*\(/,
        /syscall\.Exec\s*\(/,
        /plugin\.Open\s*\(/,
        /os\.StartProcess\s*\(/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Go code executes external commands',
          };
        }
      }
      return { matched: false };
    },
  },

  // ===== DROPPER / DOWNLOAD-EXECUTE PATTERNS =====
  {
    id: 'dropper-temp-execute',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 30,
    name: 'Temp file execution pattern',
    description: 'Code downloads to temp directory and executes - classic dropper behavior',
    remediation: 'Do not run this code. This is a malware dropper pattern',
    filePatterns: [/\.(js|ts|py|rb|sh|ps1)$/],
    check: (filePath, content) => {
      const patterns = [
        /(\/tmp\/|%temp%|AppData.*Local.*Temp|os\.tmpdir).*(chmod|exec|spawn|system|Start-Process)/is,
        /(fetch|axios|request|urllib|wget|curl).*(\/tmp\/|%temp%|tempdir)/is,
        /writeFile.*(\.exe|\.sh|\.bat|\.ps1|\.vbs).*exec/is,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Downloads to temp directory and executes - dropper pattern',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'dropper-hidden-directory',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 25,
    name: 'Hidden directory operations',
    description: 'Code creates or operates in hidden directories',
    remediation: 'Hidden directories are used to evade detection. Review carefully',
    filePatterns: [/\.(js|ts|py|rb|sh|ps1)$/],
    check: (filePath, content) => {
      const patterns = [
        /mkdir.*\/\.\w+/,
        /writeFile.*\/\.\w+\//,
        /\$HOME\/\.[a-z]+\//,
        /\.local\/share.*exec/is,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Operations in hidden directories - evasion technique',
          };
        }
      }
      return { matched: false };
    },
  },

  // ===== CREDENTIAL THEFT PATTERNS =====
  {
    id: 'exfil-browser-data',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 35,
    name: 'Browser data access',
    description: 'Code accesses browser cookies, passwords, or history',
    remediation: 'This is credential theft. Do not run this code',
    filePatterns: [/\.(js|ts|py|rb)$/],
    check: (filePath, content) => {
      const patterns = [
        /Chrome.*User.Data.*(Cookies|Login Data|History)/i,
        /Firefox.*Profiles.*(cookies|logins|places)\.sqlite/i,
        /\.mozilla\/firefox.*\.sqlite/i,
        /Library.*Application.Support.*(Chrome|Firefox|Safari)/i,
        /Cookies\.binarycookies/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code attempts to access browser credentials or cookies',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exfil-keychain',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 35,
    name: 'Keychain/credential store access',
    description: 'Code accesses system keychain or credential managers',
    remediation: 'Credential store access without user consent is theft',
    filePatterns: [/\.(js|ts|py|rb|sh)$/],
    check: (filePath, content) => {
      const patterns = [
        /security\s+find-(generic|internet)-password/i,
        /Keychain.*dump/i,
        /secretservice/i,
        /gnome-keyring/i,
        /kwallet/i,
        /dpapi.*crypt/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code accesses system credential storage',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exfil-password-files',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 30,
    name: 'Password file access',
    description: 'Code reads system password files or shadow files',
    remediation: 'Reading password files is a major security concern',
    filePatterns: [/\.(js|ts|py|rb|sh|go)$/],
    check: (filePath, content) => {
      const patterns = [
        /\/etc\/passwd/,
        /\/etc\/shadow/,
        /\/etc\/security\/opasswd/,
        /SAM.*SYSTEM.*SECURITY/i,
        /Windows.*SAM/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code attempts to read password/shadow files',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'exfil-token-files',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 25,
    name: 'Token/secret file enumeration',
    description: 'Code searches for token, secret, or credential files',
    remediation: 'Token enumeration is a precursor to credential theft',
    filePatterns: [/\.(js|ts|py|rb|sh)$/],
    check: (filePath, content) => {
      const patterns = [
        /find.*-name.*\*(token|secret|credential|password|api[_-]?key)\*/i,
        /glob.*\*\*(token|secret|credential|password)\*\*/i,
        /\.npmrc|\.pypirc|\.netrc/,
        /\.docker\/config\.json/,
        /\.kube\/config/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code searches for credential/token files',
          };
        }
      }
      return { matched: false };
    },
  },

  // ===== NETWORK EXFILTRATION =====
  {
    id: 'network-fingerprint-exfil',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 25,
    name: 'System fingerprinting with exfil',
    description: 'Code collects system information and sends it externally',
    remediation: 'System fingerprinting followed by POST is exfiltration',
    filePatterns: [/\.(js|ts|py|rb)$/],
    check: (filePath, content) => {
      const hasFingerprint = /(os\.platform|os\.hostname|os\.userInfo|getmac|whoami|uname|systeminfo)/i.test(content);
      const hasExfil = /(fetch|axios|request|http\.post|urllib\.request|POST)/i.test(content);
      if (hasFingerprint && hasExfil) {
        return {
          matched: true,
          snippet: 'System info collection + HTTP POST detected',
          note: 'Code collects system info and sends it externally',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'network-suspicious-endpoint',
    category: 'EXFILTRATION',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Suspicious external endpoints',
    description: 'Code connects to pastebin-like services or dynamic DNS',
    remediation: 'Review why this code connects to file sharing services',
    filePatterns: [/\.(js|ts|py|rb|sh)$/],
    check: (filePath, content) => {
      const patterns = [
        /pastebin\.com|hastebin\.com|ghostbin\./,
        /webhook\.site|pipedream\.net|requestbin\./,
        /ngrok\.io|serveo\.net|localhost\.run/,
        /duckdns\.org|no-ip\.com|dynu\.com/,
        /tor2web|\.onion/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Connection to suspicious file-sharing or tunneling service',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'network-raw-socket',
    category: 'EXFILTRATION',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Raw socket usage',
    description: 'Code creates raw sockets which can bypass security controls',
    remediation: 'Raw sockets can be used for tunneling or exfiltration',
    filePatterns: [/\.(js|ts|py|go|rb)$/],
    check: (filePath, content) => {
      const patterns = [
        /socket\.socket.*SOCK_RAW/,
        /dgram\.createSocket/,
        /net\.createConnection/,
        /net\.Socket\(\)/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Raw socket creation detected',
          };
        }
      }
      return { matched: false };
    },
  },

  // ===== PERSISTENCE MECHANISMS =====
  {
    id: 'persist-crontab',
    category: 'CI_CD_RISK',
    severity: 'high',
    scoreDelta: 25,
    name: 'Crontab persistence',
    description: 'Code modifies crontab for persistence',
    remediation: 'Cron modification is a persistence technique. Review carefully',
    filePatterns: [/\.(js|ts|py|rb|sh)$/],
    check: (filePath, content) => {
      const patterns = [
        /crontab\s+-[rl]?\s*</,
        /crontab.*echo/,
        /\/etc\/cron\.d\//,
        /\/var\/spool\/cron/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code modifies crontab for scheduled execution',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'persist-systemd',
    category: 'CI_CD_RISK',
    severity: 'high',
    scoreDelta: 25,
    name: 'Systemd persistence',
    description: 'Code creates or modifies systemd services',
    remediation: 'Systemd service creation is a persistence mechanism',
    filePatterns: [/\.(js|ts|py|rb|sh)$/],
    check: (filePath, content) => {
      const patterns = [
        /\/etc\/systemd\/system\//,
        /systemctl\s+enable/,
        /\.service.*WantedBy/s,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code installs systemd service for persistence',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'persist-registry',
    category: 'CI_CD_RISK',
    severity: 'high',
    scoreDelta: 30,
    name: 'Windows registry autorun',
    description: 'Code modifies Windows registry for persistence',
    remediation: 'Registry autorun modifications are persistence techniques',
    filePatterns: [/\.(js|ts|py|ps1|bat|cmd)$/],
    check: (filePath, content) => {
      const patterns = [
        /HKEY.*(Run|RunOnce)/i,
        /reg\s+add.*\\Run/i,
        /Set-ItemProperty.*Run/i,
        /CurrentVersion\\Run/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Windows registry autorun modification detected',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'persist-launch-agent',
    category: 'CI_CD_RISK',
    severity: 'high',
    scoreDelta: 25,
    name: 'macOS launch agent',
    description: 'Code creates macOS launch agents for persistence',
    remediation: 'Launch agents persist across reboots. Review carefully',
    filePatterns: [/\.(js|ts|py|rb|sh)$/],
    check: (filePath, content) => {
      const patterns = [
        /LaunchAgents/,
        /launchctl\s+load/,
        /\.plist.*ProgramArguments/s,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'macOS launch agent creation detected',
          };
        }
      }
      return { matched: false };
    },
  },

  // ===== CRYPTO/RANSOMWARE PATTERNS =====
  {
    id: 'ransom-mass-encrypt',
    category: 'OBFUSCATION',
    severity: 'high',
    scoreDelta: 35,
    name: 'Mass file encryption pattern',
    description: 'Code traverses directories and encrypts files - ransomware behavior',
    remediation: 'DO NOT RUN. This appears to be ransomware',
    filePatterns: [/\.(js|ts|py|rb|go)$/],
    check: (filePath, content) => {
      const hasTraversal = /(walkdir|walk|readdir|glob|find)/i.test(content);
      const hasEncrypt = /(AES|encrypt|cipher|Fernet|crypto)/i.test(content);
      const hasExtension = /(\.encrypted|\.locked|\.crypted|\.enc)/i.test(content);
      if (hasTraversal && hasEncrypt && hasExtension) {
        return {
          matched: true,
          snippet: 'Directory traversal + encryption + extension change detected',
          note: 'Code pattern matches ransomware behavior',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'ransom-note-pattern',
    category: 'OBFUSCATION',
    severity: 'high',
    scoreDelta: 30,
    name: 'Ransom note creation',
    description: 'Code creates files with ransom-like messaging',
    remediation: 'This appears to be ransomware. Do not run',
    filePatterns: [/\.(js|ts|py|rb)$/],
    check: (filePath, content) => {
      const patterns = [
        /(README|HOW_TO_DECRYPT|DECRYPT_INSTRUCTIONS|YOUR_FILES_ARE_ENCRYPTED)/i,
        /(bitcoin|btc|monero|xmr).*address.*payment/is,
        /files.*encrypted.*pay.*restore/is,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Code creates ransom-note-like content',
          };
        }
      }
      return { matched: false };
    },
  },

  // ===== ADVANCED CI/CD RISKS =====
  {
    id: 'cicd-broad-permissions',
    category: 'CI_CD_RISK',
    severity: 'high',
    scoreDelta: 20,
    name: 'Overly broad workflow permissions',
    description: 'GitHub workflow has write-all or dangerous permissions',
    remediation: 'Use least-privilege permissions. Avoid write-all',
    filePatterns: [/\.github\/workflows\/.*\.ya?ml$/],
    check: (filePath, content) => {
      const patterns = [
        /permissions:\s*write-all/,
        /permissions:.*contents:\s*write/s,
        /permissions:.*packages:\s*write/s,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Workflow has dangerous write permissions',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'cicd-pull-request-target',
    category: 'CI_CD_RISK',
    severity: 'high',
    scoreDelta: 25,
    name: 'Dangerous pull_request_target usage',
    description: 'Workflow uses pull_request_target with checkout - allows secret theft',
    remediation: 'pull_request_target with checkout is dangerous. Review carefully',
    filePatterns: [/\.github\/workflows\/.*\.ya?ml$/],
    check: (filePath, content) => {
      if (/pull_request_target/.test(content) && /actions\/checkout.*ref.*pull_request/is.test(content)) {
        return {
          matched: true,
          snippet: 'pull_request_target + checkout of PR code detected',
          note: 'This pattern can expose secrets to untrusted PRs',
        };
      }
      return { matched: false };
    },
  },

  // ===== OBFUSCATION ADVANCED =====
  {
    id: 'obfusc-string-building',
    category: 'OBFUSCATION',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Suspicious string construction',
    description: 'Code builds strings character by character to evade detection',
    remediation: 'Manually decode the constructed string to see what it does',
    filePatterns: [/\.(js|ts)$/],
    check: (filePath, content) => {
      const patterns = [
        /String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+/,
        /\[\s*['"][a-z]['"],\s*['"][a-z]['"].*\]\.join\s*\(\s*['"]['"]?\s*\)/i,
        /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'String built character-by-character to evade detection',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'obfusc-anti-debug',
    category: 'OBFUSCATION',
    severity: 'medium',
    scoreDelta: 20,
    name: 'Anti-debugging techniques',
    description: 'Code contains anti-debugging or VM detection',
    remediation: 'Anti-debug techniques indicate malware trying to evade analysis',
    filePatterns: [/\.(js|ts|py)$/],
    check: (filePath, content) => {
      const patterns = [
        /debugger\s*;.*debugger\s*;/s,
        /setInterval.*debugger/s,
        /(VMware|VirtualBox|Sandbox|QEMU)/i,
        /IsDebuggerPresent/,
        /ptrace.*PTRACE_TRACEME/,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Anti-debugging or VM detection code found',
          };
        }
      }
      return { matched: false };
    },
  },

  // ===== HARDCODED SECRETS =====
  {
    id: 'secret-api-key',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 20,
    name: 'Hardcoded API key',
    description: 'Code contains hardcoded API keys or tokens',
    remediation: 'Remove secrets from code. Use environment variables',
    filePatterns: [/\.(js|ts|py|rb|go|java|php)$/],
    check: (filePath, content) => {
      // Ignore test files
      if (/test|spec|mock|fixture/i.test(filePath)) return { matched: false };
      
      const patterns = [
        /['"]sk-[a-zA-Z0-9]{32,}['"]/,  // OpenAI
        /['"]AKIA[A-Z0-9]{16}['"]/,  // AWS
        /['"]ghp_[a-zA-Z0-9]{36}['"]/,  // GitHub PAT
        /['"]gho_[a-zA-Z0-9]{36}['"]/,  // GitHub OAuth
        /['"]glpat-[a-zA-Z0-9\-_]{20,}['"]/,  // GitLab
        /['"]xox[baprs]-[a-zA-Z0-9\-]+['"]/,  // Slack
        /private_key.*BEGIN.*PRIVATE.*KEY/s,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: `Hardcoded secret: ${match[0].substring(0, 20)}...`,
            note: 'Hardcoded API key or token detected',
          };
        }
      }
      return { matched: false };
    },
  },
];

// Run all rules against a file
export function runRules(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];

  // Run VS Code specific rules first (for .vscode/ files)
  if (filePath.includes('.vscode/')) {
    try {
      const vscodeFindings = detectVSCodeMalware(filePath, content);
      findings.push(...vscodeFindings);
    } catch (e) {
      console.error(`VS Code rules failed on ${filePath}:`, e);
    }
  }

  // Run Git trickery rules
  const gitFiles = ['.gitattributes', '.gitmodules', 'devcontainer'];
  if (gitFiles.some(f => filePath.toLowerCase().includes(f))) {
    try {
      const gitFindings = detectGitTrickery(filePath, content);
      findings.push(...gitFindings);
    } catch (e) {
      console.error(`Git trickery rules failed on ${filePath}:`, e);
    }
  }

  // Run advanced rules (crypto mining, backdoors, Docker, prototype pollution, expanded CI/CD)
  try {
    const advancedFindings = runAdvancedRules(filePath, content);
    findings.push(...advancedFindings);
  } catch (e) {
    console.error(`Advanced rules failed on ${filePath}:`, e);
  }

  // Run extended rules (Categories 14-28: Git config, DevContainer, test frameworks, pre-commit, lockfiles, etc.)
  try {
    const extendedFindings = runExtendedRules(filePath, content);
    findings.push(...extendedFindings);
  } catch (e) {
    console.error(`Extended rules failed on ${filePath}:`, e);
  }

  // Run IDE-specific rules (JetBrains, Vim, Emacs, Sublime, Cursor, Zed, Helix)
  try {
    const ideFindings = detectIDEMalware(filePath, content);
    findings.push(...ideFindings);
  } catch (e) {
    console.error(`IDE rules failed on ${filePath}:`, e);
  }

  // Run browser extension rules
  try {
    const browserExtFindings = detectBrowserExtensionMalware(filePath, content);
    findings.push(...browserExtFindings);
  } catch (e) {
    console.error(`Browser extension rules failed on ${filePath}:`, e);
  }

  // Run container orchestration rules (Kubernetes, Helm, Docker Compose)
  try {
    const containerFindings = detectContainerOrchRisks(filePath, content);
    findings.push(...containerFindings);
  } catch (e) {
    console.error(`Container rules failed on ${filePath}:`, e);
  }

  // Run serverless rules (AWS SAM, Serverless Framework, Vercel, Netlify, CloudFlare)
  try {
    const serverlessFindings = detectServerlessRisks(filePath, content);
    findings.push(...serverlessFindings);
  } catch (e) {
    console.error(`Serverless rules failed on ${filePath}:`, e);
  }

  // Run secrets detection rules
  try {
    const secretsFindings = detectSecretsExposure(filePath, content);
    findings.push(...secretsFindings);
  } catch (e) {
    console.error(`Secrets rules failed on ${filePath}:`, e);
  }

  // Run AI/ML pipeline rules (Pickle, Hugging Face, Jupyter, MLflow)
  try {
    const aimlFindings = detectAIMLRisks(filePath, content);
    findings.push(...aimlFindings);
  } catch (e) {
    console.error(`AI/ML rules failed on ${filePath}:`, e);
  }

  // Run mobile development rules (Android, iOS, React Native, Flutter)
  try {
    const mobileFindings = detectMobileDevRisks(filePath, content);
    findings.push(...mobileFindings);
  } catch (e) {
    console.error(`Mobile dev rules failed on ${filePath}:`, e);
  }

  // Run social engineering rules (Phishing, Fake Installers, Office Macros, PII Harvesting)
  try {
    const socialEngFindings = detectSocialEngineering(filePath, content);
    findings.push(...socialEngFindings);
  } catch (e) {
    console.error(`Social engineering rules failed on ${filePath}:`, e);
  }

  // Run standard rules
  for (const rule of RULES) {
    // Check if file matches any pattern
    const fileMatches = rule.filePatterns.some(pattern => pattern.test(filePath));
    if (!fileMatches) continue;

    try {
      const result = rule.check(filePath, content);
      if (result.matched) {
        findings.push({
          id: rule.id,
          category: rule.category,
          severity: rule.severity,
          scoreDelta: rule.scoreDelta,
          file: filePath,
          lineRange: result.lineRange,
          evidence: {
            snippet: result.snippet || '',
            note: result.note || rule.description,
          },
          remediation: rule.remediation,
        });
      }
    } catch (e) {
      // Rule failed, skip
      console.error(`Rule ${rule.id} failed on ${filePath}:`, e);
    }
  }

  return findings;
}

// Calculate score and label from findings
export function calculateScore(findings: Finding[]): { score: number; label: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' } {
  // Sum scores with category caps to prevent single category domination
  const categoryScores: Record<string, number> = {};
  const categoryCaps: Record<string, number> = {
    EXECUTION_TRIGGER: 45,
    EXFILTRATION: 40,
    OBFUSCATION: 30,
    SOCIAL_ENGINEERING: 25,
    DEPENDENCY_RISK: 25,
    BINARY_SUSPICION: 25,
    CI_CD_RISK: 35,
    SECRETS: 30,
    PERSISTENCE: 35,
    DOWNLOADER: 40,
    BROWSER_EXTENSION: 35,
    CONTAINER_RISK: 40,
    SERVERLESS_RISK: 30,
    AI_ML_RISK: 35,
  };

  // Check for critical severity findings
  let hasCritical = findings.some(f => f.severity === 'critical');

  for (const finding of findings) {
    const current = categoryScores[finding.category] || 0;
    const cap = categoryCaps[finding.category] || 30;
    categoryScores[finding.category] = Math.min(current + finding.scoreDelta, cap);
  }

  const score = Math.min(100, Object.values(categoryScores).reduce((a, b) => a + b, 0));

  let label: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  if (hasCritical || score >= 80) {
    label = 'CRITICAL';
  } else if (score >= 60) {
    label = 'HIGH';
  } else if (score >= 25) {
    label = 'MEDIUM';
  } else {
    label = 'LOW';
  }

  return { score, label };
}

// Get top reasons from findings
export function getTopReasons(findings: Finding[], limit = 5): Array<{ title: string; severity: FindingSeverity; file?: string }> {
  // Sort by severity and score delta
  const sorted = [...findings].sort((a, b) => {
    const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
    const severityDiff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
    if (severityDiff !== 0) return severityDiff;
    return b.scoreDelta - a.scoreDelta;
  });

  return sorted.slice(0, limit).map(f => {
    const rule = RULES.find(r => r.id === f.id);
    return {
      title: rule?.name || f.id,
      severity: f.severity,
      file: f.file,
    };
  });
}

export const RULE_VERSION = '4.2.1';
