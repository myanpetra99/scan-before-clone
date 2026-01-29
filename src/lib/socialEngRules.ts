// Social Engineering Detection Rules - v4.2.1
// Detects phishing, fake installers, Office macros, PII harvesting, and webhook exfiltration

import type { Finding, FindingCategory, FindingSeverity } from '@/types/scanner';

interface RuleMatch {
  matched: boolean;
  snippet?: string;
  note?: string;
}

interface SocialEngRule {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  scoreDelta: number;
  name: string;
  description: string;
  remediation: string;
  filePatterns: RegExp[];
  check: (filePath: string, content: string) => RuleMatch;
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

export const SOCIAL_ENG_RULES: SocialEngRule[] = [
  // ===== FAKE INSTALLER DETECTION =====
  {
    id: 'social-fake-installer-download',
    category: 'SOCIAL_ENGINEERING',
    severity: 'high',
    scoreDelta: 30,
    name: 'Fake software installer download',
    description: 'README instructs to download custom .exe/.dmg/.msi installer from unusual source',
    remediation: 'Never download custom interview/pair-programming software. Use official tools only',
    filePatterns: [/README\.md$/i, /\.md$/, /\.txt$/i],
    check: (filePath, content) => {
      const patterns = [
        // Suspicious download URLs for installers
        /download[^]*\.(exe|dmg|msi|pkg|deb|rpm|appimage)/i,
        // Fake video interview app references
        /(video.?interview|pair.?programming|screen.?share).*(app|tool|software).*download/i,
        // Custom zoom/teams clones
        /(zoom|teams|meet|skype).?(download|installer|setup)[^]*\.(exe|dmg|msi)/i,
        // Curl/wget followed by installer execution
        /(curl|wget)\s+[^\n]*\.(exe|dmg|msi|pkg)[^\n]*(&&|\||\;)\s*(\.\/|chmod|open|start)/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Documentation references downloading custom installer software - common job scam tactic',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'social-installer-download-exec',
    category: 'SOCIAL_ENGINEERING',
    severity: 'high',
    scoreDelta: 25,
    name: 'Installer download and execute pattern',
    description: 'Script downloads and executes installer binary',
    remediation: 'Do not run scripts that download and execute binaries from unknown sources',
    filePatterns: [/\.(sh|bash|ps1|bat|cmd)$/i],
    check: (filePath, content) => {
      const patterns = [
        // Download and execute installer
        /(curl|wget|Invoke-WebRequest)[^\n]*\.(exe|dmg|msi|pkg)[^\n]*(&&|\;|\|)[^\n]*(\.\/|start|open|chmod.*\+x)/i,
        // PowerShell download and run
        /IEX\s*\(.*\.(exe|msi)/i,
        // Hidden installer download
        /download[^\n]*installer[^\n]*(>|>>)\s*[^\s]+\.(exe|dmg|msi)/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Script downloads and executes installer binary',
          };
        }
      }
      return { matched: false };
    },
  },

  // ===== OFFICE MACRO DETECTION =====
  {
    id: 'social-vba-autoopen',
    category: 'SOCIAL_ENGINEERING',
    severity: 'high',
    scoreDelta: 35,
    name: 'VBA Auto-Open macro trigger',
    description: 'VBA macro contains auto-execution triggers (Document_Open, AutoOpen)',
    remediation: 'Never enable macros in documents from untrusted sources',
    filePatterns: [/\.(vba|bas|cls|frm)$/i],
    check: (filePath, content) => {
      const patterns = [
        /Sub\s+(Document_Open|AutoOpen|Workbook_Open|Auto_Open)\s*\(/i,
        /Private\s+Sub\s+(Document_Open|AutoOpen|Workbook_Open)\s*\(/i,
        /Sub\s+AutoExec\s*\(/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'VBA macro will execute automatically when document is opened',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'social-vba-shell-exec',
    category: 'SOCIAL_ENGINEERING',
    severity: 'high',
    scoreDelta: 35,
    name: 'VBA shell command execution',
    description: 'VBA macro executes shell commands via Shell() or WScript',
    remediation: 'VBA executing shell commands is extremely dangerous - do not enable',
    filePatterns: [/\.(vba|bas|cls|frm)$/i],
    check: (filePath, content) => {
      const patterns = [
        /Shell\s*\([^)]*\)/i,
        /CreateObject\s*\(\s*["']WScript\.Shell["']\s*\)/i,
        /CreateObject\s*\(\s*["']Shell\.Application["']\s*\)/i,
        /\.Run\s+["'][^"']*cmd|powershell|bash/i,
        /WScript\.Shell.*\.Exec/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'VBA macro executes shell commands - common malware technique',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'social-vba-network-download',
    category: 'SOCIAL_ENGINEERING',
    severity: 'high',
    scoreDelta: 30,
    name: 'VBA network download pattern',
    description: 'VBA macro downloads files from the internet',
    remediation: 'Macros downloading external content are highly suspicious',
    filePatterns: [/\.(vba|bas|cls|frm)$/i],
    check: (filePath, content) => {
      const patterns = [
        /URLDownloadToFile/i,
        /CreateObject\s*\(\s*["']MSXML2\.XMLHTTP["']\s*\)/i,
        /CreateObject\s*\(\s*["']WinHttp\.WinHttpRequest["']\s*\)/i,
        /\.Open\s+["']GET["']\s*,\s*["']https?:/i,
        /Environ\s*\(\s*["']USERPROFILE["']\s*\)/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'VBA macro downloads content from the internet',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'social-office-macro-file',
    category: 'SOCIAL_ENGINEERING',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Macro-enabled Office document',
    description: 'Repository contains macro-enabled Office files (.xlsm, .docm, .pptm)',
    remediation: 'Macro-enabled documents from unknown sources should never be opened with macros enabled',
    filePatterns: [/\.(xlsm|docm|pptm|xlsb|dotm|potm|ppam|sldm)$/i],
    check: (filePath, content) => {
      // Just flag the presence of macro-enabled files
      return {
        matched: true,
        snippet: filePath,
        note: 'Macro-enabled Office document found in repository',
      };
    },
  },

  // ===== PII HARVESTING DETECTION =====
  {
    id: 'social-pii-form-ssn',
    category: 'SOCIAL_ENGINEERING',
    severity: 'high',
    scoreDelta: 30,
    name: 'PII harvesting form (SSN/ID)',
    description: 'HTML form collects Social Security Number or government ID',
    remediation: 'Legitimate coding projects never need your SSN or passport number',
    filePatterns: [/\.(html?|jsx?|tsx?)$/i],
    check: (filePath, content) => {
      const patterns = [
        /<input[^>]*(name|id)\s*=\s*["'](ssn|social.?security|passport|national.?id|driver.?license|tax.?id|ein)["'][^>]*>/i,
        /placeholder\s*=\s*["'][^"']*(ssn|social.?security.?number|passport.?number|national.?id)["']/i,
        /(label|aria-label)\s*=?\s*["'][^"']*(ssn|social.?security|passport|government.?id)["']/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Form collects sensitive government ID - possible identity theft scam',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'social-pii-form-bank',
    category: 'SOCIAL_ENGINEERING',
    severity: 'high',
    scoreDelta: 30,
    name: 'PII harvesting form (banking)',
    description: 'HTML form collects bank account or routing numbers',
    remediation: 'Never enter banking information in coding challenge applications',
    filePatterns: [/\.(html?|jsx?|tsx?)$/i],
    check: (filePath, content) => {
      const patterns = [
        /<input[^>]*(name|id)\s*=\s*["'](bank.?account|routing.?number|account.?number|iban|swift|bic)["'][^>]*>/i,
        /placeholder\s*=\s*["'][^"]*(routing.?number|account.?number|bank.?account|iban)["']/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Form collects banking information - possible financial scam',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'social-pii-id-upload',
    category: 'SOCIAL_ENGINEERING',
    severity: 'high',
    scoreDelta: 25,
    name: 'Identity document upload request',
    description: 'Form requests upload of identity documents (passport, ID, license)',
    remediation: 'Legitimate job processes never require ID uploads before hiring',
    filePatterns: [/\.(html?|jsx?|tsx?)$/i],
    check: (filePath, content) => {
      const patterns = [
        /<input[^>]*type\s*=\s*["']file["'][^>]*(accept|id|name)\s*=\s*["'][^"']*(passport|id.?card|driver|license|identity)["']/i,
        /(upload|attach)[^<>]*(passport|id.?card|driver.?license|government.?id|photo.?id)/i,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Form requests identity document upload - possible identity theft',
          };
        }
      }
      return { matched: false };
    },
  },

  // ===== WEBHOOK EXFILTRATION =====
  {
    id: 'social-discord-webhook',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 30,
    name: 'Discord webhook exfiltration',
    description: 'Code sends data to Discord webhook (common for credential theft)',
    remediation: 'Discord webhooks in non-Discord projects are often used for data theft',
    filePatterns: [/\.(js|ts|py|rb|go|sh|ps1)$/i],
    check: (filePath, content) => {
      const patterns = [
        /discord\.com\/api\/webhooks\/\d+/i,
        /discordapp\.com\/api\/webhooks\/\d+/i,
        // Sending env/creds to Discord
        /discord.*webhook[^]*process\.env|process\.env[^]*discord.*webhook/is,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Data exfiltration to Discord webhook detected',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'social-telegram-bot',
    category: 'EXFILTRATION',
    severity: 'high',
    scoreDelta: 30,
    name: 'Telegram bot exfiltration',
    description: 'Code sends data to Telegram bot (common for credential theft)',
    remediation: 'Telegram bot API calls in unexpected projects often indicate data theft',
    filePatterns: [/\.(js|ts|py|rb|go|sh|ps1)$/i],
    check: (filePath, content) => {
      const patterns = [
        /api\.telegram\.org\/bot[A-Za-z0-9_:-]+\/(sendMessage|sendDocument|sendPhoto)/i,
        /telegram[^]*send[^]*(env|password|token|secret|key|cred)/is,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Data exfiltration to Telegram bot detected',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'social-slack-webhook-creds',
    category: 'EXFILTRATION',
    severity: 'medium',
    scoreDelta: 20,
    name: 'Slack webhook with credentials',
    description: 'Code sends credentials or secrets to Slack webhook',
    remediation: 'Sending credentials to webhooks is a red flag for data theft',
    filePatterns: [/\.(js|ts|py|rb|go|sh|ps1)$/i],
    check: (filePath, content) => {
      const pattern = /hooks\.slack\.com\/services\/[^]*?(password|secret|token|key|cred|env)/is;
      const match = content.match(pattern);
      if (match) {
        return {
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: 'Credentials being sent to Slack webhook',
        };
      }
      return { matched: false };
    },
  },

  // ===== PHISHING DETECTION =====
  {
    id: 'social-phishing-login-form',
    category: 'SOCIAL_ENGINEERING',
    severity: 'high',
    scoreDelta: 25,
    name: 'Suspicious login form pattern',
    description: 'Login form posts credentials to external or suspicious domain',
    remediation: 'Never enter credentials in clone/lookalike login pages',
    filePatterns: [/\.(html?|jsx?|tsx?|php)$/i],
    check: (filePath, content) => {
      // Login form posting to external URL
      const patterns = [
        /<form[^>]*action\s*=\s*["']https?:\/\/[^"']*["'][^>]*>[^]*?(password|passwd|pwd)[^]*?<\/form>/is,
        // Hidden fields collecting credentials
        /<input[^>]*type\s*=\s*["']hidden["'][^>]*(password|token|session|auth)/i,
        // Fake OAuth patterns
        /<form[^>]*action\s*=\s*["'][^"']*(oauth|signin|login)[^"']*["'][^>]*>.*?(google|github|facebook|linkedin)/is,
      ];
      for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
          return {
            matched: true,
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: 'Suspicious login form that may be phishing for credentials',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'social-fake-hr-portal',
    category: 'SOCIAL_ENGINEERING',
    severity: 'medium',
    scoreDelta: 20,
    name: 'Fake HR/onboarding portal pattern',
    description: 'Code mimics HR portal collecting personal information',
    remediation: 'Real HR portals are on company domains - verify before entering data',
    filePatterns: [/\.(html?|jsx?|tsx?)$/i],
    check: (filePath, content) => {
      // Combination of HR-related terms with form collection
      const pattern = /(onboarding|employee|new.?hire|hr.?portal|background.?check)[^]*?<form[^>]*>[^]*?(ssn|salary|bank|routing)/is;
      const match = content.match(pattern);
      if (match) {
        return {
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: 'Fake HR portal collecting sensitive personal information',
        };
      }
      return { matched: false };
    },
  },

  // ===== SOCIAL PLATFORM REDIRECT =====
  {
    id: 'social-offplatform-redirect',
    category: 'SOCIAL_ENGINEERING',
    severity: 'medium',
    scoreDelta: 15,
    name: 'Off-platform communication request',
    description: 'README pushes users to Discord/Telegram instead of staying on platform',
    remediation: 'Legitimate projects use official channels - moving off-platform is a red flag',
    filePatterns: [/README\.md$/i, /\.md$/],
    check: (filePath, content) => {
      // Multiple patterns indicating push to move off-platform
      const patterns = [
        /(contact|message|reach|dm)\s+(us\s+)?(on|via|at)\s+(discord|telegram|whatsapp)/i,
        /join\s+(our\s+)?(private\s+)?(discord|telegram)\s+(server|channel|group)/i,
        /(discuss|continue|talk)\s+(in|on|via)\s+(discord|telegram)/i,
      ];
      // Only flag if combined with suspicious context
      const suspiciousContext = /(job|interview|opportunity|hiring|recruitment|onboarding)/i;
      if (suspiciousContext.test(content)) {
        for (const pattern of patterns) {
          const match = content.match(pattern);
          if (match) {
            return {
              matched: true,
              snippet: extractSnippet(content, match.index || 0, match[0].length),
              note: 'Suspicious request to move job-related communication off-platform',
            };
          }
        }
      }
      return { matched: false };
    },
  },
];

/**
 * Run social engineering detection rules against a file
 */
export function detectSocialEngineering(
  filePath: string,
  content: string
): Finding[] {
  const findings: Finding[] = [];

  for (const rule of SOCIAL_ENG_RULES) {
    // Check if file matches rule's file patterns
    const fileMatches = rule.filePatterns.some(pattern => pattern.test(filePath));
    if (!fileMatches) continue;

    try {
      const result = rule.check(filePath, content);
      if (result.matched) {
        findings.push({
          id: rule.id,
          category: rule.category,
          severity: rule.severity,
          file: filePath,
          evidence: {
            snippet: result.snippet || '',
            note: result.note || rule.description,
          },
          remediation: rule.remediation,
          scoreDelta: rule.scoreDelta,
        });
      }
    } catch (e) {
      // Rule threw - skip it
      console.warn(`Rule ${rule.id} threw error on ${filePath}:`, e);
    }
  }

  return findings;
}
