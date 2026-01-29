// Git Trickery Detection Rules
// Detects malicious .gitattributes, .gitmodules, and related patterns

import type { Finding, FindingCategory, FindingSeverity } from '@/types/scanner';

interface GitTrickeryMatch {
  matched: boolean;
  snippet?: string;
  note?: string;
  severity?: FindingSeverity;
}

/**
 * Detect malicious .gitattributes patterns
 * - Suspicious filter= attributes (smudge/clean filters execute code)
 * - LFS patterns that could pull unexpected binaries
 */
function detectGitattributesTrickery(content: string): GitTrickeryMatch {
  const lines = content.split('\n');
  const suspiciousPatterns: string[] = [];
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    
    // Detect custom filter= attributes (code execution vector)
    const filterMatch = trimmed.match(/filter=([^\s]+)/);
    if (filterMatch) {
      const filterName = filterMatch[1];
      // Common safe filters
      if (!['lfs', 'git-lfs'].includes(filterName.toLowerCase())) {
        suspiciousPatterns.push(`Custom filter "${filterName}" detected: ${trimmed}`);
      }
    }
    
    // Detect smudge= and clean= (direct code execution)
    if (/smudge\s*=|clean\s*=/.test(trimmed)) {
      suspiciousPatterns.push(`Git smudge/clean filter: ${trimmed}`);
    }
    
    // Detect diff= with custom drivers
    const diffMatch = trimmed.match(/diff=([^\s]+)/);
    if (diffMatch && !['binary', 'text'].includes(diffMatch[1].toLowerCase())) {
      suspiciousPatterns.push(`Custom diff driver: ${trimmed}`);
    }
  }
  
  if (suspiciousPatterns.length > 0) {
    return {
      matched: true,
      snippet: suspiciousPatterns.join('\n').substring(0, 400),
      note: 'Git attributes may execute code when checking out or diffing files',
      severity: 'high',
    };
  }
  
  return { matched: false };
}

/**
 * Detect malicious .gitmodules patterns
 * - Submodules pointing to suspicious URLs
 * - Raw IP addresses
 * - Unusual protocols
 */
function detectGitmodulesTrickery(content: string): GitTrickeryMatch {
  const lines = content.split('\n');
  const suspiciousPatterns: string[] = [];
  let currentSubmodule = '';
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Track current submodule
    const submoduleMatch = trimmed.match(/\[submodule\s+"([^"]+)"\]/);
    if (submoduleMatch) {
      currentSubmodule = submoduleMatch[1];
      continue;
    }
    
    // Check URL patterns
    const urlMatch = trimmed.match(/url\s*=\s*(.+)/);
    if (urlMatch) {
      const url = urlMatch[1].trim();
      
      // Raw IP address
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
        suspiciousPatterns.push(`Submodule "${currentSubmodule}" points to IP address: ${url}`);
      }
      
      // Unusual protocols
      if (/^(ftp|file|gopher):/.test(url)) {
        suspiciousPatterns.push(`Submodule "${currentSubmodule}" uses unusual protocol: ${url}`);
      }
      
      // Non-GitHub/GitLab/Bitbucket git URLs (suspicious)
      if (url.includes('git@') || url.includes('git://')) {
        const domain = url.match(/@([^:\/]+)/)?.[1] || url.match(/:\/\/([^\/]+)/)?.[1];
        if (domain && !['github.com', 'gitlab.com', 'bitbucket.org', 'git.sr.ht'].includes(domain)) {
          suspiciousPatterns.push(`Submodule "${currentSubmodule}" from unknown host: ${domain}`);
        }
      }
    }
    
    // Check for update=checkout or update=merge (less common, but can be risky)
    if (/update\s*=\s*(checkout|merge|rebase)/.test(trimmed)) {
      suspiciousPatterns.push(`Submodule "${currentSubmodule}" has update strategy: ${trimmed}`);
    }
  }
  
  if (suspiciousPatterns.length > 0) {
    return {
      matched: true,
      snippet: suspiciousPatterns.join('\n').substring(0, 400),
      note: 'Submodules can pull arbitrary code. Do NOT use --recurse-submodules until reviewed',
      severity: suspiciousPatterns.some(p => p.includes('IP address')) ? 'high' : 'medium',
    };
  }
  
  return { matched: false };
}

/**
 * Detect malicious devcontainer patterns
 */
function detectDevcontainerTrickery(content: string): GitTrickeryMatch {
  const suspiciousPatterns: string[] = [];
  
  // Look for dangerous postCreateCommand, postStartCommand, etc.
  const commandPatterns = [
    /postCreateCommand['"]\s*:\s*['"]([^'"]+)['"]/gi,
    /postStartCommand['"]\s*:\s*['"]([^'"]+)['"]/gi,
    /initializeCommand['"]\s*:\s*['"]([^'"]+)['"]/gi,
    /onCreateCommand['"]\s*:\s*['"]([^'"]+)['"]/gi,
  ];
  
  for (const pattern of commandPatterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const command = match[1];
      // Check for dangerous patterns
      if (/curl|wget|bash|sh\s+-c|eval|exec|python\s+-c|node\s+-e|powershell/.test(command)) {
        suspiciousPatterns.push(`Devcontainer command: ${match[0].substring(0, 100)}`);
      }
    }
  }
  
  // Check for suspicious extensions
  if (/extensions['"]\s*:\s*\[/.test(content)) {
    // Look for non-standard extension publishers
    const extensionMatch = content.match(/extensions['"]\s*:\s*\[([\s\S]*?)\]/);
    if (extensionMatch) {
      const extensions = extensionMatch[1];
      // Flag if it contains non-Microsoft/popular publishers
      if (!/ms-|microsoft\.|vscode\./.test(extensions.toLowerCase())) {
        suspiciousPatterns.push(`Devcontainer requests custom extensions: review before opening`);
      }
    }
  }
  
  // Check for privileged mode
  if (/privileged['"]\s*:\s*true|--privileged/.test(content)) {
    suspiciousPatterns.push('Devcontainer requests privileged mode (full host access)');
  }
  
  // Check for host mount
  if (/source['"]\s*:\s*['"]\/(home|Users|root)/.test(content)) {
    suspiciousPatterns.push('Devcontainer mounts sensitive host directories');
  }
  
  if (suspiciousPatterns.length > 0) {
    return {
      matched: true,
      snippet: suspiciousPatterns.join('\n').substring(0, 400),
      note: 'Devcontainer executes when you open the folder. Review before opening in VS Code',
      severity: suspiciousPatterns.some(p => p.includes('privileged') || p.includes('mounts')) ? 'critical' : 'high',
    };
  }
  
  return { matched: false };
}

/**
 * Main function to detect git trickery patterns
 */
export function detectGitTrickery(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const pathLower = filePath.toLowerCase();
  
  // .gitattributes
  if (pathLower.endsWith('.gitattributes')) {
    const result = detectGitattributesTrickery(content);
    if (result.matched) {
      findings.push({
        id: 'git-attributes-filter',
        category: 'EXECUTION_TRIGGER' as FindingCategory,
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'critical' ? 30 : 20,
        file: filePath,
        evidence: {
          snippet: result.snippet || '',
          note: result.note || 'Suspicious git attributes',
        },
        remediation: 'Review .gitattributes before cloning. Custom filters execute code during checkout.',
        whyItMatters: 'Git smudge/clean filters can execute arbitrary code when files are checked out',
        whatToCheckNext: ['Check if corresponding filter scripts exist', 'Review .git/config for filter definitions'],
      });
    }
  }
  
  // .gitmodules
  if (pathLower.endsWith('.gitmodules')) {
    const result = detectGitmodulesTrickery(content);
    if (result.matched) {
      findings.push({
        id: 'git-submodule-suspicious',
        category: 'DEPENDENCY_RISK' as FindingCategory,
        severity: result.severity || 'medium',
        scoreDelta: result.severity === 'high' ? 20 : 12,
        file: filePath,
        evidence: {
          snippet: result.snippet || '',
          note: result.note || 'Suspicious git submodules',
        },
        remediation: 'Do NOT use --recurse-submodules. Clone submodules individually after review.',
        whyItMatters: 'Submodules can pull code from arbitrary sources during clone',
        whatToCheckNext: ['Verify submodule URLs point to trusted sources', 'Check each submodule repository independently'],
      });
    }
  }
  
  // devcontainer.json
  if (pathLower.includes('devcontainer') && pathLower.endsWith('.json')) {
    const result = detectDevcontainerTrickery(content);
    if (result.matched) {
      findings.push({
        id: 'devcontainer-exec',
        category: 'EXECUTION_TRIGGER' as FindingCategory,
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'critical' ? 35 : 25,
        file: filePath,
        evidence: {
          snippet: result.snippet || '',
          note: result.note || 'Devcontainer with execution commands',
        },
        remediation: 'Open folder in restricted mode. Review devcontainer.json before allowing VS Code to build container.',
        whyItMatters: 'Devcontainer commands execute automatically when you open the folder in VS Code',
        whatToCheckNext: ['Review postCreateCommand for downloads', 'Check if Dockerfile exists and what it installs'],
      });
    }
  }
  
  return findings;
}
