// Advanced Security Rules - Extended detection capabilities
// Crypto mining, backdoors, container security, prototype pollution, and expanded CI/CD

import type { Finding, FindingCategory, FindingSeverity } from '@/types/scanner';

interface RuleMatch {
  matched: boolean;
  snippet?: string;
  lineRange?: [number, number];
  note?: string;
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

// ========== CRYPTO MINING DETECTION ==========

interface CryptoMiningMatch extends RuleMatch {
  severity?: FindingSeverity;
}

function detectCryptoMining(filePath: string, content: string): CryptoMiningMatch {
  // Known crypto mining libraries and services
  const knownMiners = [
    /coinhive/i,
    /cryptoloot/i,
    /coin-hive/i,
    /crypto-?loot/i,
    /jsecoin/i,
    /cryptonight/i,
    /minero\.cc/i,
    /webminer/i,
    /deepMiner/i,
    /monerominer/i,
    /xmr-?stak/i,
    /mineralt/i,
    /browsermine/i,
  ];

  for (const pattern of knownMiners) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: `Known crypto mining library detected: ${match[0]}`,
        severity: 'high',
      };
    }
  }

  // WebWorker mining patterns
  const workerMiningPatterns = [
    /new\s+Worker\([^)]*miner/i,
    /importScripts\([^)]*(?:coinhive|cryptoloot|miner)/i,
    /CoinHive\.Anonymous/i,
    /CoinHive\.User/i,
  ];

  for (const pattern of workerMiningPatterns) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'WebWorker-based crypto mining pattern detected',
        severity: 'high',
      };
    }
  }

  // WebAssembly mining indicators
  const wasmMiningPatterns = [
    /WebAssembly\.instantiate[^)]*(?:cn|cryptonight|randomx)/i,
    /\.wasm[^)]*(?:miner|hash|cn_)/i,
  ];

  for (const pattern of wasmMiningPatterns) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'WASM-based mining module detected',
        severity: 'high',
      };
    }
  }

  // CPU-intensive loop patterns (potential mining)
  const cpuIntensivePatterns = [
    /while\s*\(\s*true\s*\)\s*\{[^}]*(?:hash|nonce|difficulty)/i,
    /for\s*\([^)]*;\s*;\s*\)[^}]*(?:sha256|keccak|blake)/i,
  ];

  for (const pattern of cpuIntensivePatterns) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'CPU-intensive hashing loop detected (possible mining)',
        severity: 'medium',
      };
    }
  }

  return { matched: false };
}

// ========== BACKDOOR & REVERSE SHELL DETECTION ==========

interface BackdoorMatch extends RuleMatch {
  severity?: FindingSeverity;
}

function detectBackdoors(filePath: string, content: string): BackdoorMatch {
  // Classic reverse shell patterns
  const reverseShellPatterns = [
    // Bash reverse shells
    /bash\s+-i\s+>&\s*\/dev\/tcp\//i,
    /\/bin\/bash\s+-c\s+['"].*\/dev\/tcp\//i,
    /exec\s+\d+<>\/dev\/tcp\//i,
    
    // Netcat reverse shells
    /nc\s+-e\s+\/bin\/(?:ba)?sh/i,
    /nc\s+.*-c\s+\/bin\/(?:ba)?sh/i,
    /netcat\s+-e\s+\/bin\/(?:ba)?sh/i,
    /ncat\s+-e\s+\/bin\/(?:ba)?sh/i,
    /nc\.(?:traditional|openbsd)\s+-e/i,
    
    // Python reverse shells
    /socket\.socket\([^)]*\).*connect\([^)]*\).*(?:subprocess|os\.dup2|pty\.spawn)/s,
    /import\s+socket.*os\.dup2.*subprocess/s,
    /python\s+-c\s+['"]import\s+socket/i,
    
    // Perl reverse shells
    /perl\s+-e\s+['"].*socket.*exec/i,
    /perl\s+-MIO\s+-e/i,
    
    // Ruby reverse shells
    /ruby\s+-rsocket\s+-e/i,
    /TCPSocket\.(?:new|open).*exec/i,
    
    // PHP reverse shells
    /fsockopen\([^)]*\).*(?:fwrite|shell_exec|exec|system)/s,
    /php\s+-r\s+['"].*fsockopen/i,
    
    // PowerShell reverse shells
    /New-Object\s+System\.Net\.Sockets\.TCPClient/i,
    /powershell\s+.*-e\s+[A-Za-z0-9+\/=]{20,}/i,
    /\$client\s*=\s*New-Object\s+System\.Net\.Sockets/i,
  ];

  for (const pattern of reverseShellPatterns) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'Reverse shell pattern detected - CRITICAL THREAT',
        severity: 'critical' as FindingSeverity,
      };
    }
  }

  // Bind shell patterns
  const bindShellPatterns = [
    /nc\s+-l.*-e\s+\/bin\/(?:ba)?sh/i,
    /socat\s+TCP-LISTEN:.*EXEC:/i,
    /\.listen\([^)]*\).*(?:child_process|spawn|exec)/s,
  ];

  for (const pattern of bindShellPatterns) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'Bind shell pattern detected - accepts incoming connections',
        severity: 'critical' as FindingSeverity,
      };
    }
  }

  // Webshell indicators
  const webshellPatterns = [
    /\$_(?:GET|POST|REQUEST)\s*\[[^\]]*\]\s*\(\s*\$_(?:GET|POST|REQUEST)/i, // PHP webshell
    /eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(\s*\$_/i,
    /assert\s*\(\s*\$_(?:GET|POST|REQUEST)/i,
    /preg_replace\s*\([^,]*\/e['"]/i, // PHP code execution
    /create_function\s*\([^,]*,\s*\$_/i,
  ];

  for (const pattern of webshellPatterns) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'Webshell pattern detected',
        severity: 'critical' as FindingSeverity,
      };
    }
  }

  // Remote code execution stubs
  const rcePatterns = [
    /child_process.*spawn.*\$\{/s, // Template injection to spawn
    /exec\s*\(\s*req\.(?:query|body|params)/i,
    /eval\s*\(\s*req\.(?:query|body|params)/i,
    /new\s+Function\s*\([^)]*req\./i,
  ];

  for (const pattern of rcePatterns) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'Remote code execution vulnerability pattern',
        severity: 'high',
      };
    }
  }

  return { matched: false };
}

// ========== DOCKERFILE SECURITY ==========

interface DockerMatch extends RuleMatch {
  severity?: FindingSeverity;
  ruleId?: string;
}

function detectDockerfileIssues(filePath: string, content: string): DockerMatch[] {
  const findings: DockerMatch[] = [];

  // Privileged container
  if (/--privileged/i.test(content)) {
    const match = content.match(/--privileged/i);
    findings.push({
      matched: true,
      snippet: extractSnippet(content, match?.index || 0, 12),
      note: 'Container runs with --privileged flag (full host access)',
      severity: 'critical' as FindingSeverity,
      ruleId: 'docker-privileged',
    });
  }

  // Dangerous capabilities
  const capPatterns = [
    /--cap-add\s*[=\s]*SYS_ADMIN/i,
    /--cap-add\s*[=\s]*SYS_PTRACE/i,
    /--cap-add\s*[=\s]*NET_ADMIN/i,
    /--cap-add\s*[=\s]*ALL/i,
  ];

  for (const pattern of capPatterns) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: `Dangerous capability added: ${match[0]}`,
        severity: 'high',
        ruleId: 'docker-dangerous-cap',
      });
    }
  }

  // Secrets in Dockerfile
  const secretPatterns = [
    /ENV\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*[=\s]/i,
    /ARG\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\s*=/i,
    /echo\s+['"][^'"]*(?:password|secret|key|token)[^'"]*['"].*>>/i,
  ];

  for (const pattern of secretPatterns) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'Hardcoded secret in Dockerfile',
        severity: 'high',
        ruleId: 'docker-hardcoded-secret',
      });
    }
  }

  // Running as root without user switch
  if (!/USER\s+\S+/i.test(content) && /FROM\s+/i.test(content)) {
    findings.push({
      matched: true,
      snippet: 'No USER instruction found',
      note: 'Container runs as root by default (no USER instruction)',
      severity: 'medium',
      ruleId: 'docker-no-user',
    });
  }

  // Insecure curl | bash in Dockerfile
  const curlBashMatch = content.match(/(curl|wget)\s+[^\n]*\|\s*(bash|sh)/i);
  if (curlBashMatch) {
    findings.push({
      matched: true,
      snippet: extractSnippet(content, curlBashMatch.index || 0, curlBashMatch[0].length),
      note: 'Dockerfile downloads and executes remote scripts',
      severity: 'high',
      ruleId: 'docker-curl-bash',
    });
  }

  // Latest tag usage
  const latestMatch = content.match(/FROM\s+\S+:latest/i);
  if (latestMatch) {
    findings.push({
      matched: true,
      snippet: extractSnippet(content, latestMatch.index || 0, latestMatch[0].length),
      note: 'Using :latest tag - builds are not reproducible',
      severity: 'low',
      ruleId: 'docker-latest-tag',
    });
  }

  // ADD instead of COPY for remote URLs
  const addMatch = content.match(/ADD\s+https?:\/\//i);
  if (addMatch) {
    findings.push({
      matched: true,
      snippet: extractSnippet(content, addMatch.index || 0, addMatch[0].length),
      note: 'ADD with remote URL - use COPY + curl for verification',
      severity: 'medium',
      ruleId: 'docker-add-url',
    });
  }

  return findings;
}

// ========== PROTOTYPE POLLUTION DETECTION ==========

interface PrototypePollutionMatch extends RuleMatch {
  severity?: FindingSeverity;
}

function detectPrototypePollution(filePath: string, content: string): PrototypePollutionMatch {
  // Direct __proto__ manipulation
  const protoPatterns = [
    /\[\s*['"]__proto__['"]\s*\]/,
    /\.\s*__proto__\s*=/,
    /Object\.setPrototypeOf\s*\(/,
    /\[\s*['"]constructor['"]\s*\]\s*\[\s*['"]prototype['"]\s*\]/,
    /\.constructor\.prototype\s*=/,
    /\.constructor\s*\[\s*['"]prototype['"]\s*\]/,
  ];

  for (const pattern of protoPatterns) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'Prototype pollution pattern - can modify Object.prototype',
        severity: 'high',
      };
    }
  }

  // Unsafe object merge patterns (common in prototype pollution)
  const unsafeMergePatterns = [
    /function\s+\w*merge\w*\s*\([^)]*\)\s*\{[^}]*for\s*\([^)]*in\s+[^)]*\)[^}]*\[[^\]]+\]\s*=[^}]*\}/s,
    /Object\.assign\s*\(\s*\{\s*\}\s*,.*\$\{/,
    /\.\.\.\s*req\.(?:body|query|params)/,
  ];

  for (const pattern of unsafeMergePatterns) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, Math.min(match[0].length, 200)),
        note: 'Unsafe object merge that may allow prototype pollution',
        severity: 'medium',
      };
    }
  }

  return { matched: false };
}

// ========== EXPANDED CI/CD DETECTION ==========

interface CICDMatch extends RuleMatch {
  severity?: FindingSeverity;
  ruleId?: string;
}

function detectCICDRisks(filePath: string, content: string): CICDMatch[] {
  const findings: CICDMatch[] = [];
  const lowerPath = filePath.toLowerCase();

  // GitLab CI
  if (lowerPath.includes('.gitlab-ci.yml') || lowerPath.includes('gitlab-ci.yaml')) {
    // Unpinned images
    const unpinnedMatch = content.match(/image:\s*["']?(\S+):latest/i);
    if (unpinnedMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, unpinnedMatch.index || 0, unpinnedMatch[0].length),
        note: `GitLab CI uses unpinned :latest image: ${unpinnedMatch[1]}`,
        severity: 'medium',
        ruleId: 'gitlab-unpinned-image',
      });
    }

    // Script execution from variables
    const evalMatch = content.match(/script:\s*\n\s*-\s*\$\{?\w+\}?/);
    if (evalMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, evalMatch.index || 0, evalMatch[0].length),
        note: 'GitLab CI executes commands from variables',
        severity: 'high',
        ruleId: 'gitlab-variable-exec',
      });
    }

    // curl | bash in scripts
    const curlBashMatch = content.match(/(curl|wget)\s+[^\n]*\|\s*(bash|sh)/i);
    if (curlBashMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, curlBashMatch.index || 0, curlBashMatch[0].length),
        note: 'GitLab CI downloads and executes remote scripts',
        severity: 'high',
        ruleId: 'gitlab-curl-bash',
      });
    }
  }

  // CircleCI
  if (lowerPath.includes('.circleci/config')) {
    // Unpinned orbs
    const orbMatch = content.match(/orbs:\s*\n[^:]+:\s*(\S+)@(?:volatile|latest)/);
    if (orbMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, orbMatch.index || 0, orbMatch[0].length),
        note: 'CircleCI uses unpinned orb version',
        severity: 'medium',
        ruleId: 'circleci-unpinned-orb',
      });
    }

    // curl | bash
    const curlBashMatch = content.match(/(curl|wget)\s+[^\n]*\|\s*(bash|sh)/i);
    if (curlBashMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, curlBashMatch.index || 0, curlBashMatch[0].length),
        note: 'CircleCI downloads and executes remote scripts',
        severity: 'high',
        ruleId: 'circleci-curl-bash',
      });
    }
  }

  // Bitbucket Pipelines
  if (lowerPath.includes('bitbucket-pipelines.yml')) {
    // Unpinned images
    const unpinnedMatch = content.match(/image:\s*["']?(\S+):latest/i);
    if (unpinnedMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, unpinnedMatch.index || 0, unpinnedMatch[0].length),
        note: `Bitbucket Pipeline uses unpinned :latest image: ${unpinnedMatch[1]}`,
        severity: 'medium',
        ruleId: 'bitbucket-unpinned-image',
      });
    }

    // curl | bash
    const curlBashMatch = content.match(/(curl|wget)\s+[^\n]*\|\s*(bash|sh)/i);
    if (curlBashMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, curlBashMatch.index || 0, curlBashMatch[0].length),
        note: 'Bitbucket Pipeline downloads and executes remote scripts',
        severity: 'high',
        ruleId: 'bitbucket-curl-bash',
      });
    }
  }

  // Azure Pipelines
  if (lowerPath.includes('azure-pipelines.yml') || lowerPath.includes('azure-pipelines.yaml')) {
    // Unpinned container
    const containerMatch = content.match(/container:\s*["']?(\S+):latest/i);
    if (containerMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, containerMatch.index || 0, containerMatch[0].length),
        note: `Azure Pipeline uses unpinned container: ${containerMatch[1]}`,
        severity: 'medium',
        ruleId: 'azure-unpinned-container',
      });
    }

    // curl | bash
    const curlBashMatch = content.match(/(curl|wget)\s+[^\n]*\|\s*(bash|sh)/i);
    if (curlBashMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, curlBashMatch.index || 0, curlBashMatch[0].length),
        note: 'Azure Pipeline downloads and executes remote scripts',
        severity: 'high',
        ruleId: 'azure-curl-bash',
      });
    }
  }

  // Travis CI
  if (lowerPath.includes('.travis.yml')) {
    // curl | bash in before_install or install
    const curlBashMatch = content.match(/(curl|wget)\s+[^\n]*\|\s*(bash|sh)/i);
    if (curlBashMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, curlBashMatch.index || 0, curlBashMatch[0].length),
        note: 'Travis CI downloads and executes remote scripts',
        severity: 'high',
        ruleId: 'travis-curl-bash',
      });
    }
  }

  // Jenkins
  if (lowerPath.includes('jenkinsfile') || lowerPath.endsWith('.jenkins')) {
    // Groovy code execution
    const evalMatch = content.match(/evaluate\s*\(/i);
    if (evalMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, evalMatch.index || 0, evalMatch[0].length),
        note: 'Jenkins pipeline uses dynamic Groovy evaluation',
        severity: 'high',
        ruleId: 'jenkins-groovy-eval',
      });
    }

    // curl | bash
    const curlBashMatch = content.match(/(curl|wget)\s+[^\n]*\|\s*(bash|sh)/i);
    if (curlBashMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, curlBashMatch.index || 0, curlBashMatch[0].length),
        note: 'Jenkins pipeline downloads and executes remote scripts',
        severity: 'high',
        ruleId: 'jenkins-curl-bash',
      });
    }
  }

  // Drone CI
  if (lowerPath.includes('.drone.yml') || lowerPath.includes('.drone.yaml')) {
    // curl | bash
    const curlBashMatch = content.match(/(curl|wget)\s+[^\n]*\|\s*(bash|sh)/i);
    if (curlBashMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, curlBashMatch.index || 0, curlBashMatch[0].length),
        note: 'Drone CI downloads and executes remote scripts',
        severity: 'high',
        ruleId: 'drone-curl-bash',
      });
    }
    
    // Privileged execution
    const privilegedMatch = content.match(/privileged:\s*true/i);
    if (privilegedMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, privilegedMatch.index || 0, privilegedMatch[0].length),
        note: 'Drone CI step runs in privileged mode',
        severity: 'high',
        ruleId: 'drone-privileged',
      });
    }
  }

  // Woodpecker CI
  if (lowerPath.includes('.woodpecker.yml') || lowerPath.includes('.woodpecker.yaml') || lowerPath.includes('.woodpecker/')) {
    // curl | bash
    const curlBashMatch = content.match(/(curl|wget)\s+[^\n]*\|\s*(bash|sh)/i);
    if (curlBashMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, curlBashMatch.index || 0, curlBashMatch[0].length),
        note: 'Woodpecker CI downloads and executes remote scripts',
        severity: 'high',
        ruleId: 'woodpecker-curl-bash',
      });
    }
  }

  // Tekton Pipelines
  if (lowerPath.includes('tekton') || (lowerPath.includes('pipeline') && /kind:\s*(?:Pipeline|Task|PipelineRun)/i.test(content))) {
    // Script with dangerous commands
    const scriptMatch = content.match(/script:\s*\|[\s\S]*?(curl|wget|bash\s+-c)/i);
    if (scriptMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, scriptMatch.index || 0, scriptMatch[0].length),
        note: 'Tekton pipeline script contains dangerous commands',
        severity: 'high',
        ruleId: 'tekton-script-exec',
      });
    }
  }

  return findings;
}

// ========== TIME-DELAYED EXECUTION ==========

function detectDelayedExecution(filePath: string, content: string): RuleMatch {
  // Suspicious setTimeout/setInterval with execution
  const delayPatterns = [
    /setTimeout\s*\([^,]*(?:eval|exec|spawn|Function)[^,]*,\s*\d{4,}/s, // Long delay before execution
    /setInterval\s*\([^,]*(?:fetch|XMLHttpRequest|\.send)[^,]*,\s*\d{5,}/s, // Periodic data exfil
    /sleep\s*\(\s*\d{4,}\s*\).*(?:eval|exec|system)/s, // Python sleep before exec
    /time\.sleep\s*\(\s*\d+\s*\).*(?:subprocess|os\.system)/s,
  ];

  for (const pattern of delayPatterns) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, Math.min(match[0].length, 200)),
        note: 'Delayed execution pattern - may evade sandbox timeouts',
      };
    }
  }

  return { matched: false };
}

// ========== SSRF INDICATORS ==========

function detectSSRFPatterns(filePath: string, content: string): RuleMatch {
  // Internal IP/metadata patterns in URLs
  const ssrfPatterns = [
    /(?:fetch|axios|request|http\.get)\s*\([^)]*(?:169\.254\.169\.254|metadata\.google|100\.100\.100\.200)/i,
    /(?:fetch|axios|request|http\.get)\s*\([^)]*(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0)/i,
    /(?:fetch|axios|request|http\.get)\s*\([^)]*(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)/i,
    /url\s*[=:]\s*['"]\s*\+\s*req\.(?:query|body|params)/i, // User-controlled URL
  ];

  for (const pattern of ssrfPatterns) {
    const match = content.match(pattern);
    if (match) {
      return {
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'Potential SSRF - requests to internal/metadata endpoints',
      };
    }
  }

  return { matched: false };
}

// ========== MAIN EXPORT ==========

export function runAdvancedRules(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lowerPath = filePath.toLowerCase();

  // Crypto Mining Detection (JS/TS/HTML files)
  if (/\.(js|ts|jsx|tsx|html|htm)$/i.test(filePath)) {
    const cryptoResult = detectCryptoMining(filePath, content);
    if (cryptoResult.matched) {
      findings.push({
        id: 'crypto-mining',
        category: 'EXFILTRATION', // Using existing category
        severity: cryptoResult.severity || 'high',
        scoreDelta: cryptoResult.severity === 'high' ? 30 : 15,
        file: filePath,
        evidence: {
          snippet: cryptoResult.snippet || '',
          note: cryptoResult.note || 'Crypto mining code detected',
        },
        remediation: 'Remove cryptocurrency mining code. This hijacks user CPU resources.',
      });
    }
  }

  // Backdoor Detection (all code files)
  if (/\.(js|ts|py|rb|php|sh|bash|ps1|pl)$/i.test(filePath)) {
    const backdoorResult = detectBackdoors(filePath, content);
    if (backdoorResult.matched) {
      findings.push({
        id: 'backdoor-detected',
        category: 'EXFILTRATION',
        severity: backdoorResult.severity || 'high',
        scoreDelta: backdoorResult.severity === 'critical' ? 50 : 35,
        file: filePath,
        evidence: {
          snippet: backdoorResult.snippet || '',
          note: backdoorResult.note || 'Backdoor or reverse shell detected',
        },
        remediation: 'DO NOT RUN THIS CODE. Contains backdoor/reverse shell. Report to repository owner.',
      });
    }
  }

  // Dockerfile Security
  if (lowerPath.includes('dockerfile') || lowerPath.endsWith('.dockerfile')) {
    const dockerResults = detectDockerfileIssues(filePath, content);
    for (const result of dockerResults) {
      if (result.matched) {
        findings.push({
          id: result.ruleId || 'docker-security',
          category: 'CI_CD_RISK',
          severity: result.severity || 'medium',
          scoreDelta: result.severity === 'critical' ? 35 : result.severity === 'high' ? 20 : 10,
          file: filePath,
          evidence: {
            snippet: result.snippet || '',
            note: result.note || 'Docker security issue',
          },
          remediation: 'Review Dockerfile security. Use non-root user, pin image versions, avoid privileged mode.',
        });
      }
    }
  }

  // Prototype Pollution (JS/TS files)
  if (/\.(js|ts|jsx|tsx)$/i.test(filePath)) {
    const protoResult = detectPrototypePollution(filePath, content);
    if (protoResult.matched) {
      findings.push({
        id: 'prototype-pollution',
        category: 'OBFUSCATION',
        severity: protoResult.severity || 'high',
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: protoResult.snippet || '',
          note: protoResult.note || 'Prototype pollution pattern',
        },
        remediation: 'Avoid __proto__ manipulation. Use Object.create(null) for safe dictionaries.',
      });
    }
  }

  // CI/CD Risks (expanded platforms)
  const cicdFiles = [
    '.gitlab-ci.yml', '.gitlab-ci.yaml',
    '.circleci/config', 'bitbucket-pipelines.yml',
    'azure-pipelines.yml', 'azure-pipelines.yaml',
    '.travis.yml', 'jenkinsfile', '.jenkins',
    '.drone.yml', '.drone.yaml',
    '.woodpecker.yml', '.woodpecker.yaml',
    'tekton', 'pipeline.yaml', 'pipelinerun.yaml',
  ];
  
  if (cicdFiles.some(f => lowerPath.includes(f))) {
    const cicdResults = detectCICDRisks(filePath, content);
    for (const result of cicdResults) {
      if (result.matched) {
        findings.push({
          id: result.ruleId || 'cicd-risk',
          category: 'CI_CD_RISK',
          severity: result.severity || 'medium',
          scoreDelta: result.severity === 'high' ? 20 : 10,
          file: filePath,
          evidence: {
            snippet: result.snippet || '',
            note: result.note || 'CI/CD security issue',
          },
          remediation: 'Pin CI/CD dependencies, avoid curl|bash patterns, review pipeline permissions.',
        });
      }
    }
  }

  // Delayed Execution Detection
  if (/\.(js|ts|py|rb)$/i.test(filePath)) {
    const delayResult = detectDelayedExecution(filePath, content);
    if (delayResult.matched) {
      findings.push({
        id: 'delayed-execution',
        category: 'OBFUSCATION',
        severity: 'medium',
        scoreDelta: 15,
        file: filePath,
        evidence: {
          snippet: delayResult.snippet || '',
          note: delayResult.note || 'Delayed execution pattern',
        },
        remediation: 'Investigate delayed execution. May be designed to evade sandbox analysis.',
      });
    }
  }

  // SSRF Detection (JS/TS/Python files)
  if (/\.(js|ts|jsx|tsx|py)$/i.test(filePath)) {
    const ssrfResult = detectSSRFPatterns(filePath, content);
    if (ssrfResult.matched) {
      findings.push({
        id: 'ssrf-pattern',
        category: 'EXFILTRATION',
        severity: 'high',
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: ssrfResult.snippet || '',
          note: ssrfResult.note || 'SSRF pattern detected',
        },
        remediation: 'Block requests to internal IPs and cloud metadata endpoints.',
      });
    }
  }

  return findings;
}
