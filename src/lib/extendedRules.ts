// Extended Security Rules - Categories 14-28 for comprehensive static analysis
// Covers: Git config, DevContainer, Test frameworks, Pre-commit hooks, Lockfiles,
// GitHub Actions, IDE configs, Remote development, Task runners, Package managers,
// VS Code extensions, JetBrains, EditorConfig, and Repository metadata

import type { Finding, FindingCategory, FindingSeverity } from '@/types/scanner';

interface RuleMatch {
  matched: boolean;
  snippet?: string;
  lineRange?: [number, number];
  note?: string;
  severity?: FindingSeverity;
  ruleId?: string;
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

// Unicode NFKC normalization for homoglyph detection
function normalizeUnicode(content: string): string {
  return content.normalize('NFKC');
}

// ========== CATEGORY 14: GIT CONFIGURATION ABUSE ==========

interface GitConfigMatch extends RuleMatch {
  severity?: FindingSeverity;
  ruleId?: string;
}

function detectGitConfigAbuse(filePath: string, content: string): GitConfigMatch[] {
  const findings: GitConfigMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // .gitconfig credential helpers
  if (lowerPath.endsWith('.gitconfig') || lowerPath.includes('config')) {
    // Credential helper abuse
    const credentialHelperPatterns = [
      /\[credential\][\s\S]*?helper\s*=\s*(.+)/gi,
      /credential\.helper\s*=\s*(.+)/gi,
    ];
    
    for (const pattern of credentialHelperPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const helper = match[1];
        // Suspicious helper patterns
        if (/curl|wget|bash|sh\s|python|node|eval|exec|\|/.test(helper)) {
          findings.push({
            matched: true,
            snippet: extractSnippet(content, match.index, match[0].length),
            note: `Suspicious credential helper command: ${helper.substring(0, 80)}`,
            severity: 'critical',
            ruleId: 'git-credential-helper-exec',
          });
        }
      }
    }
    
    // core.hooksPath hijacking
    const hooksPathMatch = content.match(/core\.?hooksPath\s*=\s*([^\n]+)/i);
    if (hooksPathMatch) {
      const path = hooksPathMatch[1].trim();
      if (!/^\.git\/hooks\/?$/.test(path) && !/^\.husky\/?$/.test(path)) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, hooksPathMatch.index || 0, hooksPathMatch[0].length),
          note: `Custom hooks path may execute malicious hooks: ${path}`,
          severity: 'high',
          ruleId: 'git-hooks-path-hijack',
        });
      }
    }
    
    // url.<base>.insteadOf rewriting
    const insteadOfMatch = content.match(/url\.[^\]]+\.insteadOf\s*=\s*([^\n]+)/i);
    if (insteadOfMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, insteadOfMatch.index || 0, insteadOfMatch[0].length),
        note: 'Git URL rewriting can redirect to malicious repositories',
        severity: 'high',
        ruleId: 'git-url-rewrite',
      });
    }
    
    // core.fsmonitor hook
    const fsmonitorMatch = content.match(/core\.fsmonitor\s*=\s*([^\n]+)/i);
    if (fsmonitorMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, fsmonitorMatch.index || 0, fsmonitorMatch[0].length),
        note: 'fsmonitor hook executes on every git operation',
        severity: 'high',
        ruleId: 'git-fsmonitor-hook',
      });
    }
    
    // core.sshCommand abuse
    const sshCmdMatch = content.match(/core\.sshCommand\s*=\s*([^\n]+)/i);
    if (sshCmdMatch && /curl|wget|bash|python|eval|exec/.test(sshCmdMatch[1])) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, sshCmdMatch.index || 0, sshCmdMatch[0].length),
        note: 'Suspicious SSH command override',
        severity: 'critical',
        ruleId: 'git-ssh-command-abuse',
      });
    }
  }
  
  return findings;
}

// ========== CATEGORY 15: DEVCONTAINER CONFIGURATION HOOKS ==========

interface DevContainerMatch extends RuleMatch {
  severity?: FindingSeverity;
  ruleId?: string;
}

function detectDevContainerHooks(filePath: string, content: string): DevContainerMatch[] {
  const findings: DevContainerMatch[] = [];
  
  if (!filePath.toLowerCase().includes('devcontainer')) return findings;
  
  // Features with install commands
  const featurePatterns = [
    /"features"\s*:\s*\{[\s\S]*?"installCommand"\s*:\s*"([^"]+)"/gi,
    /"features"\s*:\s*\{[\s\S]*?"ghcr\.io\/[^"]+"/gi,
  ];
  
  for (const pattern of featurePatterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const cmd = match[1] || match[0];
      if (/curl|wget|bash|sh\s+-c|python\s+-c|eval|exec/.test(cmd)) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, match.index, match[0].length),
          note: 'DevContainer feature with executable commands',
          severity: 'high',
          ruleId: 'devcontainer-feature-exec',
        });
      }
    }
  }
  
  // postCreateCommand, postStartCommand, postAttachCommand with network
  const lifecycleCommands = [
    /postCreateCommand['"]\s*:\s*"([^"]+)"/gi,
    /postStartCommand['"]\s*:\s*"([^"]+)"/gi,
    /postAttachCommand['"]\s*:\s*"([^"]+)"/gi,
    /initializeCommand['"]\s*:\s*"([^"]+)"/gi,
    /onCreateCommand['"]\s*:\s*"([^"]+)"/gi,
    /updateContentCommand['"]\s*:\s*"([^"]+)"/gi,
  ];
  
  for (const pattern of lifecycleCommands) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const command = match[1];
      // Check for network activity or shell downloads
      if (/curl|wget|http:\/\/|https:\/\/|\|.*bash|\|.*sh/.test(command)) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, match.index, match[0].length),
          note: `DevContainer lifecycle command with network/shell execution`,
          severity: 'high',
          ruleId: 'devcontainer-lifecycle-network',
        });
      }
    }
  }
  
  // containerEnv with suspicious values
  const envMatch = content.match(/containerEnv['"]\s*:\s*\{[\s\S]*?\}/gi);
  if (envMatch) {
    for (const env of envMatch) {
      if (/LD_PRELOAD|PATH\s*:\s*["']\/tmp|NODE_OPTIONS.*--require/.test(env)) {
        findings.push({
          matched: true,
          snippet: env.substring(0, 400),
          note: 'DevContainer containerEnv with suspicious environment variables',
          severity: 'critical',
          ruleId: 'devcontainer-env-abuse',
        });
      }
    }
  }
  
  // remoteUser root
  if (/remoteUser['"]\s*:\s*['"]root['"]/.test(content)) {
    findings.push({
      matched: true,
      snippet: 'remoteUser: "root"',
      note: 'DevContainer runs as root user',
      severity: 'medium',
      ruleId: 'devcontainer-root-user',
    });
  }
  
  // Docker socket mount
  if (/\/var\/run\/docker\.sock/.test(content)) {
    findings.push({
      matched: true,
      snippet: '/var/run/docker.sock mount detected',
      note: 'DevContainer mounts Docker socket - container escape vector',
      severity: 'critical',
      ruleId: 'devcontainer-docker-socket',
    });
  }
  
  return findings;
}

// ========== CATEGORY 16: TEST FRAMEWORK PAYLOAD INJECTION ==========

function detectTestFrameworkPayloads(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // Jest setupFilesAfterEnv abuse
  if (lowerPath.endsWith('jest.config.js') || lowerPath.endsWith('jest.config.ts') || lowerPath.endsWith('jest.config.json')) {
    const setupFilesMatch = content.match(/setupFilesAfterEnv\s*:\s*\[([^\]]+)\]/);
    if (setupFilesMatch) {
      const files = setupFilesMatch[1];
      // Suspicious paths
      if (/\.\.\/|\/tmp|%temp%|http:|https:/.test(files)) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, setupFilesMatch.index || 0, setupFilesMatch[0].length),
          note: 'Jest setupFilesAfterEnv points to suspicious location',
          severity: 'high',
          ruleId: 'jest-setup-files-suspicious',
        });
      }
    }
    
    // testEnvironment pointing to custom code
    const testEnvMatch = content.match(/testEnvironment\s*:\s*["']([^"']+)["']/);
    if (testEnvMatch && !/jsdom|node/.test(testEnvMatch[1])) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, testEnvMatch.index || 0, testEnvMatch[0].length),
        note: 'Custom Jest testEnvironment may execute arbitrary code',
        severity: 'medium',
        ruleId: 'jest-custom-environment',
      });
    }
    
    // globalSetup/globalTeardown
    const globalMatch = content.match(/(globalSetup|globalTeardown)\s*:\s*["']([^"']+)["']/);
    if (globalMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, globalMatch.index || 0, globalMatch[0].length),
        note: `Jest ${globalMatch[1]} executes code before/after all tests`,
        severity: 'medium',
        ruleId: 'jest-global-setup',
      });
    }
  }
  
  // Pytest conftest.py and plugins
  if (lowerPath.endsWith('conftest.py') || lowerPath.endsWith('pytest.ini') || lowerPath.includes('pyproject.toml')) {
    // pytest_configure hook
    if (/def\s+pytest_configure/.test(content)) {
      const hookMatch = content.match(/def\s+pytest_configure[\s\S]*?(?=\ndef\s|\nclass\s|$)/);
      if (hookMatch && /os\.system|subprocess|exec|eval|urllib|requests/.test(hookMatch[0])) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, content.indexOf('pytest_configure'), 50),
          note: 'pytest_configure hook with execution or network code',
          severity: 'high',
          ruleId: 'pytest-configure-exec',
        });
      }
    }
    
    // Suspicious plugin declarations
    const pluginMatch = content.match(/pytest_plugins\s*=\s*\[([^\]]+)\]/);
    if (pluginMatch && /http:|https:|\.\.\//.test(pluginMatch[1])) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, pluginMatch.index || 0, pluginMatch[0].length),
        note: 'pytest_plugins loads from suspicious source',
        severity: 'high',
        ruleId: 'pytest-plugin-suspicious',
      });
    }
  }
  
  // Go test TestMain
  if (lowerPath.endsWith('_test.go') && /func\s+TestMain\s*\(/.test(content)) {
    const mainMatch = content.match(/func\s+TestMain[\s\S]*?\n\}/);
    if (mainMatch && /exec\.Command|os\.StartProcess|net\/http\.Get/.test(mainMatch[0])) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, content.indexOf('TestMain'), 50),
        note: 'Go TestMain with external command or network execution',
        severity: 'high',
        ruleId: 'go-testmain-exec',
      });
    }
  }
  
  // Vitest config
  if (lowerPath.includes('vitest.config')) {
    const setupMatch = content.match(/setupFiles\s*:\s*\[([^\]]+)\]/);
    if (setupMatch && /http:|https:|\/tmp/.test(setupMatch[1])) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, setupMatch.index || 0, setupMatch[0].length),
        note: 'Vitest setupFiles points to suspicious location',
        severity: 'high',
        ruleId: 'vitest-setup-suspicious',
      });
    }
  }
  
  return findings;
}

// ========== CATEGORY 17: DOCUMENTATION GENERATOR EXPLOITS ==========

function detectDocGenExploits(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // JSDoc plugins (jsdoc.json, jsdoc.conf.json)
  if (lowerPath.includes('jsdoc') && lowerPath.endsWith('.json')) {
    const pluginMatch = content.match(/plugins['"]\s*:\s*\[([^\]]+)\]/);
    if (pluginMatch) {
      const plugins = pluginMatch[1];
      if (/\.\.\/|\/tmp|http:|https:|node_modules\/(?!jsdoc)/.test(plugins)) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, pluginMatch.index || 0, pluginMatch[0].length),
          note: 'JSDoc plugin from suspicious source',
          severity: 'high',
          ruleId: 'jsdoc-plugin-suspicious',
        });
      }
    }
  }
  
  // Sphinx conf.py extensions
  if (lowerPath.endsWith('conf.py') && /sphinx/.test(content.toLowerCase())) {
    // sys.path manipulation
    if (/sys\.path\.(insert|append)\s*\([^)]*['"]http/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Sphinx conf.py manipulates sys.path with remote URL',
        note: 'Sphinx configuration loads modules from remote URL',
        severity: 'critical',
        ruleId: 'sphinx-remote-module',
      });
    }
    
    // Custom extensions with exec
    const extMatch = content.match(/extensions\s*=\s*\[[\s\S]*?\]/);
    if (extMatch) {
      // Check if extension code contains dangerous patterns
      if (/exec\s*\(|eval\s*\(|subprocess|os\.system/.test(content)) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, 0, 200),
          note: 'Sphinx conf.py contains code execution patterns',
          severity: 'high',
          ruleId: 'sphinx-exec-pattern',
        });
      }
    }
  }
  
  // MkDocs hooks (mkdocs.yml)
  if (lowerPath.includes('mkdocs') && (lowerPath.endsWith('.yml') || lowerPath.endsWith('.yaml'))) {
    const hooksMatch = content.match(/hooks:\s*\n([\s\S]*?)(?=\n[a-z]|\n$|$)/i);
    if (hooksMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, hooksMatch.index || 0, hooksMatch[0].length),
        note: 'MkDocs hooks execute Python code during build',
        severity: 'medium',
        ruleId: 'mkdocs-hooks',
      });
    }
    
    // Custom theme from URL
    if (/theme:\s*\n[\s\S]*?custom_dir:\s*["']?https?:/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'MkDocs theme from remote URL',
        note: 'MkDocs loads custom theme from remote URL',
        severity: 'high',
        ruleId: 'mkdocs-remote-theme',
      });
    }
  }
  
  // TypeDoc plugins
  if (lowerPath.includes('typedoc') && lowerPath.endsWith('.json')) {
    const pluginMatch = content.match(/plugin['"]\s*:\s*\[([^\]]+)\]/);
    if (pluginMatch && /http:|https:|\.\.\//.test(pluginMatch[1])) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, pluginMatch.index || 0, pluginMatch[0].length),
        note: 'TypeDoc plugin from suspicious source',
        severity: 'high',
        ruleId: 'typedoc-plugin-suspicious',
      });
    }
  }
  
  return findings;
}

// ========== CATEGORY 18: PRE-COMMIT HOOK POISONING ==========

function detectPreCommitPoisoning(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // .pre-commit-config.yaml
  if (lowerPath.includes('pre-commit-config') && (lowerPath.endsWith('.yml') || lowerPath.endsWith('.yaml'))) {
    // Repos from non-standard sources
    const repoMatches = content.matchAll(/repo:\s*([^\n]+)/gi);
    for (const match of repoMatches) {
      const repo = match[1].trim();
      // IP addresses or non-GitHub/GitLab sources
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(repo) || 
          (!/github\.com|gitlab\.com|bitbucket\.org/.test(repo) && /https?:\/\//.test(repo))) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: `Pre-commit hook from untrusted source: ${repo}`,
          severity: 'high',
          ruleId: 'precommit-untrusted-repo',
        });
      }
    }
    
    // Hooks with additional_dependencies that contain URLs
    const depsMatch = content.match(/additional_dependencies:\s*\n([\s\S]*?)(?=\n\s*-\s+repo:|\n[a-z]|$)/gi);
    if (depsMatch) {
      for (const dep of depsMatch) {
        if (/git\+https?:|http:|https:.*\.whl|\.tar\.gz/.test(dep)) {
          findings.push({
            matched: true,
            snippet: dep.substring(0, 300),
            note: 'Pre-commit additional_dependencies from URL',
            severity: 'medium',
            ruleId: 'precommit-url-dependency',
          });
        }
      }
    }
    
    // Local hooks with shell commands
    const localMatch = content.match(/repo:\s*local[\s\S]*?(?=\n\s*-\s+repo:|$)/gi);
    if (localMatch) {
      for (const local of localMatch) {
        if (/entry:\s*['"]?(?:curl|wget|bash|sh\s+-c|python\s+-c)/.test(local)) {
          findings.push({
            matched: true,
            snippet: local.substring(0, 400),
            note: 'Local pre-commit hook with shell/network commands',
            severity: 'high',
            ruleId: 'precommit-local-exec',
          });
        }
      }
    }
  }
  
  // Husky hooks (.husky/*)
  if (lowerPath.includes('.husky/') && !lowerPath.endsWith('.gitignore')) {
    // Network commands in hooks
    if (/curl\s|wget\s|http:\/\/|https:\/\/.*\|/.test(content)) {
      findings.push({
        matched: true,
        snippet: content.substring(0, 400),
        note: 'Husky hook contains network download commands',
        severity: 'high',
        ruleId: 'husky-network-exec',
      });
    }
    
    // Obfuscated commands
    if (/\$\(base64|\bbase64\s+-d|\batob\b|eval\s*["'`]/.test(content)) {
      findings.push({
        matched: true,
        snippet: content.substring(0, 400),
        note: 'Husky hook contains obfuscated commands',
        severity: 'critical',
        ruleId: 'husky-obfuscated',
      });
    }
  }
  
  // lint-staged config
  if (lowerPath.includes('lint-staged') || (lowerPath.endsWith('package.json') && /lint-staged/.test(content))) {
    // Commands with shell execution
    const lintStagedMatch = content.match(/lint-staged['"]\s*:\s*\{[\s\S]*?\}/);
    if (lintStagedMatch) {
      const config = lintStagedMatch[0];
      if (/curl|wget|bash\s+-c|sh\s+-c|eval\s|node\s+-e/.test(config)) {
        findings.push({
          matched: true,
          snippet: config.substring(0, 400),
          note: 'lint-staged with shell execution commands',
          severity: 'high',
          ruleId: 'lint-staged-shell-exec',
        });
      }
    }
  }
  
  return findings;
}

// ========== CATEGORY 19: LOCKFILE SUPPLY CHAIN ATTACKS ==========

function detectLockfileAttacks(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // pnpm-lock.yaml overrides
  if (lowerPath.endsWith('pnpm-lock.yaml')) {
    // Check for overrides with suspicious URLs
    if (/overrides:\s*\n[\s\S]*?https?:\/\/(?!registry\.npmjs\.org)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'pnpm-lock.yaml contains non-npm registry overrides',
        note: 'pnpm lockfile overrides point to non-standard registry',
        severity: 'high',
        ruleId: 'pnpm-lock-override',
      });
    }
    
    // Integrity hash mismatches (empty or suspicious)
    const integrityMatches = content.matchAll(/integrity:\s*['"]?([^'"}\n]+)/gi);
    for (const match of integrityMatches) {
      if (match[1].length < 20 || !/^sha[0-9]+-/.test(match[1])) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: 'Suspicious integrity hash in pnpm-lock.yaml',
          severity: 'medium',
          ruleId: 'pnpm-lock-integrity',
        });
        break; // Only report once
      }
    }
  }
  
  // yarn.lock resolutions
  if (lowerPath.endsWith('yarn.lock')) {
    // Check for git+http resolutions
    if (/resolved\s+"git\+https?:\/\/(?!github\.com|gitlab\.com)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'yarn.lock contains git resolution from untrusted source',
        note: 'yarn.lock resolves package from non-standard git host',
        severity: 'high',
        ruleId: 'yarn-lock-git-resolution',
      });
    }
    
    // HTTP (non-HTTPS) resolutions
    if (/resolved\s+"http:\/\//.test(content)) {
      findings.push({
        matched: true,
        snippet: 'yarn.lock contains insecure HTTP resolution',
        note: 'yarn.lock resolves package over insecure HTTP',
        severity: 'high',
        ruleId: 'yarn-lock-http-resolution',
      });
    }
  }
  
  // Cargo.lock patches
  if (lowerPath.endsWith('cargo.lock')) {
    if (/\[patch\.[^\]]+\][\s\S]*?git\s*=\s*["']https?:\/\/(?!github\.com|gitlab\.com)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Cargo.lock patches from untrusted git source',
        note: 'Rust Cargo.lock patches package from non-standard source',
        severity: 'high',
        ruleId: 'cargo-lock-patch',
      });
    }
  }
  
  // package-lock.json
  if (lowerPath.endsWith('package-lock.json')) {
    // Non-npm registry
    if (/"resolved":\s*"https?:\/\/(?!registry\.npmjs\.org)[^"]+\.tgz"/.test(content)) {
      const match = content.match(/"resolved":\s*"(https?:\/\/(?!registry\.npmjs\.org)[^"]+\.tgz)"/);
      if (match) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: `package-lock.json resolves from non-npm registry: ${match[1].substring(0, 60)}`,
          severity: 'high',
          ruleId: 'npm-lock-non-registry',
        });
      }
    }
    
    // GitHub tarball instead of npm
    const githubTarballCount = (content.match(/"resolved":\s*"https:\/\/codeload\.github\.com/g) || []).length;
    if (githubTarballCount > 3) {
      findings.push({
        matched: true,
        snippet: `${githubTarballCount} packages resolved from GitHub tarballs`,
        note: 'Multiple packages bypass npm registry via GitHub tarballs',
        severity: 'medium',
        ruleId: 'npm-lock-github-tarballs',
      });
    }
  }
  
  // Pipfile.lock
  if (lowerPath.endsWith('pipfile.lock')) {
    // VCS dependencies
    if (/"vcs":\s*"git"[\s\S]*?"uri":\s*"https?:\/\/(?!github\.com|gitlab\.com|bitbucket\.org)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Pipfile.lock contains VCS dependency from untrusted source',
        note: 'Python Pipfile.lock installs from non-standard git host',
        severity: 'high',
        ruleId: 'pipfile-lock-vcs',
      });
    }
  }
  
  return findings;
}

// ========== CATEGORY 20: GITHUB ACTIONS WORKFLOW INJECTION ==========

function detectGitHubActionsInjection(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  
  if (!filePath.toLowerCase().includes('.github/workflows')) return findings;
  
  // Expression injection in run commands
  const expressionPatterns = [
    /run:.*\$\{\{\s*github\.event\.(?:issue|pull_request|comment)\.(?:title|body|head\.ref)/gi,
    /run:.*\$\{\{\s*github\.event\.inputs\.[^}]+\}\}/gi,
    /run:.*\$\{\{\s*github\.head_ref\s*\}\}/gi,
  ];
  
  for (const pattern of expressionPatterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, match.index, match[0].length),
        note: 'GitHub Actions expression injection - user input in run command',
        severity: 'critical',
        ruleId: 'gha-expression-injection',
      });
    }
  }
  
  // workflow_dispatch without input validation
  if (/on:\s*\n[\s\S]*?workflow_dispatch:/.test(content)) {
    const inputsMatch = content.match(/inputs:\s*\n([\s\S]*?)(?=\n[a-z]|jobs:|$)/);
    if (inputsMatch) {
      const inputs = inputsMatch[1];
      // Check if inputs are used directly in run
      const inputNames = [...inputs.matchAll(/^\s*(\w+):\s*$/gm)].map(m => m[1]);
      for (const name of inputNames) {
        if (new RegExp(`run:.*\\$\\{\\{\\s*(?:github\\.event\\.)?inputs\\.${name}`, 'i').test(content)) {
          findings.push({
            matched: true,
            snippet: `Input "${name}" used directly in run command`,
            note: `workflow_dispatch input "${name}" used unsanitized in run`,
            severity: 'high',
            ruleId: 'gha-input-injection',
          });
        }
      }
    }
  }
  
  // Composite actions with shell execution
  if (/using:\s*['"]?composite/.test(content)) {
    if (/shell:\s*bash[\s\S]*?run:\s*\|[\s\S]*?\$\{\{/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Composite action with expression in shell',
        note: 'Composite action shells expression values - injection risk',
        severity: 'high',
        ruleId: 'gha-composite-injection',
      });
    }
  }
  
  // pull_request_target with checkout
  if (/on:\s*\n[\s\S]*?pull_request_target:/.test(content)) {
    if (/actions\/checkout[\s\S]*?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(ref|sha)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'pull_request_target with PR head checkout',
        note: 'Dangerous pattern: checking out PR head in pull_request_target',
        severity: 'critical',
        ruleId: 'gha-prt-checkout',
      });
    }
  }
  
  // Secrets in artifact uploads
  if (/actions\/upload-artifact[\s\S]*?path:[\s\S]*?\$\{\{\s*secrets\./.test(content)) {
    findings.push({
      matched: true,
      snippet: 'Secrets referenced near artifact upload',
      note: 'Potential secret exposure via artifact upload',
      severity: 'high',
      ruleId: 'gha-secret-artifact',
    });
  }
  
  // GITHUB_TOKEN write permissions
  if (/permissions:\s*\n[\s\S]*?(?:contents|packages|deployments):\s*write/.test(content)) {
    // Only flag if combined with suspicious patterns
    if (/curl.*\$\{\{|wget.*\$\{\{|\$\{\{.*secrets.*GITHUB_TOKEN/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Write permissions with dynamic curl/wget',
        note: 'High-privilege workflow with dynamic HTTP requests',
        severity: 'high',
        ruleId: 'gha-write-perms-network',
      });
    }
  }
  
  return findings;
}

// ========== CATEGORY 21: IDE SEARCH/INDEXER PATTERNS ==========

function detectIDEIndexerPatterns(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // .eslintrc ReDoS patterns
  if (lowerPath.includes('eslint') && /\.(json|js|cjs|yaml|yml)$/.test(lowerPath)) {
    // Catastrophic backtracking patterns
    const redosPatterns = [
      /\(\.\*\)\+/,
      /\(\[^\]\*\)\+/,
      /\(\.\+\)\+/,
      /\(.*\?\)\+/,
      /(?:\.\*){3,}/,
    ];
    
    for (const pattern of redosPatterns) {
      if (pattern.test(content)) {
        findings.push({
          matched: true,
          snippet: 'Potential ReDoS pattern in ESLint config',
          note: 'ESLint config contains regex patterns prone to catastrophic backtracking',
          severity: 'medium',
          ruleId: 'eslint-redos-pattern',
        });
        break;
      }
    }
  }
  
  // .vscode/settings.json glob injection
  if (lowerPath === '.vscode/settings.json' || lowerPath.endsWith('/settings.json')) {
    // Extremely deep glob patterns
    const deepGlobMatch = content.match(/\*\*\/\*\*\/\*\*\/\*\*\/\*\*|\{\*\*,\*\*\}/);
    if (deepGlobMatch) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, deepGlobMatch.index || 0, deepGlobMatch[0].length),
        note: 'VS Code settings contain excessively deep glob patterns',
        severity: 'medium',
        ruleId: 'vscode-deep-glob',
      });
    }
    
    // files.watcherExclude bypass attempts
    if (/files\.watcherExclude[\s\S]*?:\s*false/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'files.watcherExclude set to false',
        note: 'VS Code file watcher exclusion disabled - performance DoS risk',
        severity: 'low',
        ruleId: 'vscode-watcher-disabled',
      });
    }
  }
  
  // tsconfig.json include patterns
  if (lowerPath.endsWith('tsconfig.json')) {
    const includeMatch = content.match(/"include":\s*\[([^\]]*)\]/);
    if (includeMatch && /node_modules|\*\*\/\*\*\/\*\*/.test(includeMatch[1])) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, includeMatch.index || 0, includeMatch[0].length),
        note: 'tsconfig includes node_modules or deep recursion patterns',
        severity: 'medium',
        ruleId: 'tsconfig-deep-include',
      });
    }
  }
  
  return findings;
}

// ========== CATEGORY 22: REMOTE DEVELOPMENT CONFIGS ==========

function detectRemoteDevConfigs(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // SSH config
  if (lowerPath.endsWith('.ssh/config') || lowerPath.includes('ssh_config')) {
    // ProxyCommand with suspicious patterns
    const proxyMatch = content.match(/ProxyCommand\s+([^\n]+)/i);
    if (proxyMatch && /curl|wget|bash|sh\s+-c|nc\s+-e|socat/.test(proxyMatch[1])) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, proxyMatch.index || 0, proxyMatch[0].length),
        note: 'SSH ProxyCommand with suspicious command execution',
        severity: 'critical',
        ruleId: 'ssh-proxy-exec',
      });
    }
    
    // LocalCommand execution
    if (/LocalCommand\s+.+/.test(content) && /PermitLocalCommand\s+yes/i.test(content)) {
      findings.push({
        matched: true,
        snippet: 'SSH LocalCommand enabled with command execution',
        note: 'SSH config enables local command execution on connect',
        severity: 'high',
        ruleId: 'ssh-local-command',
      });
    }
  }
  
  // known_hosts with suspicious patterns
  if (lowerPath.includes('known_hosts')) {
    // Wildcard hosts
    if (/^\*\s+/.test(content) || /^@cert-authority\s+\*/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Wildcard in known_hosts',
        note: 'SSH known_hosts contains wildcard entries - MITM risk',
        severity: 'high',
        ruleId: 'ssh-known-hosts-wildcard',
      });
    }
  }
  
  // Remote-SSH extension settings
  if (lowerPath.includes('.vscode') && lowerPath.endsWith('settings.json')) {
    // remote.SSH.configFile pointing to unusual location
    const remoteSshMatch = content.match(/remote\.SSH\.configFile['"]\s*:\s*["']([^"']+)["']/);
    if (remoteSshMatch && /\/tmp|%temp%|http:|https:/.test(remoteSshMatch[1])) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, remoteSshMatch.index || 0, remoteSshMatch[0].length),
        note: 'Remote-SSH configFile points to suspicious location',
        severity: 'high',
        ruleId: 'remote-ssh-config-suspicious',
      });
    }
  }
  
  // Codespaces secrets in devcontainer
  if (lowerPath.includes('devcontainer')) {
    // secrets array with suspicious names
    const secretsMatch = content.match(/secrets['"]\s*:\s*\[([^\]]+)\]/);
    if (secretsMatch && /GH_TOKEN|GITHUB_TOKEN|NPM_TOKEN|AWS_|DOCKER_/.test(secretsMatch[1])) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, secretsMatch.index || 0, secretsMatch[0].length),
        note: 'Codespaces devcontainer requests sensitive secrets',
        severity: 'medium',
        ruleId: 'codespaces-secrets-request',
      });
    }
  }
  
  return findings;
}

// ========== CATEGORY 23: TASK RUNNER CONFIGURATIONS ==========

function detectTaskRunnerConfigs(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // Nx workspace.json generators
  if (lowerPath.includes('workspace.json') || lowerPath.includes('nx.json')) {
    // Custom generators from external sources
    const generatorMatch = content.match(/generators?['"]\s*:\s*\{[\s\S]*?\}/);
    if (generatorMatch && /https?:\/\/|git\+|\.\.\/\.\./.test(generatorMatch[0])) {
      findings.push({
        matched: true,
        snippet: generatorMatch[0].substring(0, 400),
        note: 'Nx generator from external or parent directory source',
        severity: 'high',
        ruleId: 'nx-generator-external',
      });
    }
    
    // Implicit dependencies with exec
    if (/implicitDependencies[\s\S]*?exec/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Nx implicit dependencies with execution',
        note: 'Nx workspace has implicit dependencies that execute commands',
        severity: 'medium',
        ruleId: 'nx-implicit-exec',
      });
    }
  }
  
  // Turborepo pipeline.json / turbo.json
  if (lowerPath.includes('turbo.json') || lowerPath.includes('pipeline.json')) {
    // Dangerous cache configurations
    if (/outputs['"]\s*:\s*\[[\s\S]*?\/\.\.\//.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Turbo outputs contains parent directory traversal',
        note: 'Turborepo outputs may write to parent directories',
        severity: 'high',
        ruleId: 'turbo-output-traversal',
      });
    }
    
    // globalDependencies with sensitive files
    if (/globalDependencies[\s\S]*?(?:\.env|\.npmrc|\.ssh)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Turbo globalDependencies includes sensitive files',
        note: 'Turborepo cache depends on sensitive files',
        severity: 'medium',
        ruleId: 'turbo-sensitive-dependency',
      });
    }
  }
  
  // Lerna with custom commands
  if (lowerPath.endsWith('lerna.json')) {
    const commandMatch = content.match(/command['"]\s*:\s*\{[\s\S]*?\}/);
    if (commandMatch && /curl|wget|bash\s+-c|eval/.test(commandMatch[0])) {
      findings.push({
        matched: true,
        snippet: commandMatch[0].substring(0, 400),
        note: 'Lerna config with shell execution commands',
        severity: 'high',
        ruleId: 'lerna-shell-exec',
      });
    }
  }
  
  // Gulp with external plugins
  if (lowerPath.endsWith('gulpfile.js') || lowerPath.endsWith('gulpfile.ts')) {
    if (/require\s*\(\s*['"]https?:/.test(content) || /import\s+.*from\s+['"]https?:/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Gulpfile loads module from URL',
        note: 'Gulp configuration loads plugins from remote URL',
        severity: 'critical',
        ruleId: 'gulp-remote-require',
      });
    }
  }
  
  return findings;
}

// ========== CATEGORY 24: PACKAGE MANAGER RESOLUTION ABUSE ==========

function detectPackageManagerAbuse(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // npm .npmrc
  if (lowerPath.endsWith('.npmrc')) {
    // Custom registry pointing to IP or non-standard host
    const registryMatch = content.match(/registry\s*=\s*(\S+)/);
    if (registryMatch) {
      const registry = registryMatch[1];
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(registry) ||
          (!/registry\.npmjs\.org|registry\.yarnpkg\.com/.test(registry) && /https?:\/\//.test(registry))) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, registryMatch.index || 0, registryMatch[0].length),
          note: `npm registry points to non-standard host: ${registry}`,
          severity: 'high',
          ruleId: 'npmrc-custom-registry',
        });
      }
    }
    
    // Ignore scripts disabled (could be legitimate or hiding attacks)
    if (/ignore-scripts\s*=\s*false/.test(content)) {
      // Check if there are other suspicious settings
      if (registryMatch || /\/\/.*:_authToken/.test(content)) {
        findings.push({
          matched: true,
          snippet: 'ignore-scripts=false with other suspicious settings',
          note: '.npmrc enables scripts with custom registry or auth tokens',
          severity: 'high',
          ruleId: 'npmrc-scripts-registry',
        });
      }
    }
    
    // Always-auth with custom registry
    if (/always-auth\s*=\s*true/.test(content) && registryMatch) {
      findings.push({
        matched: true,
        snippet: 'always-auth enabled with custom registry',
        note: '.npmrc forces auth to custom registry - credential theft risk',
        severity: 'high',
        ruleId: 'npmrc-always-auth-custom',
      });
    }
  }
  
  // Poetry pyproject.toml
  if (lowerPath.endsWith('pyproject.toml')) {
    // Custom source with priority
    if (/\[\[tool\.poetry\.source\]\][\s\S]*?url\s*=\s*["']https?:\/\/(?!pypi\.org|files\.pythonhosted\.org)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Poetry source from non-PyPI host',
        note: 'Poetry config adds non-PyPI package source',
        severity: 'high',
        ruleId: 'poetry-custom-source',
      });
    }
    
    // extras_require with git dependencies
    if (/\[project\.optional-dependencies\][\s\S]*?git\+https?:\/\//.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Optional dependencies from git',
        note: 'pyproject.toml extras install from git repositories',
        severity: 'medium',
        ruleId: 'pyproject-git-extras',
      });
    }
  }
  
  // Gradle settings.gradle
  if (lowerPath.endsWith('settings.gradle') || lowerPath.endsWith('settings.gradle.kts')) {
    // pluginManagement with custom repos
    if (/pluginManagement\s*\{[\s\S]*?url\s*[=:]\s*["']https?:\/\/(?!plugins\.gradle\.org|repo\.maven\.apache\.org)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Gradle pluginManagement with custom repository',
        note: 'Gradle loads plugins from non-standard repository',
        severity: 'high',
        ruleId: 'gradle-plugin-repo',
      });
    }
    
    // includeBuild with remote
    if (/includeBuild\s*\(\s*["']https?:/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Gradle includeBuild from URL',
        note: 'Gradle includes build from remote URL',
        severity: 'critical',
        ruleId: 'gradle-include-remote',
      });
    }
  }
  
  // .yarnrc.yml
  if (lowerPath.endsWith('.yarnrc.yml') || lowerPath.endsWith('.yarnrc.yaml')) {
    // Custom registry
    if (/npmRegistryServer:\s*["']?https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Yarn registry from non-standard host',
        note: '.yarnrc.yml points to custom npm registry',
        severity: 'high',
        ruleId: 'yarnrc-custom-registry',
      });
    }
    
    // Plugins from non-Yarn sources
    if (/plugins:\s*\n[\s\S]*?spec:\s*["']https?:\/\/(?!yarnpkg\.com|github\.com\/yarnpkg)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Yarn plugin from non-standard source',
        note: '.yarnrc.yml loads plugin from untrusted source',
        severity: 'high',
        ruleId: 'yarnrc-plugin-source',
      });
    }
  }
  
  return findings;
}

// ========== CATEGORY 25: VS CODE EXTENSION MANIFESTS ==========

function detectVSCodeExtensionManifests(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  
  // Only check package.json in extension directories or with vscode fields
  if (!filePath.toLowerCase().endsWith('package.json')) return findings;
  if (!/engines[\s\S]*?vscode|contributes/.test(content)) return findings;
  
  // activationEvents with broad triggers
  const activationMatch = content.match(/activationEvents['"]\s*:\s*\[([^\]]+)\]/);
  if (activationMatch) {
    const events = activationMatch[1];
    // Dangerous: activates on any file open
    if (/\*|onStartupFinished|workspaceContains:\*/.test(events)) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, activationMatch.index || 0, activationMatch[0].length),
        note: 'VS Code extension activates broadly (onStartupFinished, *, or workspaceContains:*)',
        severity: 'high',
        ruleId: 'vscode-ext-broad-activation',
      });
    }
    
    // Activates on file operations
    if (/onFileSystem:|onUri:/.test(events)) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, activationMatch.index || 0, activationMatch[0].length),
        note: 'VS Code extension hooks file system operations',
        severity: 'medium',
        ruleId: 'vscode-ext-filesystem-hook',
      });
    }
  }
  
  // contributes.commands with exec-looking names
  if (/contributes[\s\S]*?commands[\s\S]*?exec|shell|run|terminal/i.test(content)) {
    findings.push({
      matched: true,
      snippet: 'VS Code extension contributes commands with exec/shell-like names',
      note: 'Extension commands suggest shell execution capability',
      severity: 'medium',
      ruleId: 'vscode-ext-exec-command',
    });
  }
  
  // Requesting dangerous permissions
  const permsPatterns = [
    /env\.openExternal/,
    /env\.clipboard\.writeText/,
    /workspace\.fs\.writeFile/,
    /debug\.startDebugging/,
    /tasks\.executeTask/,
  ];
  
  let dangerousPermsCount = 0;
  for (const pattern of permsPatterns) {
    if (pattern.test(content)) dangerousPermsCount++;
  }
  
  if (dangerousPermsCount >= 2) {
    findings.push({
      matched: true,
      snippet: `Extension uses ${dangerousPermsCount} potentially dangerous APIs`,
      note: 'VS Code extension uses multiple privileged APIs',
      severity: 'medium',
      ruleId: 'vscode-ext-privileged-apis',
    });
  }
  
  // main script in unusual location
  const mainMatch = content.match(/"main"\s*:\s*"([^"]+)"/);
  if (mainMatch && /^https?:|\.\.\/|\/tmp/.test(mainMatch[1])) {
    findings.push({
      matched: true,
      snippet: extractSnippet(content, mainMatch.index || 0, mainMatch[0].length),
      note: 'VS Code extension main script from suspicious location',
      severity: 'critical',
      ruleId: 'vscode-ext-remote-main',
    });
  }
  
  return findings;
}

// ========== CATEGORY 26: JETBRAINS IDE CONFIGS ==========

function detectJetBrainsConfigs(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  if (!lowerPath.includes('.idea/')) return findings;
  
  // runConfigurations with shell execution
  if (lowerPath.includes('runconfiguration')) {
    // External tools or shell commands
    if (/ExternalSystemExecutionSettings|SCRIPT_PATH|SHELL_COMMAND/.test(content)) {
      const execMatch = content.match(/(?:SCRIPT_PATH|SHELL_COMMAND)[^>]*>([^<]+)</);
      if (execMatch) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, execMatch.index || 0, execMatch[0].length),
          note: 'JetBrains run configuration with shell command',
          severity: 'high',
          ruleId: 'jetbrains-shell-runconfig',
        });
      }
    }
    
    // Remote interpreters
    if (/RemoteInterpreter|SSH_CREDENTIALS|DeploymentTarget/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'JetBrains config with remote/SSH interpreter',
        note: 'Run configuration uses remote interpreter - review SSH settings',
        severity: 'medium',
        ruleId: 'jetbrains-remote-interpreter',
      });
    }
  }
  
  // workspace.xml external tools
  if (lowerPath.endsWith('workspace.xml')) {
    // ExternalToolsConfiguration
    const extToolMatch = content.match(/ExternalToolsConfiguration[\s\S]*?<\/component>/);
    if (extToolMatch && /curl|wget|bash|sh\s|python\s+-c|node\s+-e/.test(extToolMatch[0])) {
      findings.push({
        matched: true,
        snippet: extToolMatch[0].substring(0, 400),
        note: 'JetBrains external tools with network/shell commands',
        severity: 'high',
        ruleId: 'jetbrains-external-tools',
      });
    }
    
    // File watchers with external tools
    if (/FileWatchers[\s\S]*?program=["'][^"']*(?:curl|wget|bash)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'JetBrains file watcher with suspicious program',
        note: 'File watcher triggers network/shell commands on file change',
        severity: 'high',
        ruleId: 'jetbrains-filewatcher-exec',
      });
    }
  }
  
  // externalDependencies.xml
  if (lowerPath.endsWith('externaldependencies.xml')) {
    // Plugins from custom sources
    if (/pluginId[\s\S]*?enabled="true"[\s\S]*?url\s*=\s*["']https?:\/\/(?!plugins\.jetbrains\.com)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'JetBrains external plugin from non-standard source',
        note: 'IDE configured to install plugin from untrusted source',
        severity: 'high',
        ruleId: 'jetbrains-external-plugin',
      });
    }
  }
  
  return findings;
}

// ========== CATEGORY 27: EDITORCONFIG + SYMLINK PATTERNS ==========

function detectEditorConfigPatterns(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // .editorconfig charset injection
  if (lowerPath.endsWith('.editorconfig')) {
    // Unusual charsets that could cause parsing issues
    if (/charset\s*=\s*(?!utf-8|latin1|utf-16|iso-8859)[a-z0-9-]+/i.test(content)) {
      const charsetMatch = content.match(/charset\s*=\s*([a-z0-9-]+)/i);
      if (charsetMatch) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, charsetMatch.index || 0, charsetMatch[0].length),
          note: `EditorConfig specifies unusual charset: ${charsetMatch[1]}`,
          severity: 'low',
          ruleId: 'editorconfig-unusual-charset',
        });
      }
    }
    
    // Extremely wide glob patterns
    if (/\[\*\*\/\*\*\/\*\*\]|\[\{\*,\*\*\}\]/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'EditorConfig with excessively broad glob patterns',
        note: 'EditorConfig applies to excessive file patterns',
        severity: 'low',
        ruleId: 'editorconfig-broad-glob',
      });
    }
  }
  
  // .git/info/attributes
  if (lowerPath.includes('.git/info/attributes') || lowerPath.endsWith('.gitattributes')) {
    // Symlink-related patterns
    if (/filter\s*=\s*\S+.*symlink|working-tree-encoding/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Git attributes with symlink or encoding manipulation',
        note: 'Git attributes may manipulate file types or encodings',
        severity: 'medium',
        ruleId: 'git-attr-symlink-encoding',
      });
    }
    
    // Binary merge driver (could be abused)
    if (/merge\s*=\s*\S+\s+-driver/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Git attributes with custom merge driver',
        note: 'Custom merge driver may execute arbitrary code during merge',
        severity: 'medium',
        ruleId: 'git-attr-merge-driver',
      });
    }
  }
  
  // Symlink detection in source
  if (/\.(sh|bash|py|js|ts)$/.test(lowerPath)) {
    // Creating symlinks to sensitive files
    const symlinkPatterns = [
      /ln\s+-s[f]?\s+[^\n]*(?:\/etc\/passwd|\.ssh|\.gnupg|\.aws)/i,
      /os\.symlink\s*\([^)]*(?:passwd|\.ssh|credentials)/i,
      /fs\.symlinkSync?\s*\([^)]*(?:passwd|\.ssh|credentials)/i,
    ];
    
    for (const pattern of symlinkPatterns) {
      const match = content.match(pattern);
      if (match) {
        findings.push({
          matched: true,
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: 'Code creates symlinks to sensitive system files',
          severity: 'critical',
          ruleId: 'symlink-sensitive-file',
        });
      }
    }
  }
  
  return findings;
}

// ========== CATEGORY 28: REPOSITORY METADATA ABUSE ==========

function detectRepoMetadataAbuse(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // .mailmap abuse
  if (lowerPath.endsWith('.mailmap')) {
    // Very long entries (buffer overflow attempts)
    const lines = content.split('\n');
    for (const line of lines) {
      if (line.length > 500) {
        findings.push({
          matched: true,
          snippet: `Extremely long mailmap entry (${line.length} chars)`,
          note: '.mailmap contains unusually long entries - potential parser exploit',
          severity: 'medium',
          ruleId: 'mailmap-long-entry',
        });
        break;
      }
      // Shell injection in names
      if (/[`$]|\$\(|\|/.test(line)) {
        findings.push({
          matched: true,
          snippet: line.substring(0, 200),
          note: '.mailmap entry contains shell metacharacters',
          severity: 'medium',
          ruleId: 'mailmap-shell-chars',
        });
        break;
      }
    }
  }
  
  // CODEOWNERS with unusual patterns
  if (lowerPath.endsWith('codeowners')) {
    // External email addresses (potential social engineering)
    if (/@(?!github\.com|users\.noreply\.github\.com)[a-z0-9.-]+\.[a-z]{2,}/i.test(content)) {
      findings.push({
        matched: true,
        snippet: 'CODEOWNERS with external email addresses',
        note: 'CODEOWNERS references external email addresses',
        severity: 'low',
        ruleId: 'codeowners-external-email',
      });
    }
  }
  
  // FUNDING.yml with suspicious URLs
  if (lowerPath.endsWith('funding.yml') || lowerPath.endsWith('funding.yaml')) {
    // Non-standard funding platforms
    if (/custom:\s*\[?["']https?:\/\/(?!github\.com|patreon\.com|opencollective\.com|ko-fi\.com)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'FUNDING.yml with non-standard custom URL',
        note: 'Funding file links to non-standard platform - verify legitimacy',
        severity: 'low',
        ruleId: 'funding-suspicious-url',
      });
    }
  }
  
  // Git hooks in repo (.git/hooks or .githooks)
  if (lowerPath.includes('.git/hooks/') || lowerPath.includes('.githooks/')) {
    // commit-msg with network activity
    if (lowerPath.includes('commit-msg') || lowerPath.includes('pre-commit') || lowerPath.includes('post-commit')) {
      if (/curl\s|wget\s|http:\/\/|https:\/\//.test(content)) {
        findings.push({
          matched: true,
          snippet: content.substring(0, 400),
          note: 'Git hook with network commands',
          severity: 'high',
          ruleId: 'git-hook-network',
        });
      }
      
      // Exfiltration patterns
      if (/git\s+log|git\s+diff|git\s+show.*\|/.test(content)) {
        findings.push({
          matched: true,
          snippet: 'Git hook pipes git commands',
          note: 'Git hook may exfiltrate commit data',
          severity: 'medium',
          ruleId: 'git-hook-exfil',
        });
      }
    }
  }
  
  // renovate.json / dependabot.yml abuse
  if (lowerPath.includes('renovate') || lowerPath.includes('dependabot')) {
    // Custom registries
    if (/registryUrls?[\s\S]*?https?:\/\/(?!registry\.npmjs\.org|pypi\.org)/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Bot config with custom registry',
        note: 'Dependency bot configured with non-standard registry',
        severity: 'medium',
        ruleId: 'depbot-custom-registry',
      });
    }
    
    // postUpgradeTasks in renovate
    if (/postUpgradeTasks[\s\S]*?commands/.test(content)) {
      findings.push({
        matched: true,
        snippet: 'Renovate postUpgradeTasks with commands',
        note: 'Renovate executes commands after dependency updates',
        severity: 'high',
        ruleId: 'renovate-post-upgrade-exec',
      });
    }
  }
  
  return findings;
}

// ========== EVASION-RESISTANT DETECTION ==========

function detectEvasionPatterns(filePath: string, content: string): RuleMatch[] {
  const findings: RuleMatch[] = [];
  
  // Normalize unicode for homoglyph detection
  const normalizedContent = normalizeUnicode(content);
  
  // Detect obfuscated curl | bash in template literals
  const templateLiteralPatterns = [
    /`[^`]*cur[l`$].*\|.*ba[s`$]h[^`]*`/gi,
    /`[^`]*wge[t`$].*\|.*s[h`$][^`]*`/gi,
    /`[^`]*\$\{[^}]*\}.*\|.*\$\{[^}]*\}[^`]*`/gi,
  ];
  
  for (const pattern of templateLiteralPatterns) {
    const match = normalizedContent.match(pattern);
    if (match) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'Obfuscated command in template literal',
        severity: 'high',
        ruleId: 'evasion-template-literal',
      });
    }
  }
  
  // JSON string concatenation
  const jsonConcatPatterns = [
    /"[^"]*"\s*\+\s*"[^"]*(?:curl|wget|bash|eval)[^"]*"/gi,
    /'[^']*'\s*\+\s*'[^']*(?:curl|wget|bash|eval)[^']*'/gi,
  ];
  
  for (const pattern of jsonConcatPatterns) {
    const match = normalizedContent.match(pattern);
    if (match) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'String concatenation to build shell command',
        severity: 'high',
        ruleId: 'evasion-string-concat',
      });
    }
  }
  
  // Multi-level base64 encoding
  const multiBase64Pattern = /atob\s*\(\s*atob|base64\s*-d.*\|\s*base64\s*-d|b64decode\([^)]*b64decode/gi;
  const multiBase64Match = normalizedContent.match(multiBase64Pattern);
  if (multiBase64Match) {
    findings.push({
      matched: true,
      snippet: extractSnippet(content, multiBase64Match.index || 0, multiBase64Match[0].length),
      note: 'Multi-level base64 encoding - heavy obfuscation',
      severity: 'critical',
      ruleId: 'evasion-multi-base64',
    });
  }
  
  // Hex/Octal encoded shell commands
  const hexOctalPatterns = [
    /\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*(?:exec|eval|system)/gi,
    /\\[0-7]{3}.*\\[0-7]{3}.*\\[0-7]{3}.*(?:exec|eval|system)/gi,
    /String\.fromCharCode\s*\(\s*\d+\s*(?:,\s*\d+\s*){10,}\)/gi,
  ];
  
  for (const pattern of hexOctalPatterns) {
    const match = normalizedContent.match(pattern);
    if (match) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, match.index || 0, Math.min(match[0].length, 200)),
        note: 'Hex/Octal/CharCode encoded command execution',
        severity: 'critical',
        ruleId: 'evasion-hex-octal',
      });
    }
  }
  
  // Array-based command building
  const arrayBuildPatterns = [
    /\[\s*['"][a-z]['"].*\]\.join\s*\(\s*['"]['"]?\s*\)/gi,
    /\[.*\]\.reduce\s*\([^)]*\+[^)]*\)/gi,
  ];
  
  for (const pattern of arrayBuildPatterns) {
    const match = normalizedContent.match(pattern);
    if (match && /curl|wget|bash|eval|exec|system/.test(match[0])) {
      findings.push({
        matched: true,
        snippet: extractSnippet(content, match.index || 0, match[0].length),
        note: 'Array-based command string construction',
        severity: 'high',
        ruleId: 'evasion-array-build',
      });
    }
  }
  
  // Unicode lookalikes (homoglyphs) in commands
  // Common homoglyphs: а(cyrillic a), е(cyrillic e), о(cyrillic o), с(cyrillic s)
  const homoglyphPatterns = [
    /[а-яё].*curl|curl.*[а-яё]/gi,
    /[а-яё].*bash|bash.*[а-яё]/gi,
    /[а-яё].*eval|eval.*[а-яё]/gi,
  ];
  
  for (const pattern of homoglyphPatterns) {
    if (pattern.test(content) && !/[а-яё]{3,}/.test(content)) { // Exclude actual Russian text
      findings.push({
        matched: true,
        snippet: 'Unicode homoglyphs detected near shell commands',
        note: 'Possible Unicode homoglyph obfuscation in command',
        severity: 'high',
        ruleId: 'evasion-homoglyph',
      });
      break;
    }
  }
  
  return findings;
}

// ========== CROSS-FILE CORRELATION PREPARATION ==========
// Note: Actual cross-file correlation happens at the scan aggregation level

export interface FileSignal {
  filePath: string;
  signals: string[];
  severity: FindingSeverity;
}

export function extractFileSignals(filePath: string, content: string): FileSignal {
  const signals: string[] = [];
  const lowerPath = filePath.toLowerCase();
  
  // Package.json signals
  if (lowerPath.endsWith('package.json')) {
    if (/"postinstall"/.test(content)) signals.push('npm-postinstall');
    if (/"preinstall"/.test(content)) signals.push('npm-preinstall');
    if (/"prepare"/.test(content)) signals.push('npm-prepare');
    if (/"private"\s*:\s*false/.test(content)) signals.push('npm-public-package');
  }
  
  // .npmrc signals
  if (lowerPath.endsWith('.npmrc')) {
    if (/registry\s*=/.test(content)) signals.push('npm-custom-registry');
    if (/_authToken/.test(content)) signals.push('npm-auth-token');
  }
  
  // GitHub Actions signals
  if (lowerPath.includes('.github/workflows')) {
    if (/pull_request_target/.test(content)) signals.push('gha-prt');
    if (/workflow_dispatch/.test(content)) signals.push('gha-dispatch');
    if (/contents:\s*write/.test(content)) signals.push('gha-write-perms');
  }
  
  // Dockerfile signals
  if (lowerPath.includes('dockerfile')) {
    if (/USER\s+root|^(?!.*USER\s+)/i.test(content)) signals.push('docker-root');
    if (/--privileged/.test(content)) signals.push('docker-privileged');
  }
  
  // DevContainer signals
  if (lowerPath.includes('devcontainer')) {
    if (/postCreateCommand/.test(content)) signals.push('devcontainer-postcreate');
    if (/privileged.*true/.test(content)) signals.push('devcontainer-privileged');
  }
  
  return {
    filePath,
    signals,
    severity: signals.length > 2 ? 'high' : signals.length > 0 ? 'medium' : 'low',
  };
}

// ========== MAIN EXPORT ==========

export function runExtendedRules(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Category 14: Git Configuration Abuse
  const gitConfigResults = detectGitConfigAbuse(filePath, content);
  for (const result of gitConfigResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'git-config-abuse',
        category: 'EXECUTION_TRIGGER',
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'critical' ? 40 : result.severity === 'high' ? 25 : 15,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Review .gitconfig for malicious credential helpers, hooks, or URL rewrites.',
      });
    }
  }
  
  // Category 15: DevContainer Hooks
  const devContainerResults = detectDevContainerHooks(filePath, content);
  for (const result of devContainerResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'devcontainer-hook',
        category: 'EXECUTION_TRIGGER',
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'critical' ? 40 : 25,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Do not open untrusted repos with DevContainers. Review all lifecycle commands.',
      });
    }
  }
  
  // Category 16: Test Framework Payloads
  const testFrameworkResults = detectTestFrameworkPayloads(filePath, content);
  for (const result of testFrameworkResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'test-framework-payload',
        category: 'EXECUTION_TRIGGER',
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'high' ? 20 : 10,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Review test setup files and plugins before running tests.',
      });
    }
  }
  
  // Category 17: Doc Generator Exploits
  const docGenResults = detectDocGenExploits(filePath, content);
  for (const result of docGenResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'docgen-exploit',
        category: 'EXECUTION_TRIGGER',
        severity: result.severity || 'medium',
        scoreDelta: result.severity === 'high' ? 20 : 10,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Review documentation generator plugins and configurations.',
      });
    }
  }
  
  // Category 18: Pre-commit Hook Poisoning
  const preCommitResults = detectPreCommitPoisoning(filePath, content);
  for (const result of preCommitResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'precommit-poison',
        category: 'EXECUTION_TRIGGER',
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'critical' ? 35 : result.severity === 'high' ? 25 : 15,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Review pre-commit hooks and sources before installing.',
      });
    }
  }
  
  // Category 19: Lockfile Attacks
  const lockfileResults = detectLockfileAttacks(filePath, content);
  for (const result of lockfileResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'lockfile-attack',
        category: 'DEPENDENCY_RISK',
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'high' ? 25 : 15,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Verify lockfile integrity. Check for non-standard registries or patches.',
      });
    }
  }
  
  // Category 20: GitHub Actions Injection
  const ghaResults = detectGitHubActionsInjection(filePath, content);
  for (const result of ghaResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'gha-injection',
        category: 'CI_CD_RISK',
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'critical' ? 40 : 25,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Never interpolate untrusted input directly in run commands. Use environment variables.',
      });
    }
  }
  
  // Category 21: IDE Indexer Patterns
  const ideIndexerResults = detectIDEIndexerPatterns(filePath, content);
  for (const result of ideIndexerResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'ide-indexer-pattern',
        category: 'OBFUSCATION',
        severity: result.severity || 'medium',
        scoreDelta: result.severity === 'medium' ? 10 : 5,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Review IDE configurations for ReDoS patterns or excessive glob patterns.',
      });
    }
  }
  
  // Category 22: Remote Development Configs
  const remoteDevResults = detectRemoteDevConfigs(filePath, content);
  for (const result of remoteDevResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'remote-dev-config',
        category: 'EXECUTION_TRIGGER',
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'critical' ? 40 : 25,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Review SSH configs and remote development settings before connecting.',
      });
    }
  }
  
  // Category 23: Task Runner Configs
  const taskRunnerResults = detectTaskRunnerConfigs(filePath, content);
  for (const result of taskRunnerResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'task-runner-config',
        category: 'EXECUTION_TRIGGER',
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'critical' ? 35 : 20,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Review task runner configurations for external dependencies or shell execution.',
      });
    }
  }
  
  // Category 24: Package Manager Abuse
  const pkgManagerResults = detectPackageManagerAbuse(filePath, content);
  for (const result of pkgManagerResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'pkg-manager-abuse',
        category: 'DEPENDENCY_RISK',
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'high' ? 25 : 15,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Verify package manager configurations point to trusted registries.',
      });
    }
  }
  
  // Category 25: VS Code Extension Manifests
  const vscodeExtResults = detectVSCodeExtensionManifests(filePath, content);
  for (const result of vscodeExtResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'vscode-ext-manifest',
        category: 'EXECUTION_TRIGGER',
        severity: result.severity || 'medium',
        scoreDelta: result.severity === 'critical' ? 35 : result.severity === 'high' ? 20 : 10,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Review VS Code extension activation events and permissions before installing.',
      });
    }
  }
  
  // Category 26: JetBrains Configs
  const jetbrainsResults = detectJetBrainsConfigs(filePath, content);
  for (const result of jetbrainsResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'jetbrains-config',
        category: 'EXECUTION_TRIGGER',
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'high' ? 20 : 10,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Review JetBrains IDE configurations for run configs and external tools.',
      });
    }
  }
  
  // Category 27: EditorConfig + Symlinks
  const editorConfigResults = detectEditorConfigPatterns(filePath, content);
  for (const result of editorConfigResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'editorconfig-pattern',
        category: result.severity === 'critical' ? 'EXFILTRATION' : 'OBFUSCATION',
        severity: result.severity || 'medium',
        scoreDelta: result.severity === 'critical' ? 35 : result.severity === 'medium' ? 15 : 5,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Review editor configurations and check for symlink attacks.',
      });
    }
  }
  
  // Category 28: Repository Metadata Abuse
  const repoMetaResults = detectRepoMetadataAbuse(filePath, content);
  for (const result of repoMetaResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'repo-metadata-abuse',
        category: result.severity === 'high' ? 'EXECUTION_TRIGGER' : 'SOCIAL_ENGINEERING',
        severity: result.severity || 'medium',
        scoreDelta: result.severity === 'high' ? 20 : 10,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Review repository metadata files for malicious content.',
      });
    }
  }
  
  // Evasion-resistant patterns (applies to all files)
  const evasionResults = detectEvasionPatterns(filePath, content);
  for (const result of evasionResults) {
    if (result.matched) {
      findings.push({
        id: result.ruleId || 'evasion-pattern',
        category: 'OBFUSCATION',
        severity: result.severity || 'high',
        scoreDelta: result.severity === 'critical' ? 40 : 30,
        file: filePath,
        evidence: { snippet: result.snippet || '', note: result.note || '' },
        remediation: 'Heavy obfuscation detected. Manually decode and inspect before use.',
      });
    }
  }
  
  return findings;
}
