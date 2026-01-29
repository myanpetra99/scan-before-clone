// IDE Security Rules - Detects auto-execution risks in various IDEs
// Covers: JetBrains (IntelliJ, PyCharm, etc.), Vim/Neovim, Emacs, Sublime Text

import { parseJsonc } from './jsonc';
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

// Common dangerous command indicators
const DANGEROUS_COMMANDS = [
  /\bcurl\b/i,
  /\bwget\b/i,
  /\bnc\b/i,
  /\bnetcat\b/i,
  /\bbash\s+-c\b/i,
  /\bsh\s+-c\b/i,
  /\bpowershell\b/i,
  /\bInvoke-WebRequest\b/i,
  /\bInvoke-Expression\b/i,
  /\bStart-Process\b/i,
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /\bos\.system\s*\(/,
  /\bsubprocess\./,
  /\brm\s+-rf\b/,
  /\/dev\/tcp\//,
  /\|\s*(bash|sh|python|node)\b/,
];

function hasDangerousCommand(text: string): { found: boolean; indicators: string[] } {
  const indicators: string[] = [];
  for (const pattern of DANGEROUS_COMMANDS) {
    if (pattern.test(text)) {
      indicators.push(pattern.source.replace(/\\b/g, '').replace(/\\s\+/g, ' '));
    }
  }
  return { found: indicators.length > 0, indicators };
}

// ========== JETBRAINS IDE RULES ==========

interface JetBrainsRunConfig {
  type?: string;
  name?: string;
  SCRIPT_TEXT?: string;
  INTERPRETER_PATH?: string;
  SCRIPT_NAME?: string;
  PARAMETERS?: string;
  WORKING_DIRECTORY?: string;
}

/**
 * Detect malicious JetBrains IDE run configurations
 * Files: .idea/runConfigurations/*.xml, .idea/workspace.xml
 */
export function detectJetBrainsRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for .idea run configurations
  const isRunConfig = /\.idea[/\\]runConfigurations[/\\][^/\\]+\.xml$/i.test(filePath);
  const isWorkspace = /\.idea[/\\]workspace\.xml$/i.test(filePath);
  const isExternalDeps = /\.idea[/\\]externalDependencies\.xml$/i.test(filePath);
  
  if (!isRunConfig && !isWorkspace && !isExternalDeps) {
    return findings;
  }
  
  // Extract shell script content from XML
  const scriptMatches = content.matchAll(/<option\s+name="SCRIPT_TEXT"\s+value="([^"]+)"/gi);
  for (const match of scriptMatches) {
    const scriptText = match[1]
      .replace(/&#10;/g, '\n')
      .replace(/&#13;/g, '\r')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&');
    
    const { found, indicators } = hasDangerousCommand(scriptText);
    if (found) {
      findings.push({
        id: 'jetbrains-run-config-shell',
        category: 'EXECUTION_TRIGGER' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 30,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: `JetBrains run configuration contains dangerous shell commands: ${indicators.join(', ')}`,
        },
        remediation: 'Review .idea/runConfigurations/ files before opening the project. Remove or disable suspicious run configurations.',
      });
    }
  }
  
  // Check for suspicious script paths
  const scriptPathMatches = content.matchAll(/<option\s+name="SCRIPT_NAME"\s+value="([^"]+)"/gi);
  for (const match of scriptPathMatches) {
    const scriptPath = match[1];
    if (/\/tmp\/|\\temp\\|AppData.*Local.*Temp/i.test(scriptPath)) {
      findings.push({
        id: 'jetbrains-run-config-temp-script',
        category: 'EXECUTION_TRIGGER' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: match[0],
          note: `Run configuration executes script from temp directory: ${scriptPath}`,
        },
        remediation: 'Scripts should not be executed from temporary directories.',
      });
    }
  }
  
  // Check for external tools/commands
  const externalCmdMatches = content.matchAll(/<option\s+name="COMMAND"\s+value="([^"]+)"/gi);
  for (const match of externalCmdMatches) {
    const command = match[1];
    const { found, indicators } = hasDangerousCommand(command);
    if (found) {
      findings.push({
        id: 'jetbrains-external-tool-cmd',
        category: 'EXECUTION_TRIGGER' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: `External tool command contains dangerous patterns: ${indicators.join(', ')}`,
        },
        remediation: 'Review external tool configurations in .idea/ directory.',
      });
    }
  }
  
  // Check for before/after launch tasks with shell execution
  const beforeLaunchMatches = content.matchAll(/<beforeRunTasks>[\s\S]*?<\/beforeRunTasks>/gi);
  for (const match of beforeLaunchMatches) {
    const taskBlock = match[0];
    if (/Shell\s*Script|Run\s*External\s*tool/i.test(taskBlock)) {
      const { found, indicators } = hasDangerousCommand(taskBlock);
      if (found) {
        findings.push({
          id: 'jetbrains-before-launch-shell',
          category: 'EXECUTION_TRIGGER' as FindingCategory,
          severity: 'high' as FindingSeverity,
          scoreDelta: 30,
          file: filePath,
          evidence: {
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: `Before-launch task executes shell commands: ${indicators.join(', ')}`,
          },
          remediation: 'Before-launch tasks can execute automatically. Review and disable if suspicious.',
        });
      }
    }
  }
  
  return findings;
}

// ========== VIM/NEOVIM RULES ==========

/**
 * Detect malicious Vim modelines and config files
 * Vim modelines can execute arbitrary commands when a file is opened
 */
export function detectVimRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for Vim modelines in any file (first 5 and last 5 lines are checked by Vim)
  // Modeline format: vim: set ... : or /* vim: ... */ or # vim: ...
  const modelinePatterns = [
    /^\s*[#/*-]*\s*vim?:\s*(.+)$/gim,
    /^\s*[#/*-]*\s*ex:\s*(.+)$/gim,
    /^\s*[#/*-]*\s*set\s+modeline.*/gim,
  ];
  
  for (const pattern of modelinePatterns) {
    const matches = content.matchAll(pattern);
    for (const match of matches) {
      const modeline = match[1] || match[0];
      
      // Check for dangerous modeline commands
      // These can execute shell commands: !command, system(), autocmd
      const dangerousPatterns = [
        /![\w/]/,                    // Shell command execution
        /system\s*\(/i,              // system() call
        /autocmd/i,                  // Auto-commands
        /source\s+/i,                // Source external file
        /pyfile\s+/i,                // Python file execution
        /py3file\s+/i,
        /rubyfile\s+/i,
        /perlfile\s+/i,
        /luafile\s+/i,
        /exe\s+/i,                   // Execute expression
        /normal!\s+/i,               // Normal mode commands with !
      ];
      
      for (const dangerPattern of dangerousPatterns) {
        if (dangerPattern.test(modeline)) {
          findings.push({
            id: 'vim-modeline-exec',
            category: 'EXECUTION_TRIGGER' as FindingCategory,
            severity: 'high' as FindingSeverity,
            scoreDelta: 35,
            file: filePath,
            evidence: {
              snippet: match[0].substring(0, 200),
              note: `Vim modeline with code execution potential. Pattern: ${dangerPattern.source}`,
            },
            remediation: 'Vim modelines can execute code when opening a file. Set "set nomodeline" in your .vimrc or review carefully.',
          });
          break;
        }
      }
    }
  }
  
  // Check for project-local vim config files
  const isVimConfig = /^\.exrc$|^\.nvimrc$|^\.vimrc$|^\.lvimrc$/i.test(filePath.split('/').pop() || '');
  const isNvimLua = /^\.nvim\.lua$/i.test(filePath.split('/').pop() || '');
  
  if (isVimConfig || isNvimLua) {
    // Check for dangerous commands in local config
    const { found, indicators } = hasDangerousCommand(content);
    if (found) {
      findings.push({
        id: 'vim-local-config-exec',
        category: 'EXECUTION_TRIGGER' as FindingCategory,
        severity: 'critical' as FindingSeverity,
        scoreDelta: 40,
        file: filePath,
        evidence: {
          snippet: content.substring(0, 300),
          note: `Local Vim config contains dangerous commands: ${indicators.join(', ')}`,
        },
        remediation: 'Project-local Vim configs (.exrc, .nvimrc) execute when opening folder. Ensure "set noexrc" or review carefully.',
      });
    }
    
    // Check for autocmd in local config
    if (/autocmd\s+(BufRead|BufEnter|VimEnter|FileType)/i.test(content)) {
      const { found: hasDanger, indicators: dangerIndicators } = hasDangerousCommand(content);
      if (hasDanger) {
        findings.push({
          id: 'vim-autocmd-danger',
          category: 'EXECUTION_TRIGGER' as FindingCategory,
          severity: 'high' as FindingSeverity,
          scoreDelta: 30,
          file: filePath,
          evidence: {
            snippet: content.substring(0, 300),
            note: `Vim autocmd combined with dangerous commands: ${dangerIndicators.join(', ')}`,
          },
          remediation: 'Autocmds trigger automatically on file events. Review the commands executed.',
        });
      }
    }
  }
  
  return findings;
}

// ========== EMACS RULES ==========

/**
 * Detect malicious Emacs directory-local variables
 * .dir-locals.el can execute Elisp when opening any file in the directory
 */
export function detectEmacsRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  const fileName = filePath.split('/').pop() || '';
  const isDirLocals = fileName === '.dir-locals.el' || fileName === '.dir-locals-2.el';
  const isProjectile = fileName === '.projectile';
  
  if (!isDirLocals && !isProjectile) {
    return findings;
  }
  
  if (isDirLocals) {
    // Check for dangerous Elisp patterns
    const dangerousElispPatterns = [
      { pattern: /\(shell-command\s+/, name: 'shell-command' },
      { pattern: /\(call-process\s+/, name: 'call-process' },
      { pattern: /\(start-process\s+/, name: 'start-process' },
      { pattern: /\(async-shell-command\s+/, name: 'async-shell-command' },
      { pattern: /\(make-process\s+/, name: 'make-process' },
      { pattern: /\(eval\s+\./, name: 'eval' },
      { pattern: /\(load-file\s+/, name: 'load-file' },
      { pattern: /\(load\s+"/, name: 'load' },
      { pattern: /\(require\s+'/, name: 'require' },
      { pattern: /\(url-retrieve\s+/, name: 'url-retrieve' },
      { pattern: /\(url-retrieve-synchronously\s+/, name: 'url-retrieve-synchronously' },
    ];
    
    for (const { pattern, name } of dangerousElispPatterns) {
      const match = content.match(pattern);
      if (match) {
        findings.push({
          id: 'emacs-dir-locals-exec',
          category: 'EXECUTION_TRIGGER' as FindingCategory,
          severity: 'critical' as FindingSeverity,
          scoreDelta: 40,
          file: filePath,
          evidence: {
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: `.dir-locals.el contains code execution: ${name}`,
          },
          remediation: 'Emacs .dir-locals.el executes when opening files in directory. Set enable-local-variables to :safe or review carefully.',
        });
        break; // One finding per file is enough
      }
    }
    
    // Check for unsafe local variable declarations
    if (/\benable-local-variables\s*\.\s*:all\b/.test(content)) {
      findings.push({
        id: 'emacs-unsafe-local-vars',
        category: 'EXECUTION_TRIGGER' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: content.substring(0, 300),
          note: '.dir-locals.el attempts to enable all local variables without prompting',
        },
        remediation: 'This allows arbitrary code execution. Never allow all local variables.',
      });
    }
  }
  
  return findings;
}

// ========== SUBLIME TEXT RULES ==========

interface SublimeProject {
  build_systems?: Array<{
    name?: string;
    cmd?: string | string[];
    shell_cmd?: string;
    working_dir?: string;
    env?: Record<string, string>;
  }>;
  settings?: Record<string, unknown>;
}

/**
 * Detect malicious Sublime Text project configurations
 * .sublime-project files can define build systems that execute commands
 */
export function detectSublimeRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  const fileName = filePath.split('/').pop() || '';
  const isSublimeProject = fileName.endsWith('.sublime-project');
  const isSublimeBuild = fileName.endsWith('.sublime-build');
  
  if (!isSublimeProject && !isSublimeBuild) {
    return findings;
  }
  
  const config = parseJsonc<SublimeProject>(content);
  if (!config) {
    return findings;
  }
  
  // Check build systems
  const buildSystems = config.build_systems || [];
  
  // For .sublime-build files, treat the whole file as a build system
  if (isSublimeBuild) {
    const buildConfig = config as unknown as SublimeProject['build_systems'][0];
    if (buildConfig) {
      buildSystems.push(buildConfig);
    }
  }
  
  for (const build of buildSystems) {
    // Check shell_cmd
    if (build.shell_cmd) {
      const { found, indicators } = hasDangerousCommand(build.shell_cmd);
      if (found) {
        findings.push({
          id: 'sublime-build-shell-cmd',
          category: 'EXECUTION_TRIGGER' as FindingCategory,
          severity: 'high' as FindingSeverity,
          scoreDelta: 30,
          file: filePath,
          evidence: {
            snippet: `"shell_cmd": "${build.shell_cmd.substring(0, 150)}..."`,
            note: `Sublime build system "${build.name || 'unnamed'}" contains dangerous commands: ${indicators.join(', ')}`,
          },
          remediation: 'Review .sublime-project build systems before building. Commands execute in shell.',
        });
      }
    }
    
    // Check cmd array
    if (build.cmd) {
      const cmdStr = Array.isArray(build.cmd) ? build.cmd.join(' ') : build.cmd;
      const { found, indicators } = hasDangerousCommand(cmdStr);
      if (found) {
        findings.push({
          id: 'sublime-build-cmd',
          category: 'EXECUTION_TRIGGER' as FindingCategory,
          severity: 'high' as FindingSeverity,
          scoreDelta: 25,
          file: filePath,
          evidence: {
            snippet: `"cmd": ${JSON.stringify(build.cmd).substring(0, 150)}...`,
            note: `Sublime build system "${build.name || 'unnamed'}" contains dangerous commands: ${indicators.join(', ')}`,
          },
          remediation: 'Review build commands before running builds in Sublime Text.',
        });
      }
    }
    
    // Check for suspicious env vars
    if (build.env) {
      for (const [key, value] of Object.entries(build.env)) {
        const { found, indicators } = hasDangerousCommand(value);
        if (found) {
          findings.push({
            id: 'sublime-build-env',
            category: 'EXFILTRATION' as FindingCategory,
            severity: 'medium' as FindingSeverity,
            scoreDelta: 15,
            file: filePath,
            evidence: {
              snippet: `"env": { "${key}": "${value.substring(0, 100)}..." }`,
              note: `Build environment variable contains suspicious content: ${indicators.join(', ')}`,
            },
            remediation: 'Environment variables in build systems can leak data. Review carefully.',
          });
        }
      }
    }
  }
  
  return findings;
}

// ========== CURSOR IDE RULES ==========

/**
 * Detect malicious Cursor IDE configurations
 * Cursor is a VS Code fork - similar attack vectors plus AI-specific configs
 */
export function detectCursorRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for Cursor-specific config files
  const isCursorConfig = /\.cursor[/\\][^/\\]+\.json$/i.test(filePath) ||
    /\.cursor[/\\]settings\.json$/i.test(filePath);
  
  if (!isCursorConfig) {
    return findings;
  }
  
  // Check for task configurations similar to VS Code
  const { found, indicators } = hasDangerousCommand(content);
  if (found) {
    findings.push({
      id: 'cursor-config-exec',
      category: 'EXECUTION_TRIGGER' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 25,
      file: filePath,
      evidence: {
        snippet: content.substring(0, 300),
        note: `Cursor config contains dangerous commands: ${indicators.join(', ')}`,
      },
      remediation: 'Review .cursor/ directory contents before opening in Cursor IDE.',
    });
  }
  
  return findings;
}

// ========== ZED EDITOR RULES ==========

/**
 * Detect malicious Zed editor configurations
 */
export function detectZedRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for Zed config files
  const isZedConfig = /\.zed[/\\]settings\.json$/i.test(filePath) ||
    filePath.endsWith('.zed/tasks.json');
  
  if (!isZedConfig) {
    return findings;
  }
  
  // Check for task or language server configurations with dangerous commands
  const { found, indicators } = hasDangerousCommand(content);
  if (found) {
    findings.push({
      id: 'zed-config-exec',
      category: 'EXECUTION_TRIGGER' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 25,
      file: filePath,
      evidence: {
        snippet: content.substring(0, 300),
        note: `Zed config contains dangerous commands: ${indicators.join(', ')}`,
      },
      remediation: 'Review .zed/ directory before opening project in Zed editor.',
    });
  }
  
  return findings;
}

// ========== HELIX EDITOR RULES ==========

/**
 * Detect malicious Helix editor configurations
 */
export function detectHelixRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for Helix config files
  const isHelixConfig = /\.helix[/\\](?:config|languages)\.toml$/i.test(filePath);
  
  if (!isHelixConfig) {
    return findings;
  }
  
  // Check for language server or formatter configs with dangerous commands
  const { found, indicators } = hasDangerousCommand(content);
  if (found) {
    findings.push({
      id: 'helix-config-exec',
      category: 'EXECUTION_TRIGGER' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 25,
      file: filePath,
      evidence: {
        snippet: content.substring(0, 300),
        note: `Helix config contains dangerous commands: ${indicators.join(', ')}`,
      },
      remediation: 'Review .helix/ directory before opening project in Helix editor.',
    });
  }
  
  return findings;
}

// ========== NEOVIM PLUGIN MANAGER RULES ==========

/**
 * Detect risky Neovim plugin configurations (lazy.nvim, packer.nvim)
 */
export function detectNeovimPluginRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for Neovim Lua plugin configs
  const isNvimPluginConfig = /lua[/\\](?:plugins?|lazy|packer)[/\\]?.*\.lua$/i.test(filePath) ||
    /\.config[/\\]nvim[/\\].*\.lua$/i.test(filePath);
  
  if (!isNvimPluginConfig) {
    return findings;
  }
  
  // Check for plugins from suspicious sources
  const gitPluginMatch = content.match(/['"]([^'"]+\/[^'"]+)['"].*(?:dir|url|git)/i);
  if (gitPluginMatch) {
    const pluginPath = gitPluginMatch[1];
    // Flag non-GitHub or suspicious plugin sources
    if (!pluginPath.includes('github.com') && !pluginPath.includes('gitlab.com')) {
      if (/https?:\/\//.test(pluginPath)) {
        findings.push({
          id: 'nvim-plugin-untrusted',
          category: 'DEPENDENCY_RISK' as FindingCategory,
          severity: 'medium' as FindingSeverity,
          scoreDelta: 15,
          file: filePath,
          evidence: {
            snippet: gitPluginMatch[0].substring(0, 200),
            note: `Neovim plugin from non-standard source: ${pluginPath}`,
          },
          remediation: 'Verify plugin sources. Prefer well-known repos on GitHub.',
        });
      }
    }
  }
  
  // Check for post-install hooks with dangerous commands
  const buildMatch = content.match(/build\s*=\s*['"][^'"]+['"]/i);
  if (buildMatch) {
    const { found, indicators } = hasDangerousCommand(buildMatch[0]);
    if (found) {
      findings.push({
        id: 'nvim-plugin-build-exec',
        category: 'EXECUTION_TRIGGER' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: buildMatch[0].substring(0, 200),
          note: `Plugin build command contains dangerous patterns: ${indicators.join(', ')}`,
        },
        remediation: 'Review plugin build commands. They execute during plugin installation.',
      });
    }
  }
  
  return findings;
}

// ========== MAIN DETECTION FUNCTION ==========

/**
 * Run all IDE-specific security rules on a file
 */
export function detectIDEMalware(filePath: string, content: string): Finding[] {
  return [
    ...detectJetBrainsRisks(filePath, content),
    ...detectVimRisks(filePath, content),
    ...detectEmacsRisks(filePath, content),
    ...detectSublimeRisks(filePath, content),
    ...detectCursorRisks(filePath, content),
    ...detectZedRisks(filePath, content),
    ...detectHelixRisks(filePath, content),
    ...detectNeovimPluginRisks(filePath, content),
  ];
}
