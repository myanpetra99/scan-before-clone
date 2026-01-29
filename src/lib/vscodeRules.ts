// VS Code Config Security Rules
// Detects malicious patterns in .vscode/tasks.json, launch.json, settings.json

import { parseJsonc } from './jsonc';
import type { Finding, FindingCategory, FindingSeverity } from '@/types/scanner';

// ========== TYPES ==========

interface VSCodeTask {
  label?: string;
  type?: string;
  command?: string;
  args?: string[];
  options?: {
    cwd?: string;
    env?: Record<string, string>;
    shell?: {
      executable?: string;
      args?: string[];
    };
  };
  runOptions?: {
    runOn?: 'default' | 'folderOpen';
    instanceLimit?: number;
  };
  // OS-specific command overrides
  osx?: {
    command?: string;
    args?: string[];
  };
  linux?: {
    command?: string;
    args?: string[];
  };
  windows?: {
    command?: string;
    args?: string[];
  };
  // Shell task
  shell?: string;
  // Compound tasks
  dependsOn?: string | string[];
  presentation?: unknown;
}

interface VSCodeTasksConfig {
  version?: string;
  tasks?: VSCodeTask[];
  inputs?: unknown[];
}

interface CommandAnalysis {
  command: string;
  os: 'all' | 'osx' | 'linux' | 'windows';
  hasNetwork: boolean;
  hasExec: boolean;
  hasChaining: boolean;
  networkIndicators: string[];
  execIndicators: string[];
  chainIndicators: string[];
}

// ========== INDICATORS ==========

const NETWORK_INDICATORS = [
  // Curl/wget
  { pattern: /\bcurl\b/i, name: 'curl' },
  { pattern: /\bwget\b/i, name: 'wget' },
  
  // PowerShell network
  { pattern: /\bInvoke-WebRequest\b/i, name: 'Invoke-WebRequest' },
  { pattern: /\biwr\b/i, name: 'iwr' },
  { pattern: /\bInvoke-RestMethod\b/i, name: 'Invoke-RestMethod' },
  { pattern: /\birm\b/i, name: 'irm' },
  { pattern: /\bStart-BitsTransfer\b/i, name: 'Start-BitsTransfer' },
  { pattern: /\[Net\.WebClient\]/i, name: 'WebClient' },
  { pattern: /\bDownloadString\b/i, name: 'DownloadString' },
  { pattern: /\bDownloadFile\b/i, name: 'DownloadFile' },
  
  // Python
  { pattern: /python[23]?\s+.*\brequests\b/i, name: 'python requests' },
  { pattern: /python[23]?\s+.*\burllib\b/i, name: 'python urllib' },
  { pattern: /python[23]?\s+-c\s+["'].*import\s+(requests|urllib)/i, name: 'python network import' },
  
  // Node.js
  { pattern: /node\s+.*\bhttps?\b/i, name: 'node http' },
  { pattern: /node\s+-e\s+["'].*\bfetch\b/i, name: 'node fetch' },
  { pattern: /npx\s+.*download/i, name: 'npx download' },
  
  // Netcat/telnet
  { pattern: /\bnc\b/i, name: 'netcat' },
  { pattern: /\bnetcat\b/i, name: 'netcat' },
  { pattern: /\btelnet\b/i, name: 'telnet' },
  
  // SSH/SCP
  { pattern: /\bssh\b.*@/i, name: 'ssh' },
  { pattern: /\bscp\b/i, name: 'scp' },
  { pattern: /\bsftp\b/i, name: 'sftp' },
];

const EXEC_INDICATORS = [
  // Shell execution
  { pattern: /\bbash\s+-c\b/i, name: 'bash -c' },
  { pattern: /\bsh\s+-c\b/i, name: 'sh -c' },
  { pattern: /\bzsh\s+-c\b/i, name: 'zsh -c' },
  
  // PowerShell
  { pattern: /\bpowershell\s+-Command\b/i, name: 'powershell -Command' },
  { pattern: /\bpowershell\s+-EncodedCommand\b/i, name: 'powershell -EncodedCommand' },
  { pattern: /\bpwsh\s+-Command\b/i, name: 'pwsh -Command' },
  { pattern: /\bStart-Process\b/i, name: 'Start-Process' },
  
  // Windows cmd
  { pattern: /\bcmd\s+\/c\b/i, name: 'cmd /c' },
  { pattern: /\bcmd\.exe\b/i, name: 'cmd.exe' },
  
  // Make executable and run
  { pattern: /\bchmod\s+\+x\b/i, name: 'chmod +x' },
  { pattern: /\.\/[a-zA-Z0-9_-]+/i, name: 'execute local' },
  
  // Eval/exec
  { pattern: /\beval\s+/i, name: 'eval' },
  { pattern: /\bexec\s+/i, name: 'exec' },
  
  // Python exec
  { pattern: /python[23]?\s+-c\s+["'].*exec\s*\(/i, name: 'python exec' },
  
  // Node exec
  { pattern: /node\s+-e\s+/i, name: 'node -e' },
];

const CHAIN_INDICATORS = [
  { pattern: /\|/, name: 'pipe' },
  { pattern: /&&/, name: 'and-then' },
  { pattern: /;\s*[a-zA-Z]/, name: 'semicolon chain' },
  { pattern: /`[^`]+`/, name: 'command substitution' },
  { pattern: /\$\([^)]+\)/, name: 'subshell' },
];

// ========== ANALYSIS FUNCTIONS ==========

/**
 * Build effective command string from task
 */
function buildCommand(task: VSCodeTask, os: 'all' | 'osx' | 'linux' | 'windows'): string {
  let cmd = '';
  let args: string[] = [];
  
  // Get OS-specific overrides
  if (os !== 'all') {
    const osOverride = task[os];
    if (osOverride?.command) {
      cmd = osOverride.command;
      args = osOverride.args || [];
    }
  }
  
  // Fall back to main command
  if (!cmd && task.command) {
    cmd = task.command;
    args = task.args || [];
  }
  
  // Build full command string
  if (args.length > 0) {
    return `${cmd} ${args.join(' ')}`;
  }
  return cmd;
}

/**
 * Analyze a command string for suspicious patterns
 */
function analyzeCommand(cmd: string, os: 'all' | 'osx' | 'linux' | 'windows'): CommandAnalysis {
  const networkIndicators: string[] = [];
  const execIndicators: string[] = [];
  const chainIndicators: string[] = [];
  
  for (const { pattern, name } of NETWORK_INDICATORS) {
    if (pattern.test(cmd)) {
      networkIndicators.push(name);
    }
  }
  
  for (const { pattern, name } of EXEC_INDICATORS) {
    if (pattern.test(cmd)) {
      execIndicators.push(name);
    }
  }
  
  for (const { pattern, name } of CHAIN_INDICATORS) {
    if (pattern.test(cmd)) {
      chainIndicators.push(name);
    }
  }
  
  return {
    command: cmd,
    os,
    hasNetwork: networkIndicators.length > 0,
    hasExec: execIndicators.length > 0,
    hasChaining: chainIndicators.length > 0,
    networkIndicators,
    execIndicators,
    chainIndicators,
  };
}

/**
 * Check if task has autorun enabled
 */
function hasAutorun(task: VSCodeTask): boolean {
  return task.runOptions?.runOn === 'folderOpen';
}

/**
 * Analyze a VS Code task for malicious patterns
 */
function analyzeTask(task: VSCodeTask): {
  isAutorun: boolean;
  analyses: CommandAnalysis[];
  label: string;
} {
  const label = task.label || task.type || 'unnamed';
  const isAutorun = hasAutorun(task);
  const analyses: CommandAnalysis[] = [];
  
  // Analyze main command
  const mainCmd = buildCommand(task, 'all');
  if (mainCmd) {
    analyses.push(analyzeCommand(mainCmd, 'all'));
  }
  
  // Analyze OS-specific commands
  for (const os of ['osx', 'linux', 'windows'] as const) {
    if (task[os]?.command) {
      const osCmd = buildCommand(task, os);
      if (osCmd && osCmd !== mainCmd) {
        analyses.push(analyzeCommand(osCmd, os));
      }
    }
  }
  
  return { isAutorun, analyses, label };
}

// ========== MAIN DETECTION FUNCTION ==========

/**
 * Detect malicious VS Code task configurations
 */
export function detectVSCodeTaskMalware(
  filePath: string,
  content: string
): Finding[] {
  const findings: Finding[] = [];
  
  // Only process tasks.json or task.json (both naming conventions exist)
  const isTaskFile = /[/\\]\.vscode[/\\]tasks?\.json$/i.test(filePath) || 
                     filePath.endsWith('tasks.json') || 
                     filePath.endsWith('task.json');
  if (!isTaskFile) {
    return findings;
  }
  
  // Parse JSONC
  const config = parseJsonc<VSCodeTasksConfig>(content);
  if (!config || !config.tasks || !Array.isArray(config.tasks)) {
    return findings;
  }
  
  // Analyze each task
  for (const task of config.tasks) {
    const { isAutorun, analyses, label } = analyzeTask(task);
    
    // Check for malicious patterns
    for (const analysis of analyses) {
      // Rule: VSCODE_TASK_AUTORUN_NETWORK_OR_EXEC
      if (isAutorun && (analysis.hasNetwork || analysis.hasExec)) {
        // Calculate score
        let scoreDelta = 35; // Base for autorun + network/exec
        if (analysis.hasNetwork && analysis.hasExec) {
          scoreDelta += 10;
        }
        if (analysis.hasChaining) {
          scoreDelta += 5;
        }
        
        // Build evidence snippet
        const osLabel = analysis.os === 'all' ? '' : ` [${analysis.os}]`;
        const indicators = [
          ...analysis.networkIndicators,
          ...analysis.execIndicators,
          ...analysis.chainIndicators,
        ].join(', ');
        
        const snippet = buildEvidenceSnippet(task, analysis, label);
        
        findings.push({
          id: 'vscode-task-autorun-network-exec',
          category: 'EXECUTION_TRIGGER' as FindingCategory,
          severity: 'high' as FindingSeverity,
          scoreDelta,
          file: filePath,
          evidence: {
            snippet,
            note: `Task "${label}"${osLabel} auto-runs on folder open with suspicious commands. Indicators: ${indicators}`,
          },
          remediation: 'Remove runOptions.runOn: "folderOpen" or inspect the command carefully. Never open untrusted repositories in VS Code without reviewing .vscode/tasks.json first.',
        });
      }
      
      // Also flag network commands even without autorun (lower severity)
      if (!isAutorun && analysis.hasNetwork && analysis.hasChaining) {
        findings.push({
          id: 'vscode-task-network-chain',
          category: 'EXFILTRATION' as FindingCategory,
          severity: 'medium' as FindingSeverity,
          scoreDelta: 15,
          file: filePath,
          evidence: {
            snippet: buildEvidenceSnippet(task, analysis, label),
            note: `Task "${label}" contains network commands with piping/chaining`,
          },
          remediation: 'Review the task command to ensure it is not downloading and executing untrusted code.',
        });
      }
    }
  }
  
  return findings;
}

/**
 * Build evidence snippet for a finding
 */
function buildEvidenceSnippet(
  task: VSCodeTask,
  analysis: CommandAnalysis,
  label: string
): string {
  const parts: string[] = [];
  
  // Add runOn if present
  if (task.runOptions?.runOn) {
    parts.push(`"runOptions": { "runOn": "${task.runOptions.runOn}" }`);
  }
  
  // Add command
  if (analysis.os === 'all') {
    parts.push(`"command": "${analysis.command.substring(0, 150)}..."`);
  } else {
    parts.push(`"${analysis.os}": { "command": "${analysis.command.substring(0, 150)}..." }`);
  }
  
  // Build snippet with label
  const snippet = `Task: ${label}\n${parts.join('\n')}`;
  return snippet.substring(0, 400);
}

// ========== LAUNCH.JSON DETECTION ==========

interface VSCodeLaunchConfig {
  version?: string;
  configurations?: Array<{
    name?: string;
    type?: string;
    request?: string;
    program?: string;
    args?: string[];
    preLaunchTask?: string;
    postDebugTask?: string;
    env?: Record<string, string>;
  }>;
}

/**
 * Detect suspicious VS Code launch configurations
 */
export function detectVSCodeLaunchMalware(
  filePath: string,
  content: string
): Finding[] {
  const findings: Finding[] = [];
  
  if (!filePath.endsWith('launch.json') && !filePath.includes('.vscode/launch.json')) {
    return findings;
  }
  
  const config = parseJsonc<VSCodeLaunchConfig>(content);
  if (!config || !config.configurations) {
    return findings;
  }
  
  for (const launch of config.configurations) {
    // Check for suspicious env vars
    if (launch.env) {
      for (const [key, value] of Object.entries(launch.env)) {
        // Check for network commands in env
        for (const { pattern, name } of NETWORK_INDICATORS) {
          if (pattern.test(value)) {
            findings.push({
              id: 'vscode-launch-env-network',
              category: 'EXFILTRATION' as FindingCategory,
              severity: 'medium' as FindingSeverity,
              scoreDelta: 15,
              file: filePath,
              evidence: {
                snippet: `"env": { "${key}": "${value.substring(0, 100)}..." }`,
                note: `Launch config "${launch.name}" has network command (${name}) in environment variable`,
              },
              remediation: 'Review environment variables in launch.json for suspicious content.',
            });
            break;
          }
        }
      }
    }
    
    // Check for suspicious program paths
    if (launch.program) {
      if (/\/tmp\/|\\temp\\|AppData.*Local.*Temp/i.test(launch.program)) {
        findings.push({
          id: 'vscode-launch-temp-program',
          category: 'EXECUTION_TRIGGER' as FindingCategory,
          severity: 'high' as FindingSeverity,
          scoreDelta: 25,
          file: filePath,
          evidence: {
            snippet: `"program": "${launch.program}"`,
            note: `Launch config "${launch.name}" executes from temp directory`,
          },
          remediation: 'Programs should not be executed from temporary directories.',
        });
      }
    }
  }
  
  return findings;
}

// ========== SETTINGS.JSON DETECTION ==========

/**
 * Detect suspicious VS Code settings
 */
export function detectVSCodeSettingsMalware(
  filePath: string,
  content: string
): Finding[] {
  const findings: Finding[] = [];
  
  if (!filePath.endsWith('settings.json') && !filePath.includes('.vscode/settings.json')) {
    return findings;
  }
  
  const config = parseJsonc<Record<string, unknown>>(content);
  if (!config) {
    return findings;
  }
  
  // Check terminal settings
  const terminalProfiles = config['terminal.integrated.profiles.windows'] as Record<string, unknown> | undefined;
  const terminalDefault = config['terminal.integrated.defaultProfile.windows'] as string | undefined;
  
  // Check for suspicious terminal profiles
  if (terminalProfiles) {
    for (const [profileName, profile] of Object.entries(terminalProfiles)) {
      if (typeof profile === 'object' && profile !== null) {
        const p = profile as Record<string, unknown>;
        const path = p.path as string;
        const args = p.args as string[];
        
        if (path && /powershell|cmd|bash/i.test(path)) {
          const fullCmd = args ? `${path} ${args.join(' ')}` : path;
          for (const { pattern, name } of NETWORK_INDICATORS) {
            if (pattern.test(fullCmd)) {
              findings.push({
                id: 'vscode-settings-terminal-network',
                category: 'EXECUTION_TRIGGER' as FindingCategory,
                severity: 'high' as FindingSeverity,
                scoreDelta: 30,
                file: filePath,
                evidence: {
                  snippet: `"${profileName}": { "path": "${path}", "args": ${JSON.stringify(args || [])} }`,
                  note: `Terminal profile "${profileName}" contains network command (${name})`,
                },
                remediation: 'Remove suspicious terminal profiles from settings.json.',
              });
              break;
            }
          }
        }
      }
    }
  }
  
  // Check for suspicious extensions
  const recommendations = config['extensions.recommendations'] as string[] | undefined;
  if (recommendations) {
    // Flag if recommending unknown/suspicious extensions
    // (This is informational, not necessarily malicious)
  }
  
  return findings;
}

// ========== COMBINED DETECTION ==========

/**
 * Run all VS Code config detection rules
 */
export function detectVSCodeMalware(filePath: string, content: string): Finding[] {
  return [
    ...detectVSCodeTaskMalware(filePath, content),
    ...detectVSCodeLaunchMalware(filePath, content),
    ...detectVSCodeSettingsMalware(filePath, content),
  ];
}
