// Container Orchestration Security Rules
// Covers: Kubernetes, Helm, Docker Compose, Kustomize

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

// ========== KUBERNETES DETECTION ==========

/**
 * Detect security risks in Kubernetes manifests
 */
export function detectKubernetesRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check if this is a Kubernetes manifest
  const isK8s = /apiVersion:\s*['"]?(?:v1|apps\/v1|batch\/v1|rbac)/i.test(content) ||
    /kind:\s*['"]?(?:Pod|Deployment|DaemonSet|StatefulSet|Job|CronJob|ClusterRole)/i.test(content);
  
  if (!isK8s) {
    return findings;
  }
  
  // Privileged containers
  const privilegedMatch = content.match(/privileged:\s*true/i);
  if (privilegedMatch) {
    findings.push({
      id: 'k8s-privileged-container',
      category: 'CONTAINER_RISK' as FindingCategory,
      severity: 'critical' as FindingSeverity,
      scoreDelta: 40,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, privilegedMatch.index || 0, privilegedMatch[0].length),
        note: 'Kubernetes pod runs with privileged: true (full host access)',
      },
      remediation: 'Remove privileged: true. Use specific capabilities instead if needed.',
    });
  }
  
  // Host network/PID/IPC namespaces
  const hostNetMatch = content.match(/hostNetwork:\s*true/i);
  if (hostNetMatch) {
    findings.push({
      id: 'k8s-host-network',
      category: 'CONTAINER_RISK' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 25,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, hostNetMatch.index || 0, hostNetMatch[0].length),
        note: 'Pod uses host network namespace',
      },
      remediation: 'Avoid hostNetwork: true unless absolutely necessary.',
    });
  }
  
  const hostPidMatch = content.match(/hostPID:\s*true/i);
  if (hostPidMatch) {
    findings.push({
      id: 'k8s-host-pid',
      category: 'CONTAINER_RISK' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 25,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, hostPidMatch.index || 0, hostPidMatch[0].length),
        note: 'Pod uses host PID namespace (can see all host processes)',
      },
      remediation: 'Avoid hostPID: true. This exposes all host processes to the container.',
    });
  }
  
  // Dangerous capabilities
  const capPatterns = [
    { pattern: /SYS_ADMIN/i, cap: 'SYS_ADMIN' },
    { pattern: /SYS_PTRACE/i, cap: 'SYS_PTRACE' },
    { pattern: /NET_ADMIN/i, cap: 'NET_ADMIN' },
    { pattern: /NET_RAW/i, cap: 'NET_RAW' },
  ];
  
  for (const { pattern, cap } of capPatterns) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        id: `k8s-dangerous-cap-${cap.toLowerCase()}`,
        category: 'CONTAINER_RISK' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 20,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: `Container adds dangerous capability: ${cap}`,
        },
        remediation: `Remove ${cap} capability unless absolutely required.`,
      });
    }
  }
  
  // Sensitive host path mounts
  const sensitivePathPatterns = [
    { pattern: /path:\s*['"]?\/var\/run\/docker\.sock['"]?/i, path: 'Docker socket' },
    { pattern: /path:\s*['"]?\/etc\/shadow['"]?/i, path: '/etc/shadow' },
    { pattern: /path:\s*['"]?\/etc\/passwd['"]?/i, path: '/etc/passwd' },
    { pattern: /path:\s*['"]?\/root['"]?/i, path: '/root' },
    { pattern: /path:\s*['"]?\/[\s]*['"]?/i, path: 'Root filesystem' },
  ];
  
  for (const { pattern, path } of sensitivePathPatterns) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        id: 'k8s-sensitive-mount',
        category: 'CONTAINER_RISK' as FindingCategory,
        severity: 'critical' as FindingSeverity,
        scoreDelta: 35,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: `Pod mounts sensitive host path: ${path}`,
        },
        remediation: 'Avoid mounting sensitive host paths into containers.',
      });
    }
  }
  
  // RBAC cluster-admin
  const clusterAdminMatch = content.match(/name:\s*['"]?cluster-admin['"]?/i);
  if (clusterAdminMatch && /ClusterRoleBinding/i.test(content)) {
    findings.push({
      id: 'k8s-cluster-admin-binding',
      category: 'CONTAINER_RISK' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 30,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, clusterAdminMatch.index || 0, clusterAdminMatch[0].length),
        note: 'ClusterRoleBinding grants cluster-admin privileges',
      },
      remediation: 'Use least-privilege RBAC. Avoid cluster-admin bindings.',
    });
  }
  
  // Secrets in manifests
  const secretPatterns = [
    /password:\s*['"][^'"]+['"]/i,
    /apiKey:\s*['"][^'"]+['"]/i,
    /secretKey:\s*['"][^'"]+['"]/i,
    /token:\s*['"][A-Za-z0-9+/=]{20,}['"]/i,
  ];
  
  for (const pattern of secretPatterns) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        id: 'k8s-hardcoded-secret',
        category: 'SECRETS' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, match.index || 0, Math.min(match[0].length, 50)),
          note: 'Hardcoded secret in Kubernetes manifest',
        },
        remediation: 'Use Kubernetes Secrets or external secret management.',
      });
      break;
    }
  }
  
  return findings;
}

// ========== HELM DETECTION ==========

/**
 * Detect security risks in Helm charts
 */
export function detectHelmRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check if this is a Helm chart
  const isHelm = /^Chart\.ya?ml$/i.test(filePath.split('/').pop() || '') ||
    filePath.includes('/templates/') ||
    /\{\{.*\.Values\./i.test(content);
  
  if (!isHelm && !filePath.includes('helm')) {
    return findings;
  }
  
  // Helm hooks with command execution
  const hookPatterns = [
    { pattern: /helm\.sh\/hook.*pre-install/i, hook: 'pre-install' },
    { pattern: /helm\.sh\/hook.*post-install/i, hook: 'post-install' },
    { pattern: /helm\.sh\/hook.*pre-upgrade/i, hook: 'pre-upgrade' },
    { pattern: /helm\.sh\/hook.*post-upgrade/i, hook: 'post-upgrade' },
  ];
  
  for (const { pattern, hook } of hookPatterns) {
    const match = content.match(pattern);
    if (match) {
      // Check for command execution in the same file
      if (/command:|args:|curl|wget|bash|sh\s+-c/i.test(content)) {
        findings.push({
          id: 'helm-hook-exec',
          category: 'CONTAINER_RISK' as FindingCategory,
          severity: 'high' as FindingSeverity,
          scoreDelta: 25,
          file: filePath,
          evidence: {
            snippet: extractSnippet(content, match.index || 0, match[0].length),
            note: `Helm ${hook} hook executes commands`,
          },
          remediation: 'Review Helm hook commands. These run automatically during install/upgrade.',
        });
        break;
      }
    }
  }
  
  // Templated image with no digest/tag
  const templateImageMatch = content.match(/image:\s*\{\{.*\.Values\..*\}\}/i);
  if (templateImageMatch && !/sha256:|@sha256/i.test(content)) {
    findings.push({
      id: 'helm-unpinned-image',
      category: 'CONTAINER_RISK' as FindingCategory,
      severity: 'medium' as FindingSeverity,
      scoreDelta: 10,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, templateImageMatch.index || 0, templateImageMatch[0].length),
        note: 'Helm chart uses templated image without digest pinning',
      },
      remediation: 'Consider using image digests for reproducible deployments.',
    });
  }
  
  return findings;
}

// ========== DOCKER COMPOSE DETECTION ==========

/**
 * Detect security risks in Docker Compose files
 */
export function detectDockerComposeRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check if this is a Docker Compose file
  const isCompose = /docker-compose\.ya?ml$/i.test(filePath) ||
    /compose\.ya?ml$/i.test(filePath) ||
    (/services:/i.test(content) && /image:/i.test(content));
  
  if (!isCompose) {
    return findings;
  }
  
  // Privileged containers
  const privilegedMatch = content.match(/privileged:\s*true/i);
  if (privilegedMatch) {
    findings.push({
      id: 'compose-privileged',
      category: 'CONTAINER_RISK' as FindingCategory,
      severity: 'critical' as FindingSeverity,
      scoreDelta: 35,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, privilegedMatch.index || 0, privilegedMatch[0].length),
        note: 'Docker Compose service runs in privileged mode',
      },
      remediation: 'Remove privileged: true. Use cap_add with specific capabilities if needed.',
    });
  }
  
  // Docker socket mount
  const socketMatch = content.match(/\/var\/run\/docker\.sock/i);
  if (socketMatch) {
    findings.push({
      id: 'compose-docker-socket',
      category: 'CONTAINER_RISK' as FindingCategory,
      severity: 'critical' as FindingSeverity,
      scoreDelta: 40,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, socketMatch.index || 0, socketMatch[0].length),
        note: 'Docker socket mounted into container (container escape possible)',
      },
      remediation: 'Avoid mounting Docker socket. Use Docker-in-Docker or alternatives.',
    });
  }
  
  // Sensitive host mounts
  const sensitiveMountPatterns = [
    { pattern: /['"]?\/etc\/passwd['"]?\s*:/i, path: '/etc/passwd' },
    { pattern: /['"]?\/etc\/shadow['"]?\s*:/i, path: '/etc/shadow' },
    { pattern: /['"]?\/root['"]?\s*:/i, path: '/root' },
    { pattern: /['"]?\/['"]?\s*:/i, path: 'Root filesystem' },
  ];
  
  for (const { pattern, path } of sensitiveMountPatterns) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        id: 'compose-sensitive-mount',
        category: 'CONTAINER_RISK' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: `Sensitive host path mounted: ${path}`,
        },
        remediation: 'Avoid mounting sensitive host paths into containers.',
      });
    }
  }
  
  // Network mode host
  const hostNetMatch = content.match(/network_mode:\s*['"]?host['"]?/i);
  if (hostNetMatch) {
    findings.push({
      id: 'compose-host-network',
      category: 'CONTAINER_RISK' as FindingCategory,
      severity: 'medium' as FindingSeverity,
      scoreDelta: 15,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, hostNetMatch.index || 0, hostNetMatch[0].length),
        note: 'Container uses host network mode',
      },
      remediation: 'Avoid network_mode: host unless necessary.',
    });
  }
  
  // Dangerous capabilities
  const capAddMatch = content.match(/cap_add:\s*\n\s*-\s*(?:SYS_ADMIN|ALL)/i);
  if (capAddMatch) {
    findings.push({
      id: 'compose-dangerous-cap',
      category: 'CONTAINER_RISK' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 25,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, capAddMatch.index || 0, capAddMatch[0].length),
        note: 'Container adds dangerous capabilities',
      },
      remediation: 'Use least-privilege capabilities. Avoid SYS_ADMIN and ALL.',
    });
  }
  
  return findings;
}

// ========== MAIN DETECTION FUNCTION ==========

/**
 * Run all container orchestration security rules on a file
 */
export function detectContainerOrchRisks(filePath: string, content: string): Finding[] {
  return [
    ...detectKubernetesRisks(filePath, content),
    ...detectHelmRisks(filePath, content),
    ...detectDockerComposeRisks(filePath, content),
  ];
}
