// Dynamic Safety Recommendations based on findings

import type { Finding, FindingCategory } from '@/types/scanner';

// Comprehensive dictionary of safety recommendations per category
export const CATEGORY_RECOMMENDATIONS: Record<FindingCategory, {
  immediate: string[];    // Do immediately before anything
  review: string[];       // What to review/check
  mitigation: string[];   // How to mitigate risk
}> = {
  EXECUTION_TRIGGER: {
    immediate: [
      'Open project in restricted/untrusted workspace mode',
      'Disable VS Code extensions auto-running tasks',
    ],
    review: [
      'Review package.json "scripts" section before npm install',
      'Check .vscode/tasks.json for "runOn: folderOpen" triggers',
      'Inspect setup.py/pyproject.toml for post-install scripts',
      'Review Makefile targets before running make',
    ],
    mitigation: [
      'Remove or comment out suspicious install/postinstall scripts',
      'Run npm install --ignore-scripts first',
    ],
  },

  EXFILTRATION: {
    immediate: [
      'Do NOT run with real credentials or secrets in environment',
      'Disconnect from sensitive networks before testing',
    ],
    review: [
      'Search for outbound network calls (fetch, axios, http)',
      'Check for file reading of ~/.ssh, ~/.aws, ~/.config paths',
      'Review any code accessing environment variables',
      'Look for webhook URLs or external endpoints',
    ],
    mitigation: [
      'Use mock/dummy credentials for testing',
      'Run in network-isolated container',
      'Block outbound traffic except known domains',
    ],
  },

  OBFUSCATION: {
    immediate: [
      'Treat obfuscated code as potentially malicious until verified',
    ],
    review: [
      'Decode base64/hex strings to inspect actual content',
      'Check what eval/exec statements are running',
      'Review heavily minified code that shouldn\'t be minified',
      'Inspect unusual Unicode or escape sequences',
    ],
    mitigation: [
      'De-obfuscate and analyze before running',
      'Ask repository owner for source/unminified version',
    ],
  },

  SOCIAL_ENGINEERING: {
    immediate: [
      'Do NOT follow unusual installation instructions',
      'Verify the repository is the official/expected source',
    ],
    review: [
      'Check README for suspicious commands (curl | bash)',
      'Verify any URLs in documentation are legitimate',
      'Compare with official project documentation',
      'Check repository stars/forks vs similar projects',
    ],
    mitigation: [
      'Cross-reference instructions with official sources',
      'Type commands manually rather than copy-paste',
    ],
  },

  DEPENDENCY_RISK: {
    immediate: [
      'Run npm audit / pip-audit before installing',
      'Check for typosquatting package names',
    ],
    review: [
      'Verify dependency names match intended packages',
      'Check for unpinned/floating versions',
      'Review new or unusual dependencies',
      'Check npm/pypi for package reputation',
    ],
    mitigation: [
      'Pin dependencies to specific versions',
      'Use lockfiles (package-lock.json, poetry.lock)',
      'Consider using private registry or caching',
    ],
  },

  BINARY_SUSPICION: {
    immediate: [
      'Do NOT execute binary files without verification',
      'Quarantine suspicious binaries',
    ],
    review: [
      'Check why binary files are included in source repo',
      'Verify binaries with hash/signature if available',
      'Scan binaries with antivirus/VirusTotal',
      'Compare binary sizes with expected tools',
    ],
    mitigation: [
      'Delete binaries and rebuild from source',
      'Request build instructions from maintainer',
    ],
  },

  CI_CD_RISK: {
    immediate: [
      'Do NOT fork until CI/CD files are reviewed',
      'Disable Actions on fork if auto-enabled',
    ],
    review: [
      'Check workflow triggers (push, pull_request, etc)',
      'Review shell commands in CI/CD pipelines',
      'Look for secrets being logged or exported',
      'Check for self-hosted runner exploitation',
    ],
    mitigation: [
      'Use restricted GitHub token permissions',
      'Review workflow changes in PRs',
      'Disable unnecessary workflow triggers',
    ],
  },

  SECRETS: {
    immediate: [
      'Assume exposed secrets are compromised',
      'Do NOT use repository secrets in production',
    ],
    review: [
      'Search for API keys, tokens, passwords in code',
      'Check .env files committed to repository',
      'Review git history for removed secrets',
      'Inspect config files for hardcoded credentials',
    ],
    mitigation: [
      'Rotate any exposed credentials immediately',
      'Use environment variables or secret managers',
      'Add secrets patterns to .gitignore',
    ],
  },

  PERSISTENCE: {
    immediate: [
      'Do NOT run with elevated/admin privileges',
      'Review before running on persistent systems',
    ],
    review: [
      'Check for cron/systemd/launchd service creation',
      'Look for registry modifications (Windows)',
      'Review startup script installations',
      'Check for SSH key additions',
    ],
    mitigation: [
      'Run in ephemeral container/VM only',
      'Monitor system changes during execution',
      'Use process sandboxing tools',
    ],
  },

  DOWNLOADER: {
    immediate: [
      'Block network access before running',
      'Do NOT pipe curl/wget output to shell',
    ],
    review: [
      'Inspect all URLs being fetched',
      'Check for dynamic URL construction',
      'Review what happens with downloaded content',
      'Look for encoded/obfuscated URLs',
    ],
    mitigation: [
      'Manually download and inspect payloads first',
      'Use network monitoring during execution',
      'Whitelist only known-safe domains',
    ],
  },

  BROWSER_EXTENSION: {
    immediate: [
      'Do NOT install the extension without reviewing permissions',
      'Check the extension in Chrome/Firefox developer mode first',
    ],
    review: [
      'Review manifest.json permissions carefully',
      'Check background scripts for network calls',
      'Inspect content scripts for form/keylogging patterns',
      'Verify externally_connectable settings',
    ],
    mitigation: [
      'Install in a separate browser profile for testing',
      'Use browser dev tools to monitor network activity',
      'Review extension code before granting permissions',
    ],
  },

  CONTAINER_RISK: {
    immediate: [
      'Do NOT run with privileged mode or host network',
      'Review volume mounts before starting containers',
    ],
    review: [
      'Check for privileged: true in Kubernetes/Compose',
      'Look for Docker socket mounts',
      'Review capability additions (SYS_ADMIN, etc.)',
      'Check RBAC bindings for cluster-admin',
    ],
    mitigation: [
      'Use rootless containers where possible',
      'Apply Pod Security Policies/Standards',
      'Restrict capabilities to minimum required',
    ],
  },

  SERVERLESS_RISK: {
    immediate: [
      'Review IAM policies before deployment',
      'Check for hardcoded secrets in config',
    ],
    review: [
      'Verify no wildcard IAM actions',
      'Check build commands for network calls',
      'Review custom plugins and runtimes',
      'Inspect inline Lambda code',
    ],
    mitigation: [
      'Apply least-privilege IAM policies',
      'Use Secrets Manager for credentials',
      'Pin plugin and runtime versions',
    ],
  },

  AI_ML_RISK: {
    immediate: [
      'Do NOT load pickle files from untrusted sources',
      'Review trust_remote_code settings',
    ],
    review: [
      'Check for pickle/joblib/torch.load usage',
      'Verify Hugging Face model sources',
      'Inspect Jupyter notebook hidden cells',
      'Review MLflow custom loaders',
    ],
    mitigation: [
      'Use safetensors instead of pickle for models',
      'Load models only from verified sources',
      'Clear notebook outputs before sharing',
    ],
  },
};

// Severity-based additional recommendations
const SEVERITY_RECOMMENDATIONS: Record<string, string[]> = {
  critical: [
    '⛔ HIGH RISK: Consider not using this repository',
    'Report to GitHub if malicious intent is clear',
    'Seek alternative, trusted packages',
  ],
  high: [
    '⚠️ Requires thorough manual review before use',
    'Consider contacting maintainer for clarification',
  ],
  medium: [
    'Review flagged items but likely safe with caution',
  ],
};

// File-pattern specific recommendations
const FILE_PATTERN_RECOMMENDATIONS: Array<{ pattern: RegExp; steps: string[] }> = [
  {
    pattern: /\.vscode\/(tasks|settings|launch)\.json/i,
    steps: [
      'Open VS Code in Restricted Mode first',
      'Review .vscode folder contents before trusting workspace',
    ],
  },
  {
    pattern: /\.devcontainer\//i,
    steps: [
      'Review devcontainer.json before allowing container build',
      'Check postCreateCommand and other lifecycle scripts',
    ],
  },
  {
    pattern: /\.github\/workflows\//i,
    steps: [
      'Review all GitHub Actions before forking',
      'Check for workflow_dispatch and repository_dispatch triggers',
    ],
  },
  {
    pattern: /\.gitmodules/i,
    steps: [
      'Do NOT use --recurse-submodules until submodules are reviewed',
      'Check submodule URLs for suspicious domains',
    ],
  },
  {
    pattern: /Dockerfile|docker-compose/i,
    steps: [
      'Review Docker images being pulled',
      'Check for privileged mode or host mounts',
    ],
  },
  {
    pattern: /package\.json$/i,
    steps: [
      'Review scripts section before npm install',
      'Check dependencies for typosquatting',
    ],
  },
  {
    pattern: /setup\.py|pyproject\.toml/i,
    steps: [
      'Review for post-install script execution',
      'Use pip install --no-build-isolation cautiously',
    ],
  },
  {
    pattern: /Makefile|CMakeLists\.txt/i,
    steps: [
      'Review build targets before running make',
      'Check for shell commands in build steps',
    ],
  },
];

/**
 * Generate dynamic safe next steps based on actual findings
 */
export function generateDynamicSafetySteps(
  findings: Finding[],
  verdict?: 'GO' | 'CAUTION' | 'NO-GO'
): string[] {
  const steps = new Set<string>();

  // Handle NO-GO verdict
  if (verdict === 'NO-GO') {
    steps.add('⛔ DO NOT clone, install, or run this repository');
    steps.add('Report this repository if you suspect malicious intent');
    steps.add('Seek alternative, trusted packages for the same functionality');
    return Array.from(steps);
  }

  // Collect categories and severities present
  const categories = new Set<FindingCategory>();
  const severities = new Set<string>();
  const files = new Set<string>();

  for (const finding of findings) {
    categories.add(finding.category);
    severities.add(finding.severity);
    if (finding.file) files.add(finding.file);
  }

  // Add severity-based recommendations first
  if (severities.has('critical')) {
    SEVERITY_RECOMMENDATIONS.critical.forEach(s => steps.add(s));
  } else if (severities.has('high')) {
    SEVERITY_RECOMMENDATIONS.high.forEach(s => steps.add(s));
  }

  // Always add base isolation recommendation if there are findings
  if (findings.length > 0 || verdict === 'CAUTION') {
    steps.add('Run in isolated container or VM, never on host machine');
  }

  // Add category-specific immediate actions
  for (const category of categories) {
    const recs = CATEGORY_RECOMMENDATIONS[category];
    if (recs) {
      // Add immediate actions
      recs.immediate.forEach(s => steps.add(s));
      // Add first review item (most relevant)
      if (recs.review.length > 0) {
        steps.add(recs.review[0]);
      }
    }
  }

  // Add file-pattern specific recommendations
  for (const file of files) {
    for (const { pattern, steps: patternSteps } of FILE_PATTERN_RECOMMENDATIONS) {
      if (pattern.test(file)) {
        patternSteps.forEach(s => steps.add(s));
      }
    }
  }

  // Add mitigation for high-impact categories
  const highImpactCategories: FindingCategory[] = [
    'EXECUTION_TRIGGER',
    'EXFILTRATION',
    'DOWNLOADER',
    'PERSISTENCE',
  ];

  for (const category of highImpactCategories) {
    if (categories.has(category)) {
      const recs = CATEGORY_RECOMMENDATIONS[category];
      if (recs?.mitigation?.length > 0) {
        steps.add(recs.mitigation[0]);
      }
    }
  }

  // Default recommendations if no findings
  if (steps.size === 0) {
    steps.add('Repository appears relatively safe');
    steps.add('Standard code review recommended before production use');
    steps.add('Verify repository ownership and maintainer reputation');
  }

  // Limit to most relevant steps (max 8)
  return Array.from(steps).slice(0, 8);
}

/**
 * Get detailed recommendations for a specific finding
 */
export function getDetailedRecommendations(finding: Finding): {
  immediate: string[];
  review: string[];
  mitigation: string[];
} {
  const recs = CATEGORY_RECOMMENDATIONS[finding.category];
  if (!recs) {
    return {
      immediate: ['Review this finding manually'],
      review: ['Inspect the affected file'],
      mitigation: ['Remove or comment out suspicious code'],
    };
  }
  return recs;
}
