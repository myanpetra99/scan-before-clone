// Scanner Types - Shared across the application

export type ScanStatus = 'queued' | 'running' | 'done' | 'error';
export type ScanMode = 'quick' | 'deep';
export type RiskLabel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type FindingSeverity = 'low' | 'medium' | 'high' | 'critical';
export type ConfidenceLevel = 'low' | 'medium' | 'high';

export type FindingCategory =
  | 'EXECUTION_TRIGGER'
  | 'EXFILTRATION'
  | 'OBFUSCATION'
  | 'SOCIAL_ENGINEERING'
  | 'DEPENDENCY_RISK'
  | 'BINARY_SUSPICION'
  | 'CI_CD_RISK'
  | 'SECRETS'
  | 'PERSISTENCE'
  | 'DOWNLOADER'
  | 'BROWSER_EXTENSION'
  | 'CONTAINER_RISK'
  | 'SERVERLESS_RISK'
  | 'AI_ML_RISK';

export interface RepoInfo {
  owner: string;
  name: string;
  url: string;
  defaultBranch: string;
  commitSha: string;
}

export interface Evidence {
  path: string;
  lines?: string;
  snippet: string;
}

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  confidence?: ConfidenceLevel;
  scoreDelta: number;
  file: string;
  lineRange?: [number, number];
  evidence: {
    snippet: string;
    note: string;
  };
  remediation: string;
  whyItMatters?: string;
  whatToCheckNext?: string[];
  // AI-enhanced fields
  execMoment?: 'OPEN' | 'INSTALL' | 'BUILD' | 'RUN' | 'CI';
  chain?: string;
  aiNote?: string;
  escalatedSeverity?: FindingSeverity | null;
}

export interface SecretFound {
  path: string;
  lines?: string;
  type: 'APIKey' | 'PrivateKey' | 'Token' | 'Env' | 'Other';
  redactedExample: string;
  severity: FindingSeverity;
}

export interface SupplyChainRisk {
  path: string;
  issue: string;
  severity: FindingSeverity;
  recommendation: string;
}

export interface CICDRisk {
  path: string;
  issue: string;
  severity: FindingSeverity;
  recommendation: string;
}

export interface TopReason {
  title: string;
  severity: FindingSeverity;
  file?: string;
}

export interface ScanStats {
  filesScanned: number;
  bytesFetched: number;
  truncated: boolean;
  rulesExecuted?: number;
  timeMs?: number;
}

export interface Report {
  reportId: string;
  repo: RepoInfo;
  generatedAt: string;
  ruleVersion: string;
  score: number;
  label: RiskLabel;
  overallSummary?: string;
  topReasons: TopReason[];
  findings: Finding[];
  secretsFound?: SecretFound[];
  supplyChainRisks?: SupplyChainRisk[];
  cicdRisks?: CICDRisk[];
  stats: ScanStats;
  safeNextSteps: string[];
  notesOnFalsePositives?: string[];
  limitations?: string[];
  // AI-enhanced fields
  verdict?: 'GO' | 'CAUTION' | 'NO-GO';
  verdictReason?: string;
  aiAnalyzed?: boolean;
  missedPatterns?: string[];
  falsePositiveHints?: string[];
  safetyChecklist?: string[];
}

export interface ScanActivity {
  stage: 'metadata' | 'tree' | 'fetch' | 'rules' | 'summarize';
  currentItem?: string;
  processedCount?: number;
  totalCount?: number;
}

export interface Scan {
  id: string;
  repoUrl: string;
  repoOwner?: string;
  repoName?: string;
  ref?: string;
  mode: ScanMode;
  status: ScanStatus;
  progress: number;
  error?: string;
  reportId?: string;
  createdAt: string;
  updatedAt: string;
  activity?: ScanActivity;
}

// Category display info
export const CATEGORY_INFO: Record<FindingCategory, { label: string; icon: string; description: string }> = {
  EXECUTION_TRIGGER: {
    label: 'Execution Trigger',
    icon: '⚡',
    description: 'Code that executes during package installation, build, or folder open',
  },
  EXFILTRATION: {
    label: 'Data Exfiltration',
    icon: '📤',
    description: 'Potential data stealing or credential harvesting',
  },
  OBFUSCATION: {
    label: 'Obfuscation',
    icon: '🔒',
    description: 'Encoded or heavily obfuscated code patterns',
  },
  SOCIAL_ENGINEERING: {
    label: 'Social Engineering',
    icon: '🎭',
    description: 'Misleading instructions or deceptive content',
  },
  DEPENDENCY_RISK: {
    label: 'Dependency Risk',
    icon: '📦',
    description: 'Risky or vulnerable dependencies',
  },
  BINARY_SUSPICION: {
    label: 'Binary Suspicion',
    icon: '💾',
    description: 'Suspicious binary files or executables',
  },
  CI_CD_RISK: {
    label: 'CI/CD Risk',
    icon: '🔧',
    description: 'Risky patterns in CI/CD configuration',
  },
  SECRETS: {
    label: 'Exposed Secrets',
    icon: '🔑',
    description: 'API keys, tokens, or credentials in code',
  },
  PERSISTENCE: {
    label: 'Persistence',
    icon: '🔄',
    description: 'Attempts to establish persistent access',
  },
  DOWNLOADER: {
    label: 'Downloader',
    icon: '⬇️',
    description: 'Downloads and executes remote payloads',
  },
  BROWSER_EXTENSION: {
    label: 'Browser Extension',
    icon: '🌐',
    description: 'Malicious browser extension patterns',
  },
  CONTAINER_RISK: {
    label: 'Container Risk',
    icon: '🐳',
    description: 'Kubernetes/Docker privilege escalation',
  },
  SERVERLESS_RISK: {
    label: 'Serverless Risk',
    icon: '☁️',
    description: 'Lambda/Edge function security issues',
  },
  AI_ML_RISK: {
    label: 'AI/ML Risk',
    icon: '🤖',
    description: 'Pickle deserialization and model injection',
  },
};

// Safe next steps recommendations
export const DEFAULT_SAFE_NEXT_STEPS = [
  'Run the code in an isolated container or VM, never on your host machine',
  'Review all package.json scripts before running npm install',
  'Check .vscode/tasks.json for auto-run tasks before opening in VS Code',
  'Inspect any encoded strings or obfuscated code blocks',
  'Verify the repository owner and check their reputation',
  'Look for recent security issues or CVEs in dependencies',
  'Scan for hardcoded secrets and credentials',
  'Review GitHub Actions workflows for suspicious commands',
];

// Severity colors for UI
export const SEVERITY_COLORS: Record<FindingSeverity, string> = {
  critical: 'text-red-500',
  high: 'text-risk-high',
  medium: 'text-risk-medium',
  low: 'text-risk-low',
};
