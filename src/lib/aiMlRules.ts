// AI/ML Pipeline Security Rules
// Covers: Pickle files, Hugging Face, Jupyter notebooks, MLflow

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

// ========== PICKLE FILE RISKS ==========

/**
 * Detect risky usage of Pickle (arbitrary code execution)
 */
export function detectPickleRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for Python files with pickle usage
  if (!/\.py$/i.test(filePath)) {
    return findings;
  }
  
  // Dangerous pickle patterns
  const picklePatterns = [
    { pattern: /pickle\.loads?\s*\(/i, method: 'pickle.load/loads' },
    { pattern: /cPickle\.loads?\s*\(/i, method: 'cPickle.load' },
    { pattern: /dill\.loads?\s*\(/i, method: 'dill.load' },
    { pattern: /joblib\.load\s*\(/i, method: 'joblib.load' },
    { pattern: /torch\.load\s*\(/i, method: 'torch.load' },
  ];
  
  for (const { pattern, method } of picklePatterns) {
    const match = content.match(pattern);
    if (match) {
      // Check if loading from untrusted source
      const context = content.substring(
        Math.max(0, (match.index || 0) - 200),
        (match.index || 0) + 200
      );
      
      const untrustedSource = 
        /url|http|request|download|fetch|s3|gcs|blob/i.test(context) ||
        /input|argv|environ|user|param/i.test(context);
      
      findings.push({
        id: 'aiml-pickle-load',
        category: 'AI_ML_RISK' as FindingCategory,
        severity: untrustedSource ? 'critical' : 'high' as FindingSeverity,
        scoreDelta: untrustedSource ? 40 : 25,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: untrustedSource
            ? `${method} from potentially untrusted source (arbitrary code execution risk)`
            : `${method} can execute arbitrary code during deserialization`,
        },
        remediation: 'Use safer alternatives like safetensors, JSON, or verify model sources. Never unpickle untrusted data.',
      });
    }
  }
  
  // Check for pickle files in model directories
  if (/model|weights|checkpoint/i.test(filePath) && /\.pkl$|\.pickle$/i.test(filePath)) {
    findings.push({
      id: 'aiml-pickle-file',
      category: 'AI_ML_RISK' as FindingCategory,
      severity: 'medium' as FindingSeverity,
      scoreDelta: 15,
      file: filePath,
      evidence: {
        snippet: `Pickle file: ${filePath}`,
        note: 'Pickle model file can execute arbitrary code when loaded',
      },
      remediation: 'Prefer safetensors format. Verify the source of pickle files before loading.',
    });
  }
  
  return findings;
}

// ========== HUGGING FACE RISKS ==========

/**
 * Detect risky patterns in Hugging Face model usage
 */
export function detectHuggingFaceRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for Python/config files
  if (!/\.(py|json|ya?ml)$/i.test(filePath)) {
    return findings;
  }
  
  // Trust remote code
  const trustRemoteMatch = content.match(/trust_remote_code\s*[=:]\s*True/i);
  if (trustRemoteMatch) {
    findings.push({
      id: 'aiml-hf-trust-remote',
      category: 'AI_ML_RISK' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 30,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, trustRemoteMatch.index || 0, trustRemoteMatch[0].length),
        note: 'trust_remote_code=True allows execution of arbitrary code from model repo',
      },
      remediation: 'Only use trust_remote_code=True with models you have audited.',
    });
  }
  
  // Loading from non-official sources
  const unofficialMatch = content.match(/(?:from_pretrained|load)\s*\(\s*['"]([^'"]+\/[^'"]+)['"]/i);
  if (unofficialMatch) {
    const modelPath = unofficialMatch[1];
    // Check if it's not from a known org
    const knownOrgs = ['huggingface', 'meta-llama', 'facebook', 'google', 'openai', 'microsoft', 'stability-ai'];
    const isUnknown = !knownOrgs.some(org => modelPath.toLowerCase().startsWith(org + '/'));
    
    if (isUnknown && !modelPath.startsWith('./') && !modelPath.startsWith('/')) {
      findings.push({
        id: 'aiml-hf-unknown-model',
        category: 'AI_ML_RISK' as FindingCategory,
        severity: 'medium' as FindingSeverity,
        scoreDelta: 15,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, unofficialMatch.index || 0, unofficialMatch[0].length),
          note: `Loading model from unverified source: ${modelPath}`,
        },
        remediation: 'Verify model sources. Check the Hugging Face model page for security advisories.',
      });
    }
  }
  
  return findings;
}

// ========== JUPYTER NOTEBOOK RISKS ==========

/**
 * Detect risky patterns in Jupyter notebooks
 */
export function detectJupyterRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for notebook files
  if (!/\.ipynb$/i.test(filePath)) {
    return findings;
  }
  
  try {
    const notebook = JSON.parse(content);
    
    // Check for suspicious cell outputs (may contain hidden content)
    let hasHiddenCells = false;
    let hasSuspiciousOutputs = false;
    
    for (const cell of notebook.cells || []) {
      // Check for hidden cells via metadata
      if (cell.metadata?.hidden === true || cell.metadata?.jupyter?.source_hidden === true) {
        hasHiddenCells = true;
      }
      
      // Check cell source for dangerous patterns
      const source = Array.isArray(cell.source) ? cell.source.join('') : cell.source || '';
      
      // Shell commands
      if (/^!(?:curl|wget|bash|sh)\s/im.test(source) || /os\.system|subprocess/i.test(source)) {
        findings.push({
          id: 'aiml-jupyter-shell',
          category: 'AI_ML_RISK' as FindingCategory,
          severity: 'high' as FindingSeverity,
          scoreDelta: 25,
          file: filePath,
          evidence: {
            snippet: source.substring(0, 200),
            note: 'Jupyter notebook executes shell commands',
          },
          remediation: 'Review shell commands in notebooks. They execute when cells are run.',
        });
      }
      
      // Network requests
      if (/requests\.get|urllib|fetch|download/i.test(source)) {
        // Check outputs for this cell
        for (const output of cell.outputs || []) {
          if (output.output_type === 'execute_result' && JSON.stringify(output).length > 10000) {
            hasSuspiciousOutputs = true;
          }
        }
      }
    }
    
    if (hasHiddenCells) {
      findings.push({
        id: 'aiml-jupyter-hidden',
        category: 'AI_ML_RISK' as FindingCategory,
        severity: 'medium' as FindingSeverity,
        scoreDelta: 15,
        file: filePath,
        evidence: {
          snippet: 'Notebook contains hidden cells',
          note: 'Hidden cells can contain malicious code that runs without being visible',
        },
        remediation: 'Unhide all cells before running. Check View → Expand Hidden Cells.',
      });
    }
    
    if (hasSuspiciousOutputs) {
      findings.push({
        id: 'aiml-jupyter-large-output',
        category: 'AI_ML_RISK' as FindingCategory,
        severity: 'low' as FindingSeverity,
        scoreDelta: 5,
        file: filePath,
        evidence: {
          snippet: 'Notebook has large embedded outputs',
          note: 'Large outputs may hide obfuscated code or data',
        },
        remediation: 'Clear all outputs before sharing notebooks.',
      });
    }
    
  } catch {
    // Invalid notebook JSON
  }
  
  return findings;
}

// ========== MLFLOW RISKS ==========

/**
 * Detect risky patterns in MLflow configs
 */
export function detectMLflowRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for MLflow config files
  const isMLflow = /mlflow/i.test(filePath) || 
    /MLmodel$/i.test(filePath) ||
    /conda\.ya?ml$/i.test(filePath);
  
  if (!isMLflow) {
    return findings;
  }
  
  // Custom Python code in MLmodel
  if (/MLmodel$/i.test(filePath)) {
    const loaderMatch = content.match(/python_function:\s*[^\n]*loader_module/i);
    if (loaderMatch) {
      findings.push({
        id: 'aiml-mlflow-loader',
        category: 'AI_ML_RISK' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, loaderMatch.index || 0, loaderMatch[0].length),
          note: 'MLflow model uses custom Python loader (arbitrary code execution)',
        },
        remediation: 'Review custom loader modules. They execute when loading the model.',
      });
    }
  }
  
  // Remote artifact stores
  const remoteMatch = content.match(/artifact_uri:\s*['"]?(s3|gs|wasb|hdfs|http)/i);
  if (remoteMatch) {
    findings.push({
      id: 'aiml-mlflow-remote-artifacts',
      category: 'AI_ML_RISK' as FindingCategory,
      severity: 'low' as FindingSeverity,
      scoreDelta: 5,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, remoteMatch.index || 0, remoteMatch[0].length),
        note: 'MLflow loads artifacts from remote storage',
      },
      remediation: 'Verify remote artifact sources are trusted before loading models.',
    });
  }
  
  return findings;
}

// ========== MAIN DETECTION FUNCTION ==========

/**
 * Run all AI/ML security rules on a file
 */
export function detectAIMLRisks(filePath: string, content: string): Finding[] {
  return [
    ...detectPickleRisks(filePath, content),
    ...detectHuggingFaceRisks(filePath, content),
    ...detectJupyterRisks(filePath, content),
    ...detectMLflowRisks(filePath, content),
  ];
}
