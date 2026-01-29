// Mobile Development Security Rules
// Covers: Android Gradle, iOS Podfile, React Native, Flutter

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

// ========== ANDROID GRADLE RISKS ==========

/**
 * Detect security risks in Android Gradle files
 */
export function detectAndroidGradleRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for Gradle files
  if (!/\.gradle(\.kts)?$/i.test(filePath) && !/settings\.gradle/i.test(filePath)) {
    return findings;
  }
  
  // Check for custom/untrusted repositories
  const repoPatterns = [
    { pattern: /maven\s*\{\s*url\s*[=\s]*['"]https?:\/\/(?!repo1?\.maven|google\.android|jcenter|mavenCentral|plugins\.gradle)[^'"]+/gi, type: 'custom Maven' },
    { pattern: /flatDir\s*\{/i, type: 'flatDir' },
  ];
  
  for (const { pattern, type } of repoPatterns) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        id: 'android-custom-repo',
        category: 'DEPENDENCY_RISK' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, match.index || 0, match[0].length),
          note: `Android project uses ${type} repository`,
        },
        remediation: 'Verify custom Maven repositories are trustworthy. Prefer official repos.',
      });
    }
  }
  
  // Custom Gradle plugins
  const pluginMatch = content.match(/classpath\s*['"][^'"]+:(?!com\.android|org\.jetbrains\.kotlin|com\.google)[^'"]+['"]/i);
  if (pluginMatch) {
    findings.push({
      id: 'android-custom-plugin',
      category: 'DEPENDENCY_RISK' as FindingCategory,
      severity: 'medium' as FindingSeverity,
      scoreDelta: 15,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, pluginMatch.index || 0, pluginMatch[0].length),
        note: 'Android project uses custom Gradle plugin',
      },
      remediation: 'Audit custom Gradle plugins. They execute during build.',
    });
  }
  
  // Disable SSL verification
  const sslMatch = content.match(/allowInsecureProtocol\s*[=\s]*true/i);
  if (sslMatch) {
    findings.push({
      id: 'android-insecure-protocol',
      category: 'DEPENDENCY_RISK' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 20,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, sslMatch.index || 0, sslMatch[0].length),
        note: 'Gradle allows insecure HTTP for dependencies',
      },
      remediation: 'Use HTTPS for all dependency repositories.',
    });
  }
  
  // Task with command execution
  const execMatch = content.match(/exec\s*\{[\s\S]*?commandLine|Runtime\.getRuntime\(\)\.exec/i);
  if (execMatch) {
    findings.push({
      id: 'android-gradle-exec',
      category: 'EXECUTION_TRIGGER' as FindingCategory,
      severity: 'high' as FindingSeverity,
      scoreDelta: 25,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, execMatch.index || 0, execMatch[0].length),
        note: 'Gradle build executes external commands',
      },
      remediation: 'Review command execution in Gradle. This runs during build.',
    });
  }
  
  return findings;
}

// ========== IOS PODFILE RISKS ==========

/**
 * Detect security risks in iOS Podfiles
 */
export function detectiOSPodfileRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for Podfile
  if (!/Podfile$/i.test(filePath) && !/\.podspec$/i.test(filePath)) {
    return findings;
  }
  
  // Git pods from untrusted sources
  const gitPodMatch = content.match(/pod\s+['"][^'"]+['"],\s*:git\s*=>\s*['"]([^'"]+)['"]/i);
  if (gitPodMatch) {
    const gitUrl = gitPodMatch[1];
    // Check if it's not from a well-known org
    if (!/github\.com\/(apple|google|facebook|microsoft|airbnb|realm)/i.test(gitUrl)) {
      findings.push({
        id: 'ios-git-pod',
        category: 'DEPENDENCY_RISK' as FindingCategory,
        severity: 'medium' as FindingSeverity,
        scoreDelta: 15,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, gitPodMatch.index || 0, gitPodMatch[0].length),
          note: `Pod from git: ${gitUrl}`,
        },
        remediation: 'Verify git-based pods. Prefer CocoaPods registry with version pinning.',
      });
    }
  }
  
  // Pods from path (local)
  const pathPodMatch = content.match(/pod\s+['"][^'"]+['"],\s*:path\s*=>\s*['"][^'"]+['"]/i);
  if (pathPodMatch) {
    findings.push({
      id: 'ios-local-pod',
      category: 'DEPENDENCY_RISK' as FindingCategory,
      severity: 'low' as FindingSeverity,
      scoreDelta: 5,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, pathPodMatch.index || 0, pathPodMatch[0].length),
        note: 'Pod loaded from local path',
      },
      remediation: 'Review local pod sources for unexpected changes.',
    });
  }
  
  // Script phases
  const scriptMatch = content.match(/script_phase\s*:name\s*=>/i);
  if (scriptMatch) {
    findings.push({
      id: 'ios-script-phase',
      category: 'EXECUTION_TRIGGER' as FindingCategory,
      severity: 'medium' as FindingSeverity,
      scoreDelta: 15,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, scriptMatch.index || 0, scriptMatch[0].length),
        note: 'Podfile defines script phase',
      },
      remediation: 'Review script phases. They execute during pod install.',
    });
  }
  
  return findings;
}

// ========== REACT NATIVE RISKS ==========

/**
 * Detect security risks in React Native projects
 */
export function detectReactNativeRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for React Native/Expo configs
  const isRNConfig = /app\.json$/i.test(filePath) || 
    /expo\.json$/i.test(filePath) ||
    /app\.config\.[jt]s$/i.test(filePath);
  
  if (!isRNConfig) {
    return findings;
  }
  
  // OTA update URLs
  const otaMatch = content.match(/["']?updates["']?\s*:\s*\{[^}]*url["']?\s*:\s*["']([^'"]+)/i);
  if (otaMatch) {
    findings.push({
      id: 'rn-ota-update',
      category: 'DEPENDENCY_RISK' as FindingCategory,
      severity: 'medium' as FindingSeverity,
      scoreDelta: 15,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, otaMatch.index || 0, otaMatch[0].length),
        note: `OTA update URL: ${otaMatch[1]}`,
      },
      remediation: 'Verify OTA update endpoints. Malicious updates can execute arbitrary code.',
    });
  }
  
  // Expo hooks
  const hooksMatch = content.match(/["']?hooks["']?\s*:\s*\{/i);
  if (hooksMatch) {
    findings.push({
      id: 'rn-expo-hooks',
      category: 'EXECUTION_TRIGGER' as FindingCategory,
      severity: 'medium' as FindingSeverity,
      scoreDelta: 10,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, hooksMatch.index || 0, hooksMatch[0].length),
        note: 'Expo config defines hooks',
      },
      remediation: 'Review Expo hooks. They execute during build processes.',
    });
  }
  
  // Deep linking schemes
  const schemeMatch = content.match(/["']?scheme["']?\s*:\s*["']([^'"]+)/i);
  if (schemeMatch) {
    // This is informational, not necessarily a risk
    // But worth noting for review
  }
  
  return findings;
}

// ========== FLUTTER RISKS ==========

/**
 * Detect security risks in Flutter projects
 */
export function detectFlutterRisks(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for Flutter pubspec
  if (!/pubspec\.ya?ml$/i.test(filePath)) {
    return findings;
  }
  
  // Git dependencies
  const gitDepMatch = content.match(/git:\s*\n\s*url:\s*['"]?([^'"\s]+)/i);
  if (gitDepMatch) {
    const gitUrl = gitDepMatch[1];
    if (!/github\.com\/(flutter|dart-lang|google|firebase)/i.test(gitUrl)) {
      findings.push({
        id: 'flutter-git-dep',
        category: 'DEPENDENCY_RISK' as FindingCategory,
        severity: 'medium' as FindingSeverity,
        scoreDelta: 15,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, gitDepMatch.index || 0, gitDepMatch[0].length),
          note: `Flutter dependency from git: ${gitUrl}`,
        },
        remediation: 'Verify git dependencies. Prefer pub.dev packages with version pinning.',
      });
    }
  }
  
  // Path dependencies
  const pathDepMatch = content.match(/path:\s*['"]?\.\.\/[^'"\s]+/i);
  if (pathDepMatch) {
    findings.push({
      id: 'flutter-path-dep',
      category: 'DEPENDENCY_RISK' as FindingCategory,
      severity: 'low' as FindingSeverity,
      scoreDelta: 5,
      file: filePath,
      evidence: {
        snippet: extractSnippet(content, pathDepMatch.index || 0, pathDepMatch[0].length),
        note: 'Flutter uses relative path dependency',
      },
      remediation: 'Review path dependencies for unexpected modifications.',
    });
  }
  
  // Hosted dependencies from non-pub.dev
  const hostedMatch = content.match(/hosted:\s*\n\s*name:.*\n\s*url:\s*['"]?([^'"\s]+)/i);
  if (hostedMatch) {
    const hostedUrl = hostedMatch[1];
    if (!/pub\.dev|pub\.dartlang\.org/i.test(hostedUrl)) {
      findings.push({
        id: 'flutter-custom-hosted',
        category: 'DEPENDENCY_RISK' as FindingCategory,
        severity: 'high' as FindingSeverity,
        scoreDelta: 25,
        file: filePath,
        evidence: {
          snippet: extractSnippet(content, hostedMatch.index || 0, hostedMatch[0].length),
          note: `Flutter uses custom package host: ${hostedUrl}`,
        },
        remediation: 'Verify custom package hosts are trustworthy.',
      });
    }
  }
  
  return findings;
}

// ========== MAIN DETECTION FUNCTION ==========

/**
 * Run all mobile development security rules on a file
 */
export function detectMobileDevRisks(filePath: string, content: string): Finding[] {
  return [
    ...detectAndroidGradleRisks(filePath, content),
    ...detectiOSPodfileRisks(filePath, content),
    ...detectReactNativeRisks(filePath, content),
    ...detectFlutterRisks(filePath, content),
  ];
}
