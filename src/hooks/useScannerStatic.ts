import { useState, useCallback } from "react";
import { parseGitHubUrl, fetchRepoForScan } from "@/lib/github";
import { runRules, calculateScore, getTopReasons, RULE_VERSION } from "@/lib/rules";
import { generateDynamicSafetySteps } from "@/lib/safetyRecommendations";
import { getStoredGitHubToken } from "@/hooks/useGitHubToken";
import type { Scan, Report, ScanMode, Finding, ScanActivity } from "@/types/scanner";

/**
 * Static-only scanner hook - NO backend dependencies!
 * Perfect for static hosting.
 * 
 * Features:
 * - API file fetching (public repos)
 * - 20+ security rule analysis
 * - Risk scoring & verdicts
 * - Dynamic safety recommendations
 */

// Compound escalation logic (moved from aiAnalysis.ts)
function applyCompoundEscalation(findings: Finding[]): Finding[] {
  const hasExfil = findings.some(f => f.category === 'EXFILTRATION');
  const hasExec = findings.some(f => f.category === 'EXECUTION_TRIGGER');
  const hasObfuscation = findings.some(f => f.category === 'OBFUSCATION');
  
  // If we have exfiltration + execution trigger, escalate both
  if (hasExfil && hasExec) {
    return findings.map(f => {
      if ((f.category === 'EXFILTRATION' || f.category === 'EXECUTION_TRIGGER') && f.severity !== 'critical') {
        return { ...f, escalatedSeverity: 'high' as const, severity: 'high' as const };
      }
      return f;
    });
  }
  
  // If obfuscation + any dangerous pattern, escalate obfuscation
  if (hasObfuscation && (hasExfil || hasExec)) {
    return findings.map(f => {
      if (f.category === 'OBFUSCATION' && f.severity === 'medium') {
        return { ...f, escalatedSeverity: 'high' as const, severity: 'high' as const };
      }
      return f;
    });
  }
  
  return findings;
}

interface UseScannerResult {
  scan: Scan | null;
  report: Report | null;
  isLoading: boolean;
  error: string | null;
  startScan: (repoUrl: string, mode?: ScanMode) => Promise<void>;
  reset: () => void;
}

export function useScannerStatic(): UseScannerResult {
  const [scan, setScan] = useState<Scan | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const updateActivity = useCallback((activity: ScanActivity) => {
    setScan((prev) => prev ? { ...prev, activity } : null);
  }, []);

  const startScan = useCallback(async (repoUrl: string, mode: ScanMode = "quick") => {
    setIsLoading(true);
    setError(null);
    setReport(null);

    const parsed = parseGitHubUrl(repoUrl);
    if (!parsed) {
      setError("Invalid GitHub URL");
      setIsLoading(false);
      return;
    }

    // Create local scan state (no database)
    const scanId = crypto.randomUUID();
    const now = new Date().toISOString();
    
    setScan({
      id: scanId,
      repoUrl,
      repoOwner: parsed.owner,
      repoName: parsed.name,
      mode,
      status: "queued",
      progress: 0,
      createdAt: now,
      updatedAt: now,
    });

    try {
      // Update to running - metadata stage
      setScan(prev => prev ? { 
        ...prev, 
        progress: 10, 
        status: "running",
        activity: { stage: 'metadata', currentItem: `${parsed.owner}/${parsed.name}` }
      } : null);

      // Fetch repo data from GitHub API - tree stage
      setScan(prev => prev ? { 
        ...prev, 
        progress: 20,
        activity: { stage: 'tree', currentItem: 'Loading file tree...' }
      } : null);
      
      const token = getStoredGitHubToken();
      const { repoInfo, scanData: fetchedData } = await fetchRepoForScan(
        parsed.owner,
        parsed.name,
        parsed.ref,
        token ?? undefined
      );

      const totalFiles = fetchedData.files.length;
      
      // Fetch stage
      setScan(prev => prev ? { 
        ...prev, 
        progress: 40,
        activity: { 
          stage: 'fetch', 
          currentItem: `${totalFiles} files to analyze`,
          processedCount: 0,
          totalCount: totalFiles
        }
      } : null);

      // Rules stage - run rules on all files
      let allFindings: Finding[] = [];
      
      setScan(prev => prev ? { 
        ...prev, 
        progress: 60,
        activity: { 
          stage: 'rules', 
          currentItem: 'Starting analysis...',
          processedCount: 0,
          totalCount: totalFiles
        }
      } : null);
      
      for (let i = 0; i < fetchedData.files.length; i++) {
        const file = fetchedData.files[i];
        
        // Update activity to show current file
        updateActivity({ 
          stage: 'rules', 
          currentItem: file.path,
          processedCount: i + 1,
          totalCount: totalFiles
        });
        
        const fileFindings = runRules(file.path, file.content);
        allFindings.push(...fileFindings);
      }

      // Apply compound signal escalation
      allFindings = applyCompoundEscalation(allFindings);

      // Summarize stage
      setScan(prev => prev ? { 
        ...prev, 
        progress: 85,
        activity: { stage: 'summarize', currentItem: 'Generating security report...' }
      } : null);

      // Create verdict from rules (no AI)
      const verdict = allFindings.some(f => f.severity === 'critical') ? 'NO-GO' as const : 
                     allFindings.some(f => f.severity === 'high') ? 'CAUTION' as const :
                     allFindings.length > 3 ? 'CAUTION' as const : 'GO' as const;

      // Calculate score and generate report
      const { score, label } = calculateScore(allFindings);
      const topReasons = getTopReasons(allFindings);
      
      // Generate dynamic safe next steps based on actual findings
      const dynamicSafetySteps = generateDynamicSafetySteps(allFindings, verdict);

      const reportData: Report = {
        reportId: crypto.randomUUID(),
        repo: {
          owner: parsed.owner,
          name: parsed.name,
          url: repoInfo.url,
          defaultBranch: repoInfo.defaultBranch,
          commitSha: repoInfo.commitSha,
        },
        generatedAt: new Date().toISOString(),
        ruleVersion: RULE_VERSION,
        score,
        label,
        overallSummary: `Detected ${allFindings.length} potential security issue(s) using static rules`,
        topReasons,
        findings: allFindings,
        stats: fetchedData.stats,
        safeNextSteps: dynamicSafetySteps,
        verdict,
        verdictReason: 'Based on pattern analysis',
        aiAnalyzed: false,
        missedPatterns: [],
        falsePositiveHints: [],
        safetyChecklist: dynamicSafetySteps,
      };

      setScan(prev => prev ? { ...prev, progress: 100, status: "done" } : null);
      setReport(reportData);

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Scan failed";
      setError(errorMessage);
      setScan(prev => prev ? { ...prev, status: "error", error: errorMessage } : null);
    } finally {
      setIsLoading(false);
    }
  }, [updateActivity]);

  const reset = useCallback(() => {
    setScan(null);
    setReport(null);
    setError(null);
    setIsLoading(false);
  }, []);

  return {
    scan,
    report,
    isLoading,
    error,
    startScan,
    reset,
  };
}
