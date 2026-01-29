import { useState } from "react";
import { RiskBadge } from "./RiskBadge";
import { FindingCard } from "./FindingCard";
import { 
  Shield, 
  ExternalLink, 
  GitBranch, 
  FileCode, 
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronUp,
  BarChart3,
  Clock,
  Ban,
  AlertOctagon,
  ThumbsUp,
  Info
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { Report, FindingCategory } from "@/types/scanner";
import { CATEGORY_INFO } from "@/types/scanner";

interface ReportViewProps {
  report: Report;
  onNewScan: () => void;
}

export function ReportView({ report, onNewScan }: ReportViewProps) {
  const [expandedCategories, setExpandedCategories] = useState<Set<FindingCategory>>(
    new Set(["EXECUTION_TRIGGER", "EXFILTRATION"])
  );

  // Group findings by category
  const findingsByCategory = report.findings.reduce((acc, finding) => {
    if (!acc[finding.category]) {
      acc[finding.category] = [];
    }
    acc[finding.category].push(finding);
    return acc;
  }, {} as Record<FindingCategory, typeof report.findings>);

  const toggleCategory = (category: FindingCategory) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(category)) {
        next.delete(category);
      } else {
        next.add(category);
      }
      return next;
    });
  };

  const scoreGradient = report.label === "CRITICAL"
    ? "from-red-600 to-red-500"
    : report.label === "HIGH" 
    ? "from-risk-high to-risk-high/50" 
    : report.label === "MEDIUM"
    ? "from-risk-medium to-risk-medium/50"
    : "from-risk-low to-risk-low/50";

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6">
      
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="p-6 pb-4">
          <div className="flex items-start justify-between mb-4">
            <div>
              <h1 className="text-2xl font-bold flex items-center gap-3">
                <Shield className="w-7 h-7 text-primary" />
                Security Report
              </h1>
              <a
                href={report.repo.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-primary transition-colors flex items-center gap-2 mt-1 font-mono"
              >
                {report.repo.owner}/{report.repo.name}
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
            <Button variant="outline" size="sm" onClick={onNewScan}>
              New Scan
            </Button>
          </div>

          
          <div className="flex flex-wrap gap-4 text-sm text-muted-foreground">
            <div className="flex items-center gap-2">
              <GitBranch className="w-4 h-4" />
              <span className="font-mono">{report.repo.defaultBranch}</span>
            </div>
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4" />
              <span>{report.stats.filesScanned} files scanned</span>
            </div>
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4" />
              <span>{new Date(report.generatedAt).toLocaleString()}</span>
            </div>
          </div>
        </div>

        
        <div className={`bg-gradient-to-r ${scoreGradient} p-6`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <div className="text-center">
                <div className="text-5xl font-bold text-white mb-1">{report.score}</div>
                <div className="text-sm text-white/80">Risk Score</div>
              </div>
              <RiskBadge label={report.label} size="lg" showScore={false} />
            </div>
            <div className="text-right">
              <div className="text-sm text-white/80">Rule Version</div>
              <div className="font-mono text-white/80">{report.ruleVersion}</div>
              <Badge variant="secondary" className="mt-2">
                Pattern Analysis
              </Badge>
            </div>
          </div>

          
          {report.verdict && (
            <div className={`mt-4 p-3 rounded-lg flex items-center gap-3 ${
              report.verdict === "GO" 
                ? "bg-white/20" 
                : report.verdict === "NO-GO"
                ? "bg-black/30"
                : "bg-black/20"
            }`}>
              {report.verdict === "GO" ? (
                <ThumbsUp className="w-5 h-5 text-white" />
              ) : report.verdict === "NO-GO" ? (
                <Ban className="w-5 h-5 text-white" />
              ) : (
                <AlertOctagon className="w-5 h-5 text-white" />
              )}
              <div>
                <span className="font-bold text-white">{report.verdict}</span>
                {report.verdictReason && (
                  <p className="text-sm text-white/80">{report.verdictReason}</p>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      
      {report.topReasons.length > 0 && (
        <div className="bg-card border border-border rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-risk-medium" />
            Top Concerns
          </h2>
          <div className="space-y-3">
            {report.topReasons.map((reason, index) => (
              <div
                key={index}
                className="flex items-center gap-3 p-3 bg-secondary/50 rounded-lg"
              >
                <span className={`text-sm font-medium ${
                  reason.severity === "critical"
                    ? "text-red-500"
                    : reason.severity === "high" 
                    ? "text-risk-high" 
                    : reason.severity === "medium"
                    ? "text-risk-medium"
                    : "text-risk-low"
                }`}>
                  {reason.severity.toUpperCase()}
                </span>
                <span className="text-foreground">{reason.title}</span>
                {reason.file && (
                  <span className="ml-auto text-xs text-muted-foreground font-mono truncate max-w-[200px]">
                    {reason.file}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="p-6 pb-4 border-b border-border">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-primary" />
            Detailed Findings
            <span className="ml-2 text-sm font-normal text-muted-foreground">
              ({report.findings.length} issues found)
            </span>
          </h2>
        </div>

        <div className="divide-y divide-border">
          {(Object.keys(CATEGORY_INFO) as FindingCategory[]).map((category) => {
            const findings = findingsByCategory[category] || [];
            if (findings.length === 0) return null;

            const categoryInfo = CATEGORY_INFO[category];
            const isExpanded = expandedCategories.has(category);

            return (
              <div key={category}>
                <button
                  onClick={() => toggleCategory(category)}
                  className="w-full p-4 flex items-center gap-4 hover:bg-accent/30 transition-colors"
                >
                  <span className="text-2xl">{categoryInfo.icon}</span>
                  <div className="flex-1 text-left">
                    <h3 className="font-medium">{categoryInfo.label}</h3>
                    <p className="text-sm text-muted-foreground">
                      {categoryInfo.description}
                    </p>
                  </div>
                  <span className="text-sm font-medium text-muted-foreground">
                    {findings.length} {findings.length === 1 ? "issue" : "issues"}
                  </span>
                  {isExpanded ? (
                    <ChevronUp className="w-5 h-5 text-muted-foreground" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-muted-foreground" />
                  )}
                </button>

                {isExpanded && (
                  <div className="px-4 pb-4 space-y-3">
                    {findings.map((finding, index) => (
                      <FindingCard key={`${finding.id}-${index}`} finding={finding} />
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {report.findings.length === 0 && (
          <div className="p-12 text-center">
            <CheckCircle className="w-12 h-12 text-risk-low mx-auto mb-4" />
            <h3 className="text-lg font-semibold mb-2">No Issues Found</h3>
            <p className="text-muted-foreground">
              This repository passed all security checks
            </p>
          </div>
        )}
      </div>

      
      <div className="bg-card border border-primary/30 rounded-xl p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <CheckCircle className="w-5 h-5 text-primary" />
          Safe Next Steps
        </h2>
        <ul className="space-y-2">
          {report.safeNextSteps.map((step, index) => (
            <li key={index} className="flex items-start gap-3">
              <span className="text-primary mt-1">✓</span>
              <span className="text-muted-foreground">{step}</span>
            </li>
          ))}
        </ul>
      </div>

      
      <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-5">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-semibold text-amber-500 mb-1">⚠️ Important Disclaimer</h3>
            <p className="text-sm text-muted-foreground leading-relaxed">
              This analysis is based on <strong>pattern matching</strong> and may produce <strong>false positives or miss threats</strong>. 
              Results are not 100% accurate. <strong className="text-foreground">Developers are strongly advised to manually review 
              all flagged items</strong> and perform additional security audits before trusting any repository.
            </p>
          </div>
        </div>
      </div>

      
      <div className="text-center text-sm text-muted-foreground">
        <p>
          Scanned {report.stats.filesScanned} files ({(report.stats.bytesFetched / 1024).toFixed(1)} KB)
          {report.stats.truncated && " • Repository tree was truncated"}
        </p>
        <p className="mt-1">
          Report generated at {new Date(report.generatedAt).toLocaleString()}
        </p>
      </div>
    </div>
  );
}
