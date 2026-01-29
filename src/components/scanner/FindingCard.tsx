import { useState } from "react";
import { ChevronDown, ChevronUp, FileCode, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Finding } from "@/types/scanner";
import { CATEGORY_INFO } from "@/types/scanner";

interface FindingCardProps {
  finding: Finding;
}

export function FindingCard({ finding }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);
  const categoryInfo = CATEGORY_INFO[finding.category];

  const severityClasses = {
    low: "border-l-risk-low",
    medium: "border-l-risk-medium",
    high: "border-l-risk-high",
  };

  const severityBadgeClasses = {
    low: "risk-badge-low",
    medium: "risk-badge-medium",
    high: "risk-badge-high",
  };

  return (
    <div
      className={cn(
        "bg-card border-3 border-border border-l-[6px] overflow-hidden transition-all shadow-comic hover:shadow-comic-lg",
        severityClasses[finding.severity]
      )}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-4 flex items-start gap-4 text-left hover:bg-accent/30 transition-colors"
      >
        <div className="flex-shrink-0 text-3xl">{categoryInfo.icon}</div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2">
            <span className={cn("text-xs px-2 py-1 font-bold", severityBadgeClasses[finding.severity])}>
              {finding.severity.toUpperCase()}
            </span>
            <span className="text-xs text-primary font-bold font-display">
              +{finding.scoreDelta} pts
            </span>
          </div>
          
          <h4 className="font-bold text-foreground mb-1">
            {finding.evidence.note}
          </h4>
          
          <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono bg-muted px-2 py-1 border border-border inline-flex">
            <FileCode className="w-3 h-3" />
            <span className="truncate">{finding.file}</span>
            {finding.lineRange && (
              <span className="text-primary">:{finding.lineRange[0]}-{finding.lineRange[1]}</span>
            )}
          </div>
        </div>

        <div className="flex-shrink-0 font-display text-2xl text-muted-foreground">
          {expanded ? "▲" : "▼"}
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-4 border-t-3 border-border pt-4 animate-fade-in-up">
          
          <div>
            <h5 className="text-xs font-display tracking-wide text-primary mb-2">
              📋 EVIDENCE
            </h5>
            <pre className="bg-terminal border-3 border-terminal-text/30 p-3 text-xs font-mono overflow-x-auto shadow-comic">
              <code className="text-terminal-text whitespace-pre-wrap break-all">
                {finding.evidence.snippet}
              </code>
            </pre>
          </div>

          
          <div>
            <h5 className="text-xs font-display tracking-wide text-secondary mb-2">
              🛠️ REMEDIATION
            </h5>
            <div className="flex items-start gap-3 p-3 bg-secondary/10 border-3 border-secondary shadow-comic">
              <AlertTriangle className="w-5 h-5 text-secondary flex-shrink-0 mt-0.5" />
              <p className="text-sm text-foreground font-medium">{finding.remediation}</p>
            </div>
          </div>

          
          <div className="text-xs text-muted-foreground p-2 bg-muted border-2 border-border font-bold">
            <span className="text-primary">{categoryInfo.label}</span>
            <span className="mx-2">•</span>
            <span>{categoryInfo.description}</span>
          </div>
        </div>
      )}
    </div>
  );
}
