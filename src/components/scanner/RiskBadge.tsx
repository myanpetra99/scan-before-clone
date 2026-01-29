import { cn } from "@/lib/utils";
import type { RiskLabel } from "@/types/scanner";

interface RiskBadgeProps {
  label: RiskLabel;
  score?: number;
  size?: "sm" | "md" | "lg";
  showScore?: boolean;
}

export function RiskBadge({ label, score, size = "md", showScore = true }: RiskBadgeProps) {
  const sizeClasses = {
    sm: "text-xs px-2 py-1",
    md: "text-sm px-3 py-1.5",
    lg: "text-lg px-5 py-2.5",
  };

  const riskClasses: Record<RiskLabel, string> = {
    LOW: "bg-risk-low/20 text-risk-low border-3 border-risk-low shadow-comic",
    MEDIUM: "bg-risk-medium/20 text-risk-medium border-3 border-risk-medium shadow-comic",
    HIGH: "bg-risk-high/20 text-risk-high border-3 border-risk-high shadow-comic animate-shake",
    CRITICAL: "bg-red-600/30 text-red-500 border-3 border-red-500 shadow-comic animate-shake",
  };

  const rotations: Record<RiskLabel, string> = {
    LOW: "-rotate-1",
    MEDIUM: "rotate-0.5",
    HIGH: "-rotate-1",
    CRITICAL: "rotate-1",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 font-display tracking-wide uppercase transform",
        sizeClasses[size],
        riskClasses[label],
        rotations[label]
      )}
    >
      <span>{label}</span>
      {showScore && score !== undefined && (
        <span className="font-mono text-sm opacity-80">({score})</span>
      )}
    </span>
  );
}
