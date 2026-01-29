import { useState, useEffect } from "react";
import { Loader2, CheckCircle, XCircle, Clock, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { RateLimitWarning } from "./RateLimitWarning";
import type { ScanStatus, ScanActivity } from "@/types/scanner";

interface ScanProgressProps {
  status: ScanStatus;
  progress: number;
  repoName?: string;
  error?: string | null;
  onRetry?: () => void;
  activity?: ScanActivity;
}

// Check if error is a rate limit error
function isRateLimitError(error: string | null | undefined): boolean {
  if (!error) return false;
  return error.toLowerCase().includes('rate limit') || 
         error.includes('403') ||
         error.includes('429');
}

export function ScanProgress({ status, progress, repoName, error, onRetry, activity }: ScanProgressProps) {
  // If rate limited, show special component
  if (status === "error" && isRateLimitError(error)) {
    return <RateLimitWarning onRetry={onRetry} />;
  }

  const statusConfig = {
    queued: {
      icon: Clock,
      label: "Queued",
      color: "text-muted-foreground",
    },
    running: {
      icon: Loader2,
      label: "Scanning",
      color: "text-primary",
    },
    done: {
      icon: CheckCircle,
      label: "Complete",
      color: "text-risk-low",
    },
    error: {
      icon: XCircle,
      label: "Error",
      color: "text-destructive",
    },
  };

  const config = statusConfig[status];
  const Icon = config.icon;
  const isAnimated = status === "running" || status === "queued";

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div className="comic-panel bg-card p-8">
        
        <div className="text-center mb-6">
          <span className="comic-sfx text-primary inline-block">
            {status === 'running' ? 'SCANNING...' : status === 'done' ? 'COMPLETE!' : status === 'error' ? 'ERROR!' : 'LOADING...'}
          </span>
        </div>

        
        <div className="flex items-center gap-5 mb-8">
          <div className={`p-4 doodle-border ${status === 'error' ? 'border-destructive bg-destructive/20' : 'border-primary bg-primary/20'} transform -rotate-3`}>
            <Icon className={`w-10 h-10 ${config.color} ${isAnimated ? "animate-pulse-ring" : ""}`} />
          </div>
          <div className="flex-1">
            <h3 className="font-display text-2xl tracking-wide">{config.label}...</h3>
            {repoName && (
              <p className="text-base text-muted-foreground font-mono doodle-underline inline-block">{repoName}</p>
            )}
          </div>
          <div className="font-display text-5xl text-primary manga-title">
            {progress}%
          </div>
        </div>

        
        <div className="relative h-6 bg-muted doodle-border overflow-hidden">
          <div 
            className="absolute inset-y-0 left-0 bg-primary transition-all duration-300"
            style={{ width: `${progress}%` }}
          >
            
            <div className="absolute inset-0 bg-speed-lines opacity-30 animate-shimmer" />
          </div>
          
          
          <div 
            className="absolute top-1/2 -translate-y-1/2 text-2xl transition-all duration-300"
            style={{ left: `calc(${Math.min(progress, 95)}% - 12px)` }}
          >
            🔍
          </div>
        </div>

        {status === "running" && (
          <ScanStagesWithTimeout progress={progress} activity={activity} />
        )}

        {error && (
          <div className="mt-6 p-5 bg-destructive/25 doodle-border border-destructive transform -rotate-0.5">
            <p className="text-base text-destructive font-display mb-4">💥 {error}</p>
            {onRetry && (
              <Button 
                onClick={onRetry}
                variant="outline"
                className="doodle-button bg-card border-destructive text-destructive hover:bg-destructive/20"
              >
                <RotateCcw className="w-4 h-4 mr-2" />
                Try Again
              </Button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

interface ScanStagesWithTimeoutProps {
  progress: number;
  activity?: ScanActivity;
}

function ScanStagesWithTimeout({ progress, activity }: ScanStagesWithTimeoutProps) {
  const [treeStageStartTime, setTreeStageStartTime] = useState<number | null>(null);
  const [showTreeDelayMessage, setShowTreeDelayMessage] = useState(false);

  const isTreeStageActive = progress >= 20 && progress < 40;

  useEffect(() => {
    if (isTreeStageActive && treeStageStartTime === null) {
      setTreeStageStartTime(Date.now());
    } else if (!isTreeStageActive) {
      setTreeStageStartTime(null);
      setShowTreeDelayMessage(false);
    }
  }, [isTreeStageActive, treeStageStartTime]);

  useEffect(() => {
    if (!isTreeStageActive || treeStageStartTime === null) return;

    const timer = setTimeout(() => {
      setShowTreeDelayMessage(true);
    }, 30000);

    return () => clearTimeout(timer);
  }, [isTreeStageActive, treeStageStartTime]);

  // Helper to get activity details for a stage
  const getActivityForStage = (stage: string) => {
    if (activity?.stage === stage) {
      return activity;
    }
    return undefined;
  };

  return (
    <div className="mt-8 space-y-4 p-5 doodle-border bg-muted/30">
      <ScanStage 
        stage="metadata" 
        complete={progress >= 20} 
        emoji="📋" 
        activity={getActivityForStage('metadata')}
      />
      <ScanStage 
        stage="tree" 
        complete={progress >= 40} 
        active={isTreeStageActive} 
        emoji="🌳" 
        activity={getActivityForStage('tree')}
      />
      
      {showTreeDelayMessage && isTreeStageActive && (
        <div className="ml-10 p-3 bg-warning/10 doodle-border border-warning/50 text-sm">
          <p className="text-warning font-medium mb-1">⏳ Taking longer than expected...</p>
          <p className="text-muted-foreground text-xs">
            Large repositories with many files can take time to analyze. The GitHub API may also be rate-limiting requests, 
            or the repository has a very deep folder structure. If you have a GitHub token configured, this helps speed things up!
          </p>
        </div>
      )}
      
      <ScanStage 
        stage="fetch" 
        complete={progress >= 60} 
        active={progress >= 40 && progress < 60} 
        emoji="📥" 
        activity={getActivityForStage('fetch')}
      />
      <ScanStage 
        stage="rules" 
        complete={progress >= 80} 
        active={progress >= 60 && progress < 80} 
        emoji="🔬" 
        activity={getActivityForStage('rules')}
      />
      <ScanStage 
        stage="summarize" 
        complete={progress >= 100} 
        active={progress >= 80 && progress < 100} 
        emoji="📊" 
        activity={getActivityForStage('summarize')}
      />
    </div>
  );
}

interface ScanStageProps {
  stage: string;
  complete?: boolean;
  active?: boolean;
  emoji?: string;
  activity?: ScanActivity;
}

function ScanStage({ stage, complete, active, emoji = "•", activity }: ScanStageProps) {
  const stages: Record<string, string> = {
    metadata: "Fetching repository metadata",
    tree: "Analyzing file structure",
    fetch: "Downloading high-signal files",
    rules: "Running security rules",
    summarize: "Generating report",
  };

  // Format the current item being processed
  const formatCurrentItem = () => {
    if (!activity?.currentItem) return null;
    
    // Truncate long file paths
    const item = activity.currentItem;
    const maxLen = 40;
    const displayItem = item.length > maxLen 
      ? '...' + item.slice(-maxLen + 3) 
      : item;
    
    return displayItem;
  };

  const currentItem = formatCurrentItem();
  const hasProgress = activity?.processedCount !== undefined && activity?.totalCount !== undefined;

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-4 text-base font-bold handwritten">
        <span className="text-2xl">{emoji}</span>
        <div
          className={`w-4 h-4 doodle-border transition-colors flex-shrink-0 ${
            complete
              ? "bg-risk-low border-risk-low"
              : active
              ? "bg-primary border-primary animate-pulse-ring"
              : "bg-muted border-border"
          }`}
        />
        <span className={`flex-1 ${complete ? "text-muted-foreground line-through" : active ? "text-foreground" : "text-muted-foreground/50"}`}>
          {stages[stage]}
          {hasProgress && active && (
            <span className="text-primary ml-2">
              ({activity.processedCount}/{activity.totalCount})
            </span>
          )}
        </span>
        {complete && <span className="text-risk-low text-xl">✓</span>}
        {active && <span className="text-primary text-xl animate-wiggle">⚡</span>}
      </div>
      
      
      {active && currentItem && (
        <div className="ml-14 flex items-center gap-2 text-xs">
          <Loader2 className="w-3 h-3 animate-spin text-primary" />
          <span className="text-muted-foreground font-mono truncate">
            {currentItem}
          </span>
        </div>
      )}
    </div>
  );
}
