import { useState, useEffect } from "react";
import { AlertTriangle, Clock, ExternalLink } from "lucide-react";
import { getRateLimitInfo, formatRateLimitReset } from "@/lib/github";
import { Button } from "@/components/ui/button";

interface RateLimitWarningProps {
  onRetry?: () => void;
}

export function RateLimitWarning({ onRetry }: RateLimitWarningProps) {
  const [timeUntilReset, setTimeUntilReset] = useState<string | null>(null);
  const [isExpired, setIsExpired] = useState(false);
  
  useEffect(() => {
    const updateTimer = () => {
      const formatted = formatRateLimitReset();
      if (formatted) {
        setTimeUntilReset(formatted);
        setIsExpired(false);
      } else {
        setTimeUntilReset(null);
        setIsExpired(true);
      }
    };
    
    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    
    return () => clearInterval(interval);
  }, []);
  
  const { resetAt } = getRateLimitInfo();
  
  return (
    <div className="w-full max-w-2xl mx-auto">
      <div className="comic-panel bg-card p-8 border-comic-orange">
        
      
        
        <div className="flex items-start gap-5 mb-6">
          <div className="p-4 doodle-border border-comic-orange bg-comic-orange/20 transform rotate-3">
            <AlertTriangle className="w-10 h-10 text-comic-orange" />
          </div>
          <div className="flex-1">
            <h3 className="font-display text-2xl tracking-wide text-foreground mb-2">
              GitHub API Limit Reached 😅
            </h3>
            <p className="text-base text-muted-foreground handwritten">
              You've hit GitHub's rate limit for unauthenticated requests 
              (60 requests/hour). Don't worry, it resets automatically!
            </p>
          </div>
        </div>
        
        
        <div className="doodle-border bg-muted/30 p-6 mb-6 text-center">
          <div className="flex items-center justify-center gap-3 mb-2">
            <Clock className="w-6 h-6 text-comic-orange" />
            <span className="font-display text-lg text-muted-foreground">
              Resets in:
            </span>
          </div>
          
          {timeUntilReset ? (
            <div className="font-display text-5xl text-comic-orange manga-title animate-pulse">
              {timeUntilReset}
            </div>
          ) : isExpired ? (
            <div className="font-display text-3xl text-risk-low manga-title">
              Ready to scan! ✨
            </div>
          ) : (
            <div className="font-display text-3xl text-muted-foreground">
              Calculating...
            </div>
          )}
          
          {resetAt && (
            <p className="text-sm text-muted-foreground mt-2 font-mono">
              @ {resetAt.toLocaleTimeString()}
            </p>
          )}
        </div>
        
        
        <div className="flex flex-col sm:flex-row gap-3 justify-center">
          {isExpired && onRetry && (
            <Button
              onClick={onRetry}
              className="doodle-button bg-primary text-primary-foreground font-display tracking-wide"
            >
              🔍 Try Again
            </Button>
          )}
          
          <a
            href="https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-2 doodle-button bg-muted px-4 py-2 text-sm font-display text-muted-foreground hover:text-foreground"
          >
            <ExternalLink className="w-4 h-4" />
            Why does this happen?
          </a>
        </div>
        
        
        <div className="mt-6 text-center">
          <p className="text-xs text-muted-foreground">
            💡 <span className="font-bold">Tip:</span> Authenticated requests get 5,000/hour. 
            We're working on GitHub OAuth support!
          </p>
        </div>
      </div>
    </div>
  );
}