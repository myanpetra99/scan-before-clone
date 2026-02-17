import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Shield, Github } from "lucide-react";
import { parseGitHubUrl } from "@/lib/github";

interface ScanUrlInputProps {
  onSubmit: (url: string) => void;
  isLoading?: boolean;
}

export function ScanUrlInput({ onSubmit, isLoading }: ScanUrlInputProps) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const trimmedUrl = url.trim();
    if (!trimmedUrl) {
      setError("Please enter a GitHub repository URL");
      return;
    }

    const parsed = parseGitHubUrl(trimmedUrl);
    if (!parsed) {
      setError("Invalid GitHub URL. Use format: github.com/owner/repo");
      return;
    }

    onSubmit(trimmedUrl);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl mx-auto space-y-4">
      <div className="relative">
        <div className="comic-panel bg-card p-8">
          <div className="flex items-center gap-4 mb-6">
            <div className="p-3 doodle-border bg-primary/20 transform -rotate-6">
              <Github className="w-7 h-7 text-primary" />
            </div>
            <p className="text-base text-muted-foreground handwritten">
              Enter any public/private GitHub repository URL 🔍
            </p>
          </div>
          
          <div className="flex gap-4">
            <div className="flex-1">
              <Input
                type="text"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  setError(null);
                }}
                placeholder="https://github.com/owner/repository"
                className="h-14 bg-background/50 border-4 border-border font-mono text-base placeholder:text-muted-foreground/50 focus:border-primary focus:shadow-comic-primary transition-all"
                style={{ borderRadius: '4px 12px 4px 12px' }}
                disabled={isLoading}
              />
            </div>
            <Button
              type="submit"
              variant="scan"
              size="lg"
              disabled={isLoading || !url.trim()}
              className="h-14 px-8 doodle-button font-display text-xl tracking-wider bg-primary text-primary-foreground hover:bg-primary/90"
            >
              {isLoading ? (
                <>
                  <span className="animate-pulse">⏳</span>
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Shield className="w-6 h-6" />
                  <span>SCAN!</span>
                </>
              )}
            </Button>
          </div>

          {error && (
            <div className="mt-4 p-3 bg-destructive/25 doodle-border border-destructive transform -rotate-1">
              <p className="text-base text-destructive font-display">💥 {error}</p>
            </div>
          )}
        </div>
      </div>
    </form>
  );
}
