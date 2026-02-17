import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { useGitHubToken } from "@/hooks/useGitHubToken";
import { Key, Check, X, ExternalLink, Github } from "lucide-react";

export function GitHubTokenInput() {
  const { token, isAuthenticated, rateLimit, setToken, clearToken } = useGitHubToken();
  const [inputValue, setInputValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isOpen, setIsOpen] = useState(false);

  const handleOAuthLogin = () => {
    const clientId = import.meta.env.VITE_GITHUB_CLIENT_ID;
    if (!clientId) {
      setError("GitHub Client ID is not configured.");
      return;
    }
    const baseUrl = import.meta.env.BASE_URL;
    // Ensure we don't have double slashes if BASE_URL is "/"
    const path = baseUrl.endsWith('/') ? `${baseUrl}auth/callback` : `${baseUrl}/auth/callback`;
    const redirectUri = `${window.location.origin}${path}`;
    const scope = "repo read:org";
    window.location.href = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope}`;
  };

  const handleSave = () => {
    setError(null);
    try {
      setToken(inputValue);
      setInputValue("");
      setIsOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid token");
    }
  };

  const handleClear = () => {
    clearToken();
    setInputValue("");
    setError(null);
  };

  const maskedToken = token ? `${token.slice(0, 8)}...${token.slice(-4)}` : null;

  return (
    <div className="flex items-center gap-2">
      {!isAuthenticated && (
        <Button
          variant="outline"
          size="sm"
          className="gap-2 font-mono text-xs"
          onClick={handleOAuthLogin}
        >
          <Github className="w-3.5 h-3.5" />
          Connect
        </Button>
      )}

      <Dialog open={isOpen} onOpenChange={setIsOpen}>
        <DialogTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className={`gap-2 font-mono text-xs ${
              isAuthenticated
                ? "text-green-500 hover:text-green-400"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            {isAuthenticated ? (
              <>
                <Check className="w-3 h-3" />
                <span>{rateLimit.toLocaleString()}/hr</span>
              </>
            ) : (
              <span>60/hr limit</span>
            )}
          </Button>
        </DialogTrigger>
        <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Key className="w-5 h-5" />
            GitHub API Token
          </DialogTitle>
          <DialogDescription>
            Add a Personal Access Token to increase rate limits from 60 to 5,000 requests/hour.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {isAuthenticated ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 rounded-lg bg-accent/20 border border-accent/30">
                <div className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-accent" />
                  <span className="text-sm text-accent font-medium">Token active</span>
                </div>
                <code className="text-xs text-muted-foreground">{maskedToken}</code>
              </div>
              <div className="text-sm text-muted-foreground">
                Rate limit: <strong className="text-accent">{rateLimit.toLocaleString()}</strong> requests/hour
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <Button
                variant="outline"
                className="w-full gap-2"
                onClick={handleOAuthLogin}
              >
                <Github className="w-4 h-4" />
                Connect with GitHub
              </Button>

              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-background px-2 text-muted-foreground">
                    Or manually enter token
                  </span>
                </div>
              </div>

              <Input
                type="password"
                placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                value={inputValue}
                onChange={(e) => {
                  setInputValue(e.target.value);
                  setError(null);
                }}
                className="font-mono text-sm"
              />
              {error && (
                <p className="text-sm text-destructive flex items-center gap-1">
                  <X className="w-3 h-3" />
                  {error}
                </p>
              )}
              <div className="text-xs text-muted-foreground space-y-1">
                <p>Create a token with <strong>public_repo</strong> scope (read-only):</p>
                <a
                  href="https://github.com/settings/tokens/new?description=RepoScan%20Scanner&scopes=public_repo"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-primary hover:underline"
                >
                  Generate token on GitHub
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          )}
        </div>

        <DialogFooter className="gap-2 sm:gap-0">
          {isAuthenticated ? (
            <Button variant="destructive" onClick={handleClear} className="gap-2">
              <X className="w-4 h-4" />
              Remove Token
            </Button>
          ) : (
            <>
              <Button variant="ghost" onClick={() => setIsOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleSave} disabled={!inputValue.trim()}>
                Save Token
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
      </Dialog>
    </div>
  );
}
