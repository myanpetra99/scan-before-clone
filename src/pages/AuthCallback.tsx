import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useGitHubToken } from "@/hooks/useGitHubToken";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function AuthCallback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { setToken } = useGitHubToken();
  const { toast } = useToast();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const code = searchParams.get("code");

    if (!code) {
      setError("No authorization code received.");
      return;
    }

    const exchangeToken = async () => {
      try {
        // We will use the VITE_API_URL environment variable if set, or default to /api/oauth/exchange
        // This allows separating frontend (GitHub Pages) and backend (Vercel)
        const apiUrl = import.meta.env.VITE_API_URL 
          ? `${import.meta.env.VITE_API_URL}/api/oauth/exchange`
          : "/api/oauth/exchange";

        const response = await fetch(apiUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ code }),
        });

        const data = await response.json();

        if (!response.ok || data.error) {
          throw new Error(data.error_description || data.error || "Failed to exchange token");
        }

        if (data.access_token) {
          setToken(data.access_token);
          toast({
            title: "Successfully logged in",
            description: "Your GitHub token has been saved.",
          });
          navigate("/");
        } else {
            throw new Error("No access token received");
        }
      } catch (err) {
        console.error(err);
        setError(err instanceof Error ? err.message : "Authentication failed");
        toast({
            variant: "destructive",
            title: "Authentication failed",
            description: err instanceof Error ? err.message : "Please try again.",
        });
      }
    };

    exchangeToken();
  }, [searchParams, setToken, navigate, toast]);

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-center">
            {error ? "Authentication Error" : "Authenticating..."}
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col items-center justify-center space-y-4">
          {error ? (
            <div className="text-destructive text-center">
              <p>{error}</p>
              <button 
                onClick={() => navigate("/")}
                className="mt-4 text-sm underline hover:text-destructive/80"
              >
                Return to Home
              </button>
            </div>
          ) : (
            <>
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <p className="text-muted-foreground text-sm">
                Please wait while we connect to GitHub...
              </p>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
