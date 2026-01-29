import { useState, useEffect, useCallback } from "react";

const STORAGE_KEY = "github_pat";

export interface GitHubTokenInfo {
  token: string | null;
  isAuthenticated: boolean;
  rateLimit: number; // 60 for anonymous, 5000 for authenticated
}

export function useGitHubToken() {
  const [token, setTokenState] = useState<string | null>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY);
    } catch {
      return null;
    }
  });

  const isAuthenticated = Boolean(token);
  const rateLimit = isAuthenticated ? 5000 : 60;

  const setToken = useCallback((newToken: string | null) => {
    try {
      if (newToken) {
        // Basic validation - GitHub PATs start with specific prefixes
        const trimmed = newToken.trim();
        if (!trimmed.match(/^(ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)/)) {
          throw new Error("Invalid GitHub token format");
        }
        localStorage.setItem(STORAGE_KEY, trimmed);
        setTokenState(trimmed);
      } else {
        localStorage.removeItem(STORAGE_KEY);
        setTokenState(null);
      }
    } catch (error) {
      console.error("Failed to save GitHub token:", error);
      throw error;
    }
  }, []);

  const clearToken = useCallback(() => {
    try {
      localStorage.removeItem(STORAGE_KEY);
      setTokenState(null);
    } catch (error) {
      console.error("Failed to clear GitHub token:", error);
    }
  }, []);

  // Validate token on mount
  useEffect(() => {
    if (token && !token.match(/^(ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)/)) {
      clearToken();
    }
  }, [token, clearToken]);

  return {
    token,
    isAuthenticated,
    rateLimit,
    setToken,
    clearToken,
  };
}

// Helper to get token synchronously (for API calls)
export function getStoredGitHubToken(): string | null {
  try {
    const token = localStorage.getItem(STORAGE_KEY);
    if (token && token.match(/^(ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)/)) {
      return token;
    }
    return null;
  } catch {
    return null;
  }
}
