// GitHub API Client - Fetches repository data without cloning

interface GitHubTreeItem {
  path: string;
  mode: string;
  type: 'blob' | 'tree';
  sha: string;
  size?: number;
  url: string;
}

interface GitHubTree {
  sha: string;
  url: string;
  tree: GitHubTreeItem[];
  truncated: boolean;
}

interface GitHubRepo {
  full_name: string;
  default_branch: string;
  owner: { login: string };
  name: string;
  html_url: string;
}

interface GitHubBranch {
  commit: { sha: string };
}

interface GitHubContent {
  content: string;
  encoding: string;
  size: number;
}

// Rate limiting state
let rateLimitRemaining = 60;
let rateLimitReset = 0;

// Export rate limit info for UI display
export function getRateLimitInfo(): { remaining: number; resetAt: Date | null; isLimited: boolean } {
  const now = Date.now();
  const isLimited = rateLimitRemaining <= 1 && rateLimitReset > now;
  return {
    remaining: rateLimitRemaining,
    resetAt: rateLimitReset > 0 ? new Date(rateLimitReset) : null,
    isLimited,
  };
}

// Format time until rate limit reset
export function formatRateLimitReset(): string | null {
  const { resetAt, isLimited } = getRateLimitInfo();
  if (!isLimited || !resetAt) return null;
  
  const now = Date.now();
  const diff = resetAt.getTime() - now;
  if (diff <= 0) return null;
  
  const minutes = Math.floor(diff / 60000);
  const seconds = Math.floor((diff % 60000) / 1000);
  
  if (minutes > 60) {
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m`;
  }
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

// Import file selection engine
import { selectFiles, getFallbackFiles, logSelectionTrace, MAX_FILES, MAX_TOTAL_BYTES, MAX_PER_FILE, type TreeEntry, type SelectionResult } from './fileSelection';

export interface ParsedRepoUrl {
  owner: string;
  name: string;
  ref?: string;
}

// Parse GitHub URL
export function parseGitHubUrl(url: string): ParsedRepoUrl | null {
  const patterns = [
    /github\.com\/([^\/]+)\/([^\/\s#?]+)/,
    /^([^\/]+)\/([^\/\s#?]+)$/,
  ];

  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return {
        owner: match[1],
        name: match[2].replace(/\.git$/, ''),
      };
    }
  }
  return null;
}

// Wait for rate limit
async function waitForRateLimit(): Promise<void> {
  if (rateLimitRemaining <= 1 && Date.now() < rateLimitReset) {
    const waitTime = rateLimitReset - Date.now() + 1000;
    console.log(`Rate limited, waiting ${waitTime}ms`);
    await new Promise(resolve => setTimeout(resolve, Math.min(waitTime, 60000)));
  }
}

// Fetch with rate limit handling
async function fetchGitHub(url: string, token?: string): Promise<Response> {
  await waitForRateLimit();

  const headers: HeadersInit = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'GitHub-Repo-Scanner/1.0',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, { headers });

  // Update rate limit info
  const remaining = response.headers.get('X-RateLimit-Remaining');
  const reset = response.headers.get('X-RateLimit-Reset');
  if (remaining) rateLimitRemaining = parseInt(remaining, 10);
  if (reset) rateLimitReset = parseInt(reset, 10) * 1000;

  if (response.status === 403 || response.status === 429) {
    const resetTime = rateLimitReset > 0 ? new Date(rateLimitReset).toLocaleTimeString() : 'soon';
    throw new Error(`GitHub API rate limit exceeded. Try again after ${resetTime}.`);
  }

  if (response.status === 401) {
    throw new Error('GitHub API authentication failed. Please check your access token.');
  }

  return response;
}

// Get repository info
export async function getRepoInfo(owner: string, name: string, token?: string): Promise<{
  defaultBranch: string;
  commitSha: string;
  url: string;
}> {
  const response = await fetchGitHub(
    `https://api.github.com/repos/${owner}/${name}`,
    token
  );

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(`Repository "${owner}/${name}" not found. Make sure it exists and is public.`);
    }
    if (response.status === 403) {
      throw new Error(`Access denied to "${owner}/${name}". This may be a private repository or you've hit rate limits.`);
    }
    const errorText = await response.text().catch(() => response.statusText);
    throw new Error(`Failed to fetch repository: ${response.status} - ${errorText || response.statusText}`);
  }

  const repo: GitHubRepo = await response.json();

  // Get latest commit SHA
  const branchResponse = await fetchGitHub(
    `https://api.github.com/repos/${owner}/${name}/branches/${repo.default_branch}`,
    token
  );

  if (!branchResponse.ok) {
    const errorText = await branchResponse.text().catch(() => branchResponse.statusText);
    throw new Error(`Failed to fetch branch "${repo.default_branch}": ${branchResponse.status} - ${errorText || branchResponse.statusText}`);
  }

  const branch: GitHubBranch = await branchResponse.json();

  return {
    defaultBranch: repo.default_branch,
    commitSha: branch.commit.sha,
    url: repo.html_url,
  };
}

// Get repository tree
export async function getRepoTree(
  owner: string,
  name: string,
  sha: string,
  token?: string
): Promise<{ files: GitHubTreeItem[]; truncated: boolean }> {
  const response = await fetchGitHub(
    `https://api.github.com/repos/${owner}/${name}/git/trees/${sha}?recursive=1`,
    token
  );

  if (!response.ok) {
    if (response.status === 409) {
      throw new Error(`Repository is empty or has no commits yet.`);
    }
    const errorText = await response.text().catch(() => response.statusText);
    throw new Error(`Failed to fetch repository tree: ${response.status} - ${errorText || response.statusText}`);
  }

  const tree: GitHubTree = await response.json();

  // Filter to only files (blobs)
  const files = tree.tree.filter(item => item.type === 'blob');

  return { files, truncated: tree.truncated };
}

// Prioritize files for scanning (uses new file selection engine)
export function prioritizeFiles(files: GitHubTreeItem[]): GitHubTreeItem[] {
  const entries: TreeEntry[] = files.map(f => ({
    path: f.path,
    size: f.size,
    type: f.type,
  }));
  
  const result = selectFiles(entries, {
    maxFiles: MAX_FILES,
    maxTotalBytes: MAX_TOTAL_BYTES,
    maxPerFile: MAX_PER_FILE,
    enableTrace: true,
  });
  
  // Log selection trace for debugging
  logSelectionTrace(result);
  
  // Map back to GitHubTreeItem
  const selectedPaths = new Set(result.files.map(f => f.path));
  return files.filter(f => selectedPaths.has(f.path));
}

// Export for fallback when tree is truncated
export { getFallbackFiles };

// Fetch file content
export async function getFileContent(
  owner: string,
  name: string,
  path: string,
  token?: string
): Promise<string | null> {
  try {
    const response = await fetchGitHub(
      `https://api.github.com/repos/${owner}/${name}/contents/${encodeURIComponent(path)}`,
      token
    );

    if (!response.ok) {
      return null;
    }

    const data: GitHubContent = await response.json();

    if (data.encoding === 'base64' && data.content) {
      // Decode base64
      const decoded = atob(data.content.replace(/\n/g, ''));
      return decoded;
    }

    return null;
  } catch {
    return null;
  }
}

// Full scan workflow
export interface ScanResult {
  files: Array<{ path: string; content: string }>;
  stats: {
    filesScanned: number;
    bytesFetched: number;
    truncated: boolean;
  };
}

export async function fetchRepoForScan(
  owner: string,
  name: string,
  ref?: string,
  token?: string
): Promise<{ repoInfo: { defaultBranch: string; commitSha: string; url: string }; scanData: ScanResult }> {
  // Get repo info
  const repoInfo = await getRepoInfo(owner, name, token);
  const sha = ref || repoInfo.commitSha;

  // Get tree
  const { files: allFiles, truncated } = await getRepoTree(owner, name, sha, token);

  // Prioritize files
  const filesToFetch = prioritizeFiles(allFiles);

  // Fetch file contents
  const fetchedFiles: Array<{ path: string; content: string }> = [];
  let totalBytes = 0;

  for (const file of filesToFetch) {
    if (totalBytes >= MAX_TOTAL_BYTES) break;
    if (file.size && file.size > MAX_PER_FILE) continue;

    const content = await getFileContent(owner, name, file.path, token);
    if (content) {
      fetchedFiles.push({ path: file.path, content });
      totalBytes += content.length;
    }
  }

  return {
    repoInfo,
    scanData: {
      files: fetchedFiles,
      stats: {
        filesScanned: fetchedFiles.length,
        bytesFetched: totalBytes,
        truncated,
      },
    },
  };
}
