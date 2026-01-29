// File Selection Engine - Priority-based file selection for repository scanning
// Time Complexity: O(n log n) where n = number of files in tree

export interface TreeEntry {
  path: string;
  size?: number;
  type: 'blob' | 'tree';
}

export interface SelectionResult {
  files: TreeEntry[];
  trace: SelectionTrace[];
  stats: {
    totalConsidered: number;
    selected: number;
    skipped: number;
    truncatedFallback: boolean;
  };
}

export interface SelectionTrace {
  path: string;
  priority: number;
  reason: string;
  selected: boolean;
  skippedReason?: string;
}

// Limits
export const MAX_FILES = 60;
export const MAX_TOTAL_BYTES = 2 * 1024 * 1024; // 2MB
export const MAX_PER_FILE = 120 * 1024; // 120KB

// Priority tiers (higher = more important)
export enum Priority {
  CRITICAL = 1000,    // Always fetch - VS Code configs, install scripts
  HIGH = 500,         // Package managers, CI configs
  MEDIUM = 200,       // Scripts, configs
  LOW = 50,           // Other source files
  VENDOR = -100,      // Vendor/node_modules (negative = exclude)
}

// ========== CRITICAL FILES (always include) ==========
// These files are fetched even if tree is truncated
// Updated for 34 detection categories (v4.2.0)
export const CRITICAL_FILES: string[] = [
  // VS Code attack vectors (both singular and plural naming)
  '.vscode/tasks.json',
  '.vscode/task.json',
  '.vscode/launch.json',
  '.vscode/settings.json',
  '.vscode/extensions.json',
  
  // Devcontainers (OPEN-time execution) - Category 15
  '.devcontainer/devcontainer.json',
  '.devcontainer/Dockerfile',
  '.devcontainer.json',
  
  // Git execution vectors - Category 14, 28
  '.gitattributes',
  '.gitmodules',
  '.gitconfig',
  '.git/config',
  '.git/hooks/pre-commit',
  '.git/hooks/post-commit',
  '.git/hooks/commit-msg',
  '.git/hooks/pre-push',
  '.git/info/attributes',
  '.mailmap',
  'CODEOWNERS',
  '.github/CODEOWNERS',
  'FUNDING.yml',
  '.github/FUNDING.yml',
  
  // Package managers (install hooks) - Category 19, 24
  'package.json',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  '.npmrc',
  '.yarnrc',
  '.yarnrc.yml',
  '.yarnrc.yaml',
  '.pnpmfile.cjs',
  
  // Python - Category 19, 24
  'setup.py',
  'setup.cfg',
  'pyproject.toml',
  'requirements.txt',
  'requirements-dev.txt',
  'Pipfile',
  'Pipfile.lock',
  'poetry.lock',
  'conftest.py',
  'pytest.ini',
  
  // Go
  'go.mod',
  'go.sum',
  
  // Rust - Category 19
  'Cargo.toml',
  'Cargo.lock',
  'build.rs',
  
  // Ruby
  'Gemfile',
  'Gemfile.lock',
  
  // Build systems - Category 24
  'Makefile',
  'CMakeLists.txt',
  'build.gradle',
  'build.gradle.kts',
  'settings.gradle',
  'settings.gradle.kts',
  'pom.xml',
  
  // Composer (PHP)
  'composer.json',
  'composer.lock',
  
  // Documentation (social engineering)
  'README.md',
  'readme.md',
  'README.rst',
  'INSTALL.md',
  
  // Docker
  'Dockerfile',
  'docker-compose.yml',
  'docker-compose.yaml',
  '.dockerignore',
  
  // CI/CD Platforms - Category 20
  '.gitlab-ci.yml',
  '.gitlab-ci.yaml',
  '.circleci/config.yml',
  'bitbucket-pipelines.yml',
  'azure-pipelines.yml',
  'azure-pipelines.yaml',
  '.travis.yml',
  'Jenkinsfile',
  'appveyor.yml',
  
  // Pre-commit hooks - Category 18
  '.pre-commit-config.yaml',
  '.pre-commit-config.yml',
  '.husky/pre-commit',
  '.husky/pre-push',
  '.husky/commit-msg',
  '.husky/post-commit',
  '.huskyrc',
  '.huskyrc.json',
  '.lintstagedrc',
  '.lintstagedrc.json',
  'lint-staged.config.js',
  
  // Test framework configs - Category 16
  'jest.config.js',
  'jest.config.ts',
  'jest.config.json',
  'vitest.config.js',
  'vitest.config.ts',
  
  // Documentation generators - Category 17
  'jsdoc.json',
  'jsdoc.conf.json',
  'conf.py',
  'mkdocs.yml',
  'mkdocs.yaml',
  'typedoc.json',
  
  // Task runners - Category 23
  'nx.json',
  'workspace.json',
  'turbo.json',
  'lerna.json',
  'gulpfile.js',
  'gulpfile.ts',
  'Gruntfile.js',
  
  // JetBrains IDE - Category 26
  '.idea/workspace.xml',
  '.idea/runConfigurations',
  '.idea/externalDependencies.xml',
  
  // Vim/Neovim - local config execution
  '.exrc',
  '.nvimrc',
  '.vimrc',
  '.lvimrc',
  '.nvim.lua',
  
  // Emacs - directory-local variables
  '.dir-locals.el',
  '.dir-locals-2.el',
  '.projectile',
  
  // Sublime Text - project build systems
  // (matched by pattern below for *.sublime-project)
  
  // Remote development - Category 22
  '.ssh/config',
  
  // EditorConfig - Category 27
  '.editorconfig',
  
  // Dependency bots - Category 28
  'renovate.json',
  '.renovaterc',
  '.renovaterc.json',
  'renovate.json5',
  '.github/dependabot.yml',
  'dependabot.yml',
  
  // Secrets bait (should be flagged)
  '.env',
  '.env.local',
  '.env.example',
  
  // Browser extension manifest
  'manifest.json',
  
  // Cursor IDE
  '.cursor/settings.json',
  '.cursor/tasks.json',
  
  // Zed editor
  '.zed/settings.json',
  '.zed/tasks.json',
  
  // Helix editor
  '.helix/config.toml',
  '.helix/languages.toml',
  
  // Container orchestration
  'k8s/deployment.yaml',
  'kubernetes/deployment.yaml',
  'helm/Chart.yaml',
  'helm/values.yaml',
  
  // Serverless
  'serverless.yml',
  'serverless.yaml',
  'sam.yaml',
  'template.yaml',
  'vercel.json',
  'netlify.toml',
  'wrangler.toml',
  
  // AI/ML
  'MLmodel',
  'conda.yaml',
  
  // Mobile development
  'Podfile',
  'pubspec.yaml',
  'app.json',
  'expo.json',
  
  // VBA/Office Macro files (Social Engineering detection)
  // Note: These are flagged as suspicious by file extension
];

// ========== HIGH-SIGNAL PATTERNS ==========
// Updated for 34 detection categories (v4.2.0)
const HIGH_SIGNAL_PATTERNS: Array<{ pattern: RegExp; priority: number; reason: string }> = [
  // GitHub Actions - CI/CD attack vector (Category 20)
  { pattern: /^\.github\/workflows\/[^/]+\.ya?ml$/, priority: Priority.CRITICAL, reason: 'GitHub Actions workflow' },
  { pattern: /^\.github\/actions\/[^/]+\/(action\.ya?ml|index\.[jt]s)$/, priority: Priority.CRITICAL, reason: 'GitHub Action definition' },
  
  // GitLab CI
  { pattern: /^\.gitlab-ci\.ya?ml$/, priority: Priority.CRITICAL, reason: 'GitLab CI config' },
  
  // CircleCI
  { pattern: /^\.circleci\/config\.ya?ml$/, priority: Priority.CRITICAL, reason: 'CircleCI config' },
  
  // Bitbucket Pipelines
  { pattern: /^bitbucket-pipelines\.ya?ml$/, priority: Priority.CRITICAL, reason: 'Bitbucket Pipelines config' },
  
  // Azure Pipelines
  { pattern: /^azure-pipelines\.ya?ml$/, priority: Priority.CRITICAL, reason: 'Azure Pipelines config' },
  
  // Travis CI
  { pattern: /^\.travis\.ya?ml$/, priority: Priority.CRITICAL, reason: 'Travis CI config' },
  
  // Jenkins
  { pattern: /^Jenkinsfile$/i, priority: Priority.CRITICAL, reason: 'Jenkins pipeline' },
  { pattern: /\.jenkins$/i, priority: Priority.HIGH, reason: 'Jenkins config' },
  
  // Dockerfiles (can be in subdirs)
  { pattern: /Dockerfile(\.[^/]+)?$/i, priority: Priority.HIGH, reason: 'Dockerfile' },
  { pattern: /\.dockerfile$/i, priority: Priority.HIGH, reason: 'Dockerfile' },
  
  // VS Code configs (Category 1, 3)
  { pattern: /^\.vscode\/[^/]+\.json$/, priority: Priority.CRITICAL, reason: 'VS Code config' },
  
  // DevContainers (Category 15)
  { pattern: /\.devcontainer\/[^/]+$/, priority: Priority.CRITICAL, reason: 'DevContainer config' },
  { pattern: /devcontainer\.json$/, priority: Priority.CRITICAL, reason: 'DevContainer config' },
  
  // Install scripts
  { pattern: /^install\.(sh|bash|ps1|bat|cmd)$/i, priority: Priority.CRITICAL, reason: 'Install script' },
  { pattern: /^setup\.(sh|bash|ps1|bat|cmd)$/i, priority: Priority.CRITICAL, reason: 'Setup script' },
  { pattern: /^bootstrap\.(sh|bash|ps1|bat|cmd)$/i, priority: Priority.CRITICAL, reason: 'Bootstrap script' },
  { pattern: /^init\.(sh|bash|ps1|bat|cmd)$/i, priority: Priority.CRITICAL, reason: 'Init script' },
  
  // Shell scripts in root
  { pattern: /^[^/]+\.(sh|bash)$/, priority: Priority.HIGH, reason: 'Root shell script' },
  { pattern: /^[^/]+\.(ps1|bat|cmd)$/, priority: Priority.HIGH, reason: 'Root Windows script' },
  
  // Scripts directory
  { pattern: /^scripts\/[^/]+\.(sh|bash|ps1|bat|cmd|js|ts|py)$/i, priority: Priority.HIGH, reason: 'Scripts directory file' },
  { pattern: /^bin\/[^/]+$/i, priority: Priority.HIGH, reason: 'Bin directory file' },
  
  // Pre-commit hooks (Category 18)
  { pattern: /^\.husky\/[^/]+$/, priority: Priority.CRITICAL, reason: 'Husky hook' },
  { pattern: /^\.git\/hooks\/[^/]+$/, priority: Priority.CRITICAL, reason: 'Git hook' },
  { pattern: /^\.githooks\/[^/]+$/, priority: Priority.CRITICAL, reason: 'Git hook directory' },
  { pattern: /^\.pre-commit-config\.ya?ml$/, priority: Priority.CRITICAL, reason: 'Pre-commit config' },
  { pattern: /lint-staged\.config\.[jt]s$/, priority: Priority.HIGH, reason: 'lint-staged config' },
  { pattern: /\.lintstagedrc(\.json)?$/, priority: Priority.HIGH, reason: 'lint-staged config' },
  
  // Git config abuse (Category 14)
  { pattern: /^\.gitconfig$/, priority: Priority.CRITICAL, reason: 'Git config' },
  { pattern: /^\.git\/config$/, priority: Priority.CRITICAL, reason: 'Git config' },
  { pattern: /^\.git\/info\/attributes$/, priority: Priority.HIGH, reason: 'Git attributes' },
  
  // Repository metadata (Category 28)
  { pattern: /^\.mailmap$/, priority: Priority.MEDIUM, reason: 'Git mailmap' },
  { pattern: /^CODEOWNERS$/, priority: Priority.MEDIUM, reason: 'CODEOWNERS file' },
  { pattern: /^\.github\/CODEOWNERS$/, priority: Priority.MEDIUM, reason: 'CODEOWNERS file' },
  { pattern: /^\.github\/FUNDING\.ya?ml$/, priority: Priority.MEDIUM, reason: 'Funding config' },
  { pattern: /renovate\.json5?$/, priority: Priority.HIGH, reason: 'Renovate config' },
  { pattern: /\.renovaterc(\.json)?$/, priority: Priority.HIGH, reason: 'Renovate config' },
  { pattern: /dependabot\.ya?ml$/, priority: Priority.HIGH, reason: 'Dependabot config' },
  
  // Package manager configs (Category 24)
  { pattern: /^\.npmrc$/, priority: Priority.CRITICAL, reason: 'npm config' },
  { pattern: /^\.yarnrc(\.ya?ml)?$/, priority: Priority.CRITICAL, reason: 'Yarn config' },
  { pattern: /^\.pnpmfile\.cjs$/, priority: Priority.HIGH, reason: 'pnpm config' },
  
  // Lockfiles (Category 19)
  { pattern: /^pnpm-lock\.yaml$/, priority: Priority.HIGH, reason: 'pnpm lockfile' },
  { pattern: /^package-lock\.json$/, priority: Priority.HIGH, reason: 'npm lockfile' },
  { pattern: /^yarn\.lock$/, priority: Priority.HIGH, reason: 'Yarn lockfile' },
  { pattern: /^Pipfile\.lock$/, priority: Priority.HIGH, reason: 'Pipfile lockfile' },
  { pattern: /^poetry\.lock$/, priority: Priority.HIGH, reason: 'Poetry lockfile' },
  { pattern: /^Cargo\.lock$/, priority: Priority.HIGH, reason: 'Cargo lockfile' },
  
  // Test framework configs (Category 16)
  { pattern: /^jest\.config\.[jt]s$/, priority: Priority.HIGH, reason: 'Jest config' },
  { pattern: /^jest\.config\.json$/, priority: Priority.HIGH, reason: 'Jest config' },
  { pattern: /^vitest\.config\.[jt]s$/, priority: Priority.HIGH, reason: 'Vitest config' },
  { pattern: /^conftest\.py$/, priority: Priority.HIGH, reason: 'Pytest conftest' },
  { pattern: /conftest\.py$/, priority: Priority.MEDIUM, reason: 'Pytest conftest' },
  { pattern: /_test\.go$/, priority: Priority.MEDIUM, reason: 'Go test file' },
  
  // Documentation generators (Category 17)
  { pattern: /^jsdoc\.(?:conf\.)?json$/, priority: Priority.MEDIUM, reason: 'JSDoc config' },
  { pattern: /^mkdocs\.ya?ml$/, priority: Priority.MEDIUM, reason: 'MkDocs config' },
  { pattern: /^typedoc\.json$/, priority: Priority.MEDIUM, reason: 'TypeDoc config' },
  { pattern: /^docs?\/conf\.py$/, priority: Priority.MEDIUM, reason: 'Sphinx config' },
  
  // Task runners (Category 23)
  { pattern: /^nx\.json$/, priority: Priority.HIGH, reason: 'Nx config' },
  { pattern: /^workspace\.json$/, priority: Priority.HIGH, reason: 'Nx workspace' },
  { pattern: /^turbo\.json$/, priority: Priority.HIGH, reason: 'Turborepo config' },
  { pattern: /^lerna\.json$/, priority: Priority.HIGH, reason: 'Lerna config' },
  { pattern: /^gulpfile\.[jt]s$/, priority: Priority.HIGH, reason: 'Gulpfile' },
  { pattern: /^Gruntfile\.js$/, priority: Priority.HIGH, reason: 'Gruntfile' },
  
  // JetBrains IDE configs (Category 26)
  { pattern: /^\.idea\/workspace\.xml$/, priority: Priority.HIGH, reason: 'JetBrains workspace' },
  { pattern: /^\.idea\/runConfigurations\/[^/]+\.xml$/, priority: Priority.CRITICAL, reason: 'JetBrains run config' },
  { pattern: /^\.idea\/externalDependencies\.xml$/, priority: Priority.HIGH, reason: 'JetBrains external deps' },
  
  // Vim/Neovim configs (auto-execution risk)
  { pattern: /^\.exrc$/, priority: Priority.CRITICAL, reason: 'Vim local config' },
  { pattern: /^\.nvimrc$/, priority: Priority.CRITICAL, reason: 'Neovim local config' },
  { pattern: /^\.vimrc$/, priority: Priority.HIGH, reason: 'Vim config' },
  { pattern: /^\.lvimrc$/, priority: Priority.CRITICAL, reason: 'Local vimrc' },
  { pattern: /^\.nvim\.lua$/, priority: Priority.CRITICAL, reason: 'Neovim Lua config' },
  
  // Emacs configs (auto-execution risk)
  { pattern: /^\.dir-locals\.el$/, priority: Priority.CRITICAL, reason: 'Emacs dir-locals' },
  { pattern: /^\.dir-locals-2\.el$/, priority: Priority.CRITICAL, reason: 'Emacs dir-locals' },
  { pattern: /^\.projectile$/, priority: Priority.MEDIUM, reason: 'Emacs Projectile config' },
  
  // Sublime Text configs
  { pattern: /\.sublime-project$/, priority: Priority.HIGH, reason: 'Sublime project' },
  { pattern: /\.sublime-build$/, priority: Priority.HIGH, reason: 'Sublime build system' },
  
  // Remote development (Category 22)
  { pattern: /\.ssh\/config$/, priority: Priority.CRITICAL, reason: 'SSH config' },
  { pattern: /\.ssh\/known_hosts$/, priority: Priority.HIGH, reason: 'SSH known hosts' },
  
  // EditorConfig (Category 27)
  { pattern: /^\.editorconfig$/, priority: Priority.MEDIUM, reason: 'EditorConfig' },
  
  // VS Code extension manifests (Category 25)
  // Detected by checking package.json for vscode engine
  
  // Gradle (Category 24)
  { pattern: /^settings\.gradle(\.kts)?$/, priority: Priority.HIGH, reason: 'Gradle settings' },
  { pattern: /^build\.gradle(\.kts)?$/, priority: Priority.HIGH, reason: 'Gradle build' },
  
  // Cursor IDE
  { pattern: /^\.cursor\/[^/]+\.json$/, priority: Priority.HIGH, reason: 'Cursor IDE config' },
  
  // Zed editor
  { pattern: /^\.zed\/[^/]+\.json$/, priority: Priority.HIGH, reason: 'Zed editor config' },
  
  // Helix editor
  { pattern: /^\.helix\/[^/]+\.toml$/, priority: Priority.HIGH, reason: 'Helix editor config' },
  
  // Browser extension manifests
  { pattern: /^manifest\.json$/, priority: Priority.HIGH, reason: 'Browser extension manifest' },
  { pattern: /^_locales\//, priority: Priority.MEDIUM, reason: 'Browser extension locales' },
  
  // Kubernetes/Helm
  { pattern: /^(?:k8s|kubernetes|helm|charts?)\/.*\.ya?ml$/i, priority: Priority.HIGH, reason: 'Kubernetes/Helm manifest' },
  { pattern: /^Chart\.ya?ml$/i, priority: Priority.HIGH, reason: 'Helm chart' },
  { pattern: /^values\.ya?ml$/i, priority: Priority.HIGH, reason: 'Helm values' },
  
  // Serverless
  { pattern: /^serverless\.ya?ml$/i, priority: Priority.CRITICAL, reason: 'Serverless Framework config' },
  { pattern: /^sam\.ya?ml$/i, priority: Priority.CRITICAL, reason: 'AWS SAM template' },
  { pattern: /^template\.ya?ml$/i, priority: Priority.HIGH, reason: 'CloudFormation/SAM template' },
  { pattern: /^vercel\.json$/i, priority: Priority.HIGH, reason: 'Vercel config' },
  { pattern: /^netlify\.toml$/i, priority: Priority.HIGH, reason: 'Netlify config' },
  { pattern: /^wrangler\.toml$/i, priority: Priority.HIGH, reason: 'CloudFlare Workers config' },
  
  // AI/ML files
  { pattern: /\.ipynb$/i, priority: Priority.HIGH, reason: 'Jupyter notebook' },
  { pattern: /^MLmodel$/i, priority: Priority.HIGH, reason: 'MLflow model' },
  { pattern: /\.pkl$|\.pickle$/i, priority: Priority.HIGH, reason: 'Pickle file' },
  
  // Mobile development
  { pattern: /^Podfile$/i, priority: Priority.HIGH, reason: 'iOS Podfile' },
  { pattern: /^pubspec\.ya?ml$/i, priority: Priority.HIGH, reason: 'Flutter pubspec' },
  { pattern: /^app\.json$/i, priority: Priority.HIGH, reason: 'React Native/Expo config' },
  { pattern: /^expo\.json$/i, priority: Priority.HIGH, reason: 'Expo config' },
  { pattern: /^app\.config\.[jt]s$/i, priority: Priority.HIGH, reason: 'Expo app config' },
  
  // Drone/Woodpecker CI
  { pattern: /^\.drone\.ya?ml$/i, priority: Priority.CRITICAL, reason: 'Drone CI config' },
  { pattern: /^\.woodpecker\.ya?ml$/i, priority: Priority.CRITICAL, reason: 'Woodpecker CI config' },
  { pattern: /^\.woodpecker\/.*\.ya?ml$/i, priority: Priority.CRITICAL, reason: 'Woodpecker CI config' },
  
  // VBA/Office Macro files (Social Engineering detection)
  { pattern: /\.(vba|bas|cls|frm)$/i, priority: Priority.CRITICAL, reason: 'VBA macro file' },
  { pattern: /\.(xlsm|docm|pptm|xlsb|dotm|potm)$/i, priority: Priority.HIGH, reason: 'Macro-enabled Office file' },
  
  // Other configs
  { pattern: /^\.env(\.[^/]+)?$/, priority: Priority.MEDIUM, reason: 'Environment file' },
  { pattern: /^webpack\.config\.[jt]s$/, priority: Priority.LOW, reason: 'Webpack config' },
  { pattern: /^vite\.config\.[jt]s$/, priority: Priority.LOW, reason: 'Vite config' },
  { pattern: /^rollup\.config\.[jt]s$/, priority: Priority.LOW, reason: 'Rollup config' },
];

// ========== EXCLUSION PATTERNS ==========
const EXCLUSION_PATTERNS: RegExp[] = [
  // Vendor directories
  /^node_modules\//,
  /^vendor\//,
  /^bower_components\//,
  /^jspm_packages\//,
  /^packages\/.*\/node_modules\//,
  
  // Build outputs
  /^dist\//,
  /^build\//,
  /^out\//,
  /^target\//,
  /^\.next\//,
  /^\.nuxt\//,
  /^\.output\//,
  
  // Generated/minified
  /\.min\.(js|css)$/,
  /\.bundle\.(js|css)$/,
  /\.chunk\.(js|css)$/,
  /\.umd\.(js|cjs|mjs)$/,
  
  // Test fixtures/mocks (lower priority, not excluded)
  // /^test(s)?\/fixtures?\//,
  
  // IDE configs (except .vscode which we want)
  /^\.idea\//,
  
  // Coverage
  /^coverage\//,
  /^\.nyc_output\//,
  
  // Logs
  /^logs?\//,
  /\.log$/,
];

// ========== SCANNABLE EXTENSIONS ==========
const SCANNABLE_EXTENSIONS = new Set([
  // JavaScript/TypeScript
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  // Python
  '.py', '.pyw', '.pyx',
  // Ruby
  '.rb', '.rake', '.gemspec',
  // Go
  '.go',
  // Rust
  '.rs',
  // Shell
  '.sh', '.bash', '.zsh', '.fish',
  // Windows
  '.ps1', '.bat', '.cmd', '.vbs',
  // Config
  '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg',
  // Markup
  '.md', '.rst', '.txt',
  // Other
  '.php', '.pl', '.lua', '.r', '.swift', '.kt', '.java', '.cs', '.c', '.cpp', '.h',
]);

/**
 * Calculates priority score for a file
 * Higher score = higher priority for selection
 */
export function calculateFilePriority(entry: TreeEntry): { priority: number; reason: string } {
  const path = entry.path;
  const pathLower = path.toLowerCase();
  
  // Check exclusions first
  for (const pattern of EXCLUSION_PATTERNS) {
    if (pattern.test(path)) {
      return { priority: Priority.VENDOR, reason: 'Excluded directory' };
    }
  }
  
  // Check critical files (exact match)
  if (CRITICAL_FILES.includes(path) || CRITICAL_FILES.includes(pathLower)) {
    return { priority: Priority.CRITICAL, reason: 'Critical file' };
  }
  
  // Check high-signal patterns
  for (const { pattern, priority, reason } of HIGH_SIGNAL_PATTERNS) {
    if (pattern.test(path)) {
      return { priority, reason };
    }
  }
  
  // Check file extension
  const ext = '.' + path.split('.').pop()?.toLowerCase();
  if (!SCANNABLE_EXTENSIONS.has(ext)) {
    return { priority: Priority.VENDOR, reason: 'Non-scannable extension' };
  }
  
  // Root level files get bonus
  const depth = path.split('/').length - 1;
  if (depth === 0) {
    return { priority: Priority.MEDIUM, reason: 'Root level file' };
  }
  
  // Source directories
  if (/^src\//.test(path)) {
    return { priority: Priority.LOW + 20, reason: 'Source directory' };
  }
  if (/^lib\//.test(path)) {
    return { priority: Priority.LOW + 15, reason: 'Lib directory' };
  }
  
  // Default for scannable files
  return { priority: Priority.LOW, reason: 'Scannable file' };
}

/**
 * Main file selection algorithm
 * 
 * Algorithm:
 * 1. Calculate priority for each file
 * 2. Sort by priority (descending), then path (for determinism)
 * 3. Select files respecting limits (maxFiles, maxTotalBytes, maxPerFile)
 * 4. Always include CRITICAL priority files first
 * 
 * Time Complexity: O(n log n) for sorting
 * Space Complexity: O(n) for scored files array
 */
export function selectFiles(
  entries: TreeEntry[],
  options: {
    maxFiles?: number;
    maxTotalBytes?: number;
    maxPerFile?: number;
    enableTrace?: boolean;
  } = {}
): SelectionResult {
  const {
    maxFiles = MAX_FILES,
    maxTotalBytes = MAX_TOTAL_BYTES,
    maxPerFile = MAX_PER_FILE,
    enableTrace = true,
  } = options;

  const trace: SelectionTrace[] = [];
  
  // Filter to blobs only and calculate priorities
  const scoredFiles = entries
    .filter(e => e.type === 'blob')
    .map(entry => {
      const { priority, reason } = calculateFilePriority(entry);
      return { entry, priority, reason };
    });
  
  // Sort by priority (desc), then path (asc) for determinism
  scoredFiles.sort((a, b) => {
    if (b.priority !== a.priority) {
      return b.priority - a.priority;
    }
    return a.entry.path.localeCompare(b.entry.path);
  });
  
  const selected: TreeEntry[] = [];
  let totalBytes = 0;
  let skipped = 0;
  
  for (const { entry, priority, reason } of scoredFiles) {
    // Skip negative priority (excluded)
    if (priority < 0) {
      if (enableTrace) {
        trace.push({
          path: entry.path,
          priority,
          reason,
          selected: false,
          skippedReason: 'Excluded by pattern',
        });
      }
      skipped++;
      continue;
    }
    
    // Check file count limit
    if (selected.length >= maxFiles) {
      if (enableTrace) {
        trace.push({
          path: entry.path,
          priority,
          reason,
          selected: false,
          skippedReason: `File limit reached (${maxFiles})`,
        });
      }
      skipped++;
      continue;
    }
    
    // Check per-file size limit
    const fileSize = entry.size || 0;
    if (fileSize > maxPerFile) {
      if (enableTrace) {
        trace.push({
          path: entry.path,
          priority,
          reason,
          selected: false,
          skippedReason: `File too large (${fileSize} > ${maxPerFile})`,
        });
      }
      skipped++;
      continue;
    }
    
    // Check total bytes limit
    if (totalBytes + fileSize > maxTotalBytes) {
      if (enableTrace) {
        trace.push({
          path: entry.path,
          priority,
          reason,
          selected: false,
          skippedReason: `Total bytes limit reached`,
        });
      }
      skipped++;
      continue;
    }
    
    // Select the file
    selected.push(entry);
    totalBytes += fileSize;
    
    if (enableTrace) {
      trace.push({
        path: entry.path,
        priority,
        reason,
        selected: true,
      });
    }
  }
  
  return {
    files: selected,
    trace,
    stats: {
      totalConsidered: entries.filter(e => e.type === 'blob').length,
      selected: selected.length,
      skipped,
      truncatedFallback: false,
    },
  };
}

/**
 * Fallback list for when tree API is truncated or unavailable
 * These files are fetched directly by path
 */
export function getFallbackFiles(): string[] {
  return [
    // Always try these first
    ...CRITICAL_FILES,
    
    // Additional high-signal patterns to try
    '.github/workflows/ci.yml',
    '.github/workflows/ci.yaml',
    '.github/workflows/main.yml',
    '.github/workflows/main.yaml',
    '.github/workflows/build.yml',
    '.github/workflows/build.yaml',
    '.github/workflows/release.yml',
    '.github/workflows/publish.yml',
    '.github/workflows/deploy.yml',
    '.github/workflows/test.yml',
    
    // Common scripts
    'install.sh',
    'setup.sh',
    'bootstrap.sh',
    'scripts/install.sh',
    'scripts/setup.sh',
    'scripts/build.sh',
    
    // Windows
    'install.ps1',
    'setup.ps1',
    'install.bat',
    'setup.bat',
    
    // Entry points
    'index.js',
    'index.ts',
    'main.js',
    'main.ts',
    'app.js',
    'app.ts',
    'src/index.js',
    'src/index.ts',
    'src/main.js',
    'src/main.ts',
    
    // Python entry
    '__init__.py',
    'src/__init__.py',
    'main.py',
    'app.py',
  ];
}

/**
 * Log selection results for debugging
 */
export function logSelectionTrace(result: SelectionResult): void {
  console.group('📁 File Selection Results');
  console.log(`Total considered: ${result.stats.totalConsidered}`);
  console.log(`Selected: ${result.stats.selected}`);
  console.log(`Skipped: ${result.stats.skipped}`);
  console.log(`Truncated fallback: ${result.stats.truncatedFallback}`);
  
  console.group('Selected files by priority:');
  const grouped = new Map<string, string[]>();
  for (const t of result.trace.filter(t => t.selected)) {
    const key = `${t.priority} - ${t.reason}`;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)!.push(t.path);
  }
  for (const [key, files] of [...grouped.entries()].sort((a, b) => {
    const pa = parseInt(a[0]);
    const pb = parseInt(b[0]);
    return pb - pa;
  })) {
    console.log(`\n${key}:`);
    files.forEach(f => console.log(`  • ${f}`));
  }
  console.groupEnd();
  
  console.groupEnd();
}
