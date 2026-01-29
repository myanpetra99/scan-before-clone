import {
  Shield,
  Package,
  Eye,
  FileCode,
  GitBranch,
  Terminal,
  Cpu,
  Server,
  Lock,
  AlertTriangle,
  Bug,
  Skull,
  Bomb,
  Fingerprint,
  Cloud,
  Wallet,
  Code,
  Settings,
  Workflow,
  Container,
  Globe,
  Smartphone,
  Brain,
  Key,
  Layers,
} from "lucide-react";

interface DetectionCategory {
  icon: React.ElementType;
  title: string;
  description: string;
  examples: string[];
  color: string;
}

const categories: DetectionCategory[] = [
  {
    icon: Package,
    title: "Install Hook Hijacking",
    description: "Detects malicious preinstall/postinstall scripts in package managers",
    examples: ["npm preinstall", "pip setup.py", "Makefile tricks"],
    color: "text-comic-orange",
  },
  {
    icon: Skull,
    title: "Backdoors & Shells",
    description: "Identifies reverse shells, bind shells, and webshell patterns",
    examples: ["Bash reverse shells", "Netcat backdoors", "PHP webshells"],
    color: "text-destructive",
  },
  {
    icon: Eye,
    title: "Data Exfiltration",
    description: "Catches code that steals credentials, keys, and sensitive data",
    examples: ["SSH key theft", "Cloud creds", "Browser cookies"],
    color: "text-comic-magenta",
  },
  {
    icon: Key,
    title: "Secrets & Credentials",
    description: "Detects API keys, private keys, JWT tokens, and connection strings",
    examples: ["AWS keys", "RSA keys", "JWT tokens", "DB URIs"],
    color: "text-comic-yellow",
  },
  {
    icon: AlertTriangle,
    title: "Phishing & Scams",
    description: "Detects fake installers, Office macros, PII harvesting, and phishing forms",
    examples: ["Fake .exe", "VBA macros", "SSN forms", "Discord exfil"],
    color: "text-destructive",
  },
  {
    icon: Cpu,
    title: "Crypto Mining",
    description: "Finds hidden cryptocurrency miners in code",
    examples: ["Coinhive", "WebWorker miners", "WASM hashers"],
    color: "text-comic-cyan",
  },
  {
    icon: Code,
    title: "Obfuscation & Evasion",
    description: "Identifies code hiding techniques used by malware",
    examples: ["Multi-level Base64", "Homoglyphs", "Hex encoding"],
    color: "text-comic-purple",
  },
  {
    icon: Workflow,
    title: "CI/CD Pipeline Risks",
    description: "Audits GitHub Actions, GitLab CI, Drone, Woodpecker, Tekton & more",
    examples: ["Expression injection", "pull_request_target", "Secret leaks"],
    color: "text-comic-pink",
  },
  {
    icon: Settings,
    title: "IDE Auto-Execution",
    description: "Detects malicious configs in VS Code, JetBrains, Vim, Emacs, Cursor, Zed & Helix",
    examples: ["tasks.json", ".dir-locals.el", "vim modelines"],
    color: "text-comic-teal",
  },
  {
    icon: GitBranch,
    title: "Git Config Abuse",
    description: "Spots dangerous Git hooks, credential helpers, and URL rewrites",
    examples: ["Credential helpers", "core.hooksPath", "url.insteadOf"],
    color: "text-secondary",
  },
  {
    icon: Container,
    title: "Container & K8s Risks",
    description: "Detects privileged containers, Helm hooks, and Docker Compose issues",
    examples: ["privileged: true", "Docker socket", "SYS_ADMIN cap"],
    color: "text-comic-blue",
  },
  {
    icon: Cloud,
    title: "Serverless & Edge",
    description: "Identifies risks in AWS Lambda, Vercel, Netlify, and CloudFlare Workers",
    examples: ["Inline code", "Wildcard IAM", "Build injection"],
    color: "text-comic-sky",
  },
  {
    icon: Brain,
    title: "AI/ML Pipeline Risks",
    description: "Detects malicious pickle files, Jupyter notebooks, and model injection",
    examples: ["Pickle RCE", "Hidden cells", "trust_remote_code"],
    color: "text-comic-violet",
  },
  {
    icon: Globe,
    title: "Browser Extensions",
    description: "Analyzes extension manifests for dangerous permissions and patterns",
    examples: ["nativeMessaging", "Keyloggers", "Form capture"],
    color: "text-comic-emerald",
  },
  {
    icon: Smartphone,
    title: "Mobile Dev Risks",
    description: "Detects risks in Android Gradle, iOS Podfiles, React Native & Flutter",
    examples: ["Custom repos", "OTA updates", "Git deps"],
    color: "text-comic-rose",
  },
  {
    icon: Bug,
    title: "Pre-commit Poisoning",
    description: "Detects malicious pre-commit, Husky, and lint-staged configs",
    examples: ["Untrusted repos", "Local shell hooks", "Obfuscated commands"],
    color: "text-comic-lime",
  },
  {
    icon: Fingerprint,
    title: "Lockfile Attacks",
    description: "Identifies supply chain attacks via tampered lockfiles",
    examples: ["Custom registries", "Git patches", "Missing integrity"],
    color: "text-comic-indigo",
  },
  {
    icon: Layers,
    title: "DevContainer Hooks",
    description: "Identifies risky devcontainer.json lifecycle commands",
    examples: ["postCreateCommand", "Docker socket mount", "Root user"],
    color: "text-comic-amber",
  },
  {
    icon: Lock,
    title: "Repository Metadata",
    description: "Detects abuse of .mailmap, CODEOWNERS, Renovate, and git hooks",
    examples: ["Renovate exec", "Git hook exfil", "Dependabot abuse"],
    color: "text-primary",
  },
];

export function DetectionCategories() {
  return (
    <section className="py-20 px-4 relative">
      <div className="zigzag-divider absolute top-0 left-0 right-0" />

      <div className="container mx-auto max-w-6xl pt-8">
        <div className="text-center mb-12">
          <h2 className="font-display text-4xl md:text-5xl manga-title text-primary mb-4">
            What We Detect
          </h2>
          <p className="text-lg text-muted-foreground handwritten max-w-2xl mx-auto">
            Our scanner runs{" "}
            <span className="text-primary font-bold">
              160+ detection patterns
            </span>{" "}
            across
            <span className="text-primary font-bold"> 35 categories</span> to
            catch supply-chain attacks
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {categories.map((category, index) => (
            <div
              key={index}
              className="comic-panel bg-card p-4 group hover:scale-105 transition-transform duration-200"
              style={{
                transform: `rotate(${((index % 3) - 1) * 0.5}deg)`,
              }}
            >
              <div className="flex items-start gap-3">
                <div
                  className={`p-2 doodle-border bg-muted/50 ${category.color} transform -rotate-3 group-hover:rotate-0 transition-transform flex-shrink-0`}
                >
                  <category.icon className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="font-display text-sm tracking-wide text-foreground mb-1 truncate">
                    {category.title}
                  </h3>
                  <p className="text-xs text-muted-foreground mb-2 line-clamp-2">
                    {category.description}
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {category.examples.slice(0, 2).map((example, i) => (
                      <span
                        key={i}
                        className="text-[10px] px-1.5 py-0.5 bg-muted/80 border border-border text-muted-foreground font-mono"
                      >
                        {example}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
