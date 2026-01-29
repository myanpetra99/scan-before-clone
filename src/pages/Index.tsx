import { useEffect } from "react";
import { Shield, Eye, Zap, Lock } from "lucide-react";
import { ScanUrlInput } from "@/components/scanner/ScanUrlInput";
import { ScanProgress } from "@/components/scanner/ScanProgress";
import { ReportView } from "@/components/scanner/ReportView";
import { DetectionCategories } from "@/components/home/DetectionCategories";
import { GitHubTokenInput } from "@/components/scanner/GitHubTokenInput";
import { useScannerStatic } from "@/hooks/useScannerStatic";

const Index = () => {
  const {
    scan,
    report,
    isLoading,
    error,
    startScan,
    reset
  } = useScannerStatic();

  // Apply dark mode by default
  // useEffect(() => {
  //   document.documentElement.classList.add("dark");
  // }, []);
  const features = [{
    icon: Eye,
    title: "20+ Rules",
    description: "Detects install hooks, exfiltration, obfuscation, and CI/CD risks",
    rotate: "-2deg"
  }, {
    icon: Zap,
    title: "Instant",
    description: "No clone needed. Fetches high-signal files via API",
    rotate: "1deg"
  }, {
    icon: Lock,
    title: "Zero Execution",
    description: "Never runs repo code. Static analysis only. Stay safe",
    rotate: "-1deg"
  }];
  const handleScan = (url: string) => {
    startScan(url, "quick");
  };
  // Show states - improved error handling
  const hasError = error || scan?.status === "error";
  const showScanner = !scan || (scan.status === "error" && !isLoading);
  const showProgress = scan && (isLoading || scan.status === "running") && !report && !hasError;
  const showError = scan && hasError && !isLoading && !report;
  const showReport = report && !isLoading;
  return (
    <div className="min-h-screen bg-background relative overflow-x-hidden">
      <div className="fixed inset-0 bg-grid-pattern bg-grid opacity-[0.08] pointer-events-none" />

      <div className="fixed inset-0 bg-halftone bg-halftone opacity-20 pointer-events-none" />

      <div className="fixed top-0 left-0 w-1/4 h-full bg-speed-lines opacity-[0.06] pointer-events-none transform -skew-x-12" />

      <div className="fixed top-0 right-0 w-1/4 h-full bg-speed-lines opacity-[0.06] pointer-events-none transform skew-x-12" />

      <div className="fixed bottom-0 right-0 w-1/3 h-1/3 bg-crosshatch opacity-30 pointer-events-none" />

      <div className="relative pt-24">
        <header className="border-b-4 border-border backdrop-blur-sm bg-background/90 fixed top-0 left-0 right-0 z-50">
          <div className="container mx-auto px-4 py-4 flex items-center justify-between">
            <div className="flex items-center gap-3 group">
              <img src={`${import.meta.env.BASE_URL}sbyc.svg`} alt="SByC Logo" className="h-12 w-auto" />
            </div>  <h1 className="font-display text-2xl tracking-wider text-black">
                Scan Before You Clone
              </h1>
            </div>

            <div className="flex items-center gap-3">
              <GitHubTokenInput />
            </div>
          </div>
        </header>

        {showScanner && !showReport && (
          <section className="pt-20 pb-16 px-4 relative">
            <div className="container mx-auto text-center max-w-3xl">
              <h1 className="font-display text-6xl md:text-7xl lg:text-8xl mb-8 leading-none tracking-wider">
                <span className="block text-foreground manga-title">
                  Scan Before
                </span>
                <span
                  className="block text-primary manga-title transform rotate-1 mt-2"
                  style={{
                    textShadow:
                      "5px 5px 0 hsl(var(--comic-orange)), 10px 10px 0 hsl(var(--border))",
                  }}
                >
                  You Clone!
                </span>
              </h1>

              <div className="speech-bubble bg-card p-8 max-w-2xl mx-auto mb-14">
                <p className="text-xl text-muted-foreground handwritten leading-relaxed">
                  Analyze any public GitHub repo for
                  <span className="text-comic-orange font-bold">
                    {" "}
                    suspicious patterns
                  </span>
                  ,
                  <span className="text-comic-magenta font-bold">
                    {" "}
                    malicious scripts and files.
                  </span>
                  <span className="text-comic-cyan font-bold">
                    {" "}
                    Prevent any linkedin/upworks/etc scammers from accessing your data
                  </span>
                </p>
              </div>

              <div className="w-full max-w-2xl mx-auto">
                <ScanUrlInput onSubmit={handleScan} isLoading={isLoading} />
              </div>

              {error && (
                <div className="mt-8 p-5 bg-destructive/25 doodle-border border-destructive max-w-2xl mx-auto transform -rotate-1 animate-shake">
                  <p className="text-destructive font-display text-lg">
                    💥 {error}
                  </p>
                </div>
              )}
            </div>
          </section>
        )}

        {showProgress && (
          <section className="py-20 px-4">
            <div className="container mx-auto">
              <ScanProgress
                status={scan.status}
                progress={scan.progress}
                repoName={`${scan.repoOwner}/${scan.repoName}`}
                error={error || scan.error}
                onRetry={reset}
                activity={scan.activity}
              />
            </div>
          </section>
        )}

        {showError && (
          <section className="py-20 px-4">
            <div className="container mx-auto">
              <ScanProgress
                status="error"
                progress={scan.progress}
                repoName={`${scan.repoOwner}/${scan.repoName}`}
                error={error || scan.error}
                onRetry={reset}
              />
            </div>
          </section>
        )}

        {showReport && (
          <section className="py-10 px-4">
            <div className="container mx-auto">
              <ReportView report={report} onNewScan={reset} />
            </div>
          </section>
        )}

        {showScanner && !showReport && (
          <section className="py-16 px-4 relative">
            <div className="zigzag-divider absolute top-0 left-0 right-0" />

            <div className="container mx-auto max-w-3xl pt-8">
              <div className="comic-panel bg-card p-8">
                <div className="flex items-start gap-5">
                  <div className="p-3 doodle-border bg-secondary/20 transform rotate-6 flex-shrink-0">
                    <Lock className="w-8 h-8 text-secondary" />
                  </div>
                  <div>
                    <h3 className="font-display text-2xl mb-3 text-secondary tracking-wide">
                      Privacy First
                    </h3>
                    <p className="text-base text-muted-foreground handwritten leading-relaxed">
                      We only access{" "}
                      <span className="text-primary font-bold">
                        public repository data
                      </span>{" "}
                      through GitHub's API.
                      <span className="text-comic-cyan font-bold">
                        {" "}
                        No code is ever executed.
                      </span>{" "}
                      We fetch file contents for static analysis only. Your scan
                      results are private and temporary.
                    </p>
                  </div>
                </div>
              </div>

              <div className="comic-panel bg-card p-8 mt-8">
                <div className="flex items-start gap-5">
                  <div className="p-3 doodle-border bg-comic-yellow/20 transform -rotate-3 flex-shrink-0">
                    <Zap className="w-8 h-8 text-comic-yellow" />
                  </div>
                  <div>
                    <h3 className="font-display text-2xl mb-3 text-comic-yellow tracking-wide">
                      GitHub API Limits
                    </h3>
                    <p className="text-base text-muted-foreground handwritten leading-relaxed">
                      For larger repositories, you might hit GitHub's API rate
                      limits.
                      <span className="text-foreground font-bold">
                        {" "}
                        Tip:
                      </span>{" "}
                      Add your GitHub Personal Access Token in the top right
                      corner to increase your limits. We are working on GitHub
                      OAuth integration!
                    </p>
                  </div>
                </div>
              </div>

              <div className="comic-panel bg-card p-8 mt-8">
                <div className="flex items-start gap-5">
                  <div className="p-3 doodle-border bg-destructive/20 transform rotate-2 flex-shrink-0">
                    <Shield className="w-8 h-8 text-destructive" />
                  </div>
                  <div>
                    <h3 className="font-display text-2xl mb-3 text-destructive tracking-wide">
                      IMPORTANT
                    </h3>
                    <p className="text-base text-muted-foreground handwritten leading-relaxed">
                      This scanner uses pattern-based detection and may produce{" "}
                      <span className="text-foreground font-bold">
                        false positives
                      </span>
                      . Results should be verified by a human. It is designed to
                      give you a quick overview of potential risks
                      <span className="text-foreground font-bold">
                        {" "}
                        before
                      </span>{" "}
                      you clone a repository.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {showScanner && !showReport && (
          <section className="py-20 px-4 relative">
            <div className="zigzag-divider absolute top-0 left-0 right-0" />

            <div className="container mx-auto max-w-5xl pt-8">
              <h2 className="font-display text-4xl md:text-5xl text-center mb-16 text-primary manga-title">
                Features
              </h2>

              <div className="grid md:grid-cols-3 gap-8">
                {features.map((feature, index) => (
                  <div
                    key={index}
                    className="comic-panel text-center p-8 bg-card group"
                    style={{
                      transform: `rotate(${feature.rotate})`,
                    }}
                  >
                    <div className="inline-flex p-4 doodle-border bg-primary/20 mb-6 transform -rotate-6 group-hover:rotate-0 transition-transform">
                      <feature.icon className="w-10 h-10 text-primary" />
                    </div>

                    <h3 className="font-display text-2xl mb-3 text-foreground tracking-wider">
                      {feature.title}
                    </h3>

                    <p className="text-base text-muted-foreground handwritten">
                      {feature.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        {showScanner && !showReport && <DetectionCategories />}

        <footer className="py-10 px-4 relative bg-muted/40">
          <div className="zigzag-divider absolute top-0 left-0 right-0" />

          <div className="container mx-auto text-center pt-6">
            <p className="font-display text-2xl text-muted-foreground tracking-wide">
              Built for security-conscious developers
            </p>
            <p className="text-base text-muted-foreground mt-3 font-marker">
              Never run untrusted code
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
};
export default Index;