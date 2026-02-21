# Scan Before Clone

![Scan Before Clone Logo](https://raw.githubusercontent.com/myanpetra99/scan-before-clone/main/sbyc.svg)

## Overview

Scan Before Clone is a tool that allows you to scan public repositories before cloning them. The purpose is to help you avoid cloning repositories that may contain malicious content such as suspicious scripts, executables, and configuration files.

## How It Works

The tool uses a set of rules to identify potentially malicious files. If it detects any suspicious patterns, it will provide you with a warning and information about the flagged files. You can then make an informed decision about whether to clone the repository or not.

## Important Disclaimers

⚠️ **Please note:**
- Scan Before Clone currently uses static analysis techniques, which means it may not detect all possible malicious files
- False positives are possible
- This tool is provided "as is" without any warranty
- The authors and contributors disclaim any liability for any damages or losses that may result from using this tool

## Getting Started

Follow these steps to use Scan Before Clone:

1. Clone the repository:
```bash
   git clone https://github.com/myanpetra99/scan-before-clone.git
```

2. Navigate to the directory:
```bash
   cd scan-before-clone
```

3. Install dependencies:
```bash
   npm install
```

4. Run the tool:
```bash
   npm start
```

## Roadmap

- [x] Add GitHub OAuth support
- [x] Support scanning private repositories
- [ ] Add support for other version control systems (GitLab, Bitbucket)
- [ ] AI integration to help identify malicious code

---

**⚠️ Always be careful when cloning repositories!**