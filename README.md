![Scan Before Clone Logo](https://raw.githubusercontent.com/myanpetra99/scan-before-clone/main/sbyc.svg)

# 🔍 Scan Before Clone

**Scan Before Clone** is a tool that helps you analyze public repositories **before cloning** them to your local machine.

Its purpose is to reduce the risk of downloading repositories that may contain **malicious or suspicious content**, such as harmful scripts, executables, or dangerous configuration files.

---

## 🚨 How It Works

Scan Before Clone uses a set of detection rules to identify potentially malicious files in a repository.

If suspicious patterns are detected, the tool will:

- ⚠️ Display a warning  
- 📂 Show you the flagged files  

You can then decide whether the repository is safe to clone.

---

## ⚠️ Limitations

Scan Before Clone currently uses **static analysis techniques**. This means:

- It may **not detect all malicious content**
- It may sometimes produce **false positives**

Always review flagged files carefully and use your own judgment.

---

## 🛠 Installation & Usage

Follow these steps to get started:

```bash
# 1. Clone the Scan Before Clone repository
git clone https://github.com/myanpetra99/scan-before-clone.git

# 2. Navigate into the project directory
cd scan-before-clone

# 3. Install dependencies
npm install

# 4. Run the tool
npm start
