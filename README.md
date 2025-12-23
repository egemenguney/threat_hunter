# 🔍 Threat Hunter

Automated GitHub malware repository detection tool targeting the known game hack malware distribution campaign.

## 🎯 Features

- **Cyrillic Obfuscation Detection**: Detects Unicode homoglyph attacks (e.g., Cyrillic 'о' instead of Latin 'o')
- **README Pattern Analysis**: Identifies bot-generated content and social engineering tactics
- **Known Infrastructure Matching**: Checks against known C2 domains and payload hosts
- **Suspicion Scoring**: Calculates risk score based on multiple indicators
- **Automated Reporting**: Generates JSON, CSV, and Markdown reports

## 📊 Campaign Statistics

As of December 2025:
- **1310+ malicious repositories** detected
- **1111 HIGH severity threats** in latest scan (Issue #7)
- **341 critical score (90-100)** repositories
- **Primary threat:** Delta Force game hack malware distribution
- **Detection methods:** YARA matching (76%), Pattern matching (14%), Cyrillic obfuscation (8%)
- **Automated daily scans** via GitHub Actions

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/egemenguney/threat_hunter.git
cd threat_hunter

# Install dependencies
pip install -r requirements.txt

# Set your GitHub token (optional but recommended for higher rate limits)
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
```

## 🚀 Usage

### Quick Check Single Repository
```bash
python threat_hunter.py https://github.com/USERNAME/REPO
```

### Full Scan (All Delta Force Searches)
```bash
python threat_hunter.py
```

### Monitor Rate Limits
```bash
# Check current rate limit status
python rate_limit_monitor.py

# Continuous monitoring
python rate_limit_monitor.py --watch

# JSON output
python rate_limit_monitor.py --json
```

### Analyze Detection Statistics
```bash
# Full analysis
python analyze_detections.py

# Show top 50 threats
python analyze_detections.py --top 50

# Identify potential false positives
python analyze_detections.py --false-positive --verbose
```

### Output Files
- `detected_repos.json` - Full detection data in JSON format
- `detected_repos.csv` - CSV for spreadsheet analysis
- `AUTO_GENERATED_REPORT.md` - Human-readable Markdown report

## 🔬 Detection Methods

### 1. Cyrillic Filename Obfuscation
Detects files like `Lоader.zip` where 'о' is Cyrillic (U+043E) instead of Latin 'o'.

```
Visual:     Lоader.zip
Actual:     L + U+043E + ader.zip
URL:        L%D0%BEader.zip
```

### 2. README Red Flags
- "Disable antivirus" instructions
- Fake "GitHub Verified" badges
- "VirusTotal Certified" claims
- Password hints (PASS: 1212)

### 3. Bot-Generated Indicators
- Excessive emoji usage
- "2025 Edition" claims
- MIT License for hack software
- SEO keyword spam

### 4. Known Infrastructure
- C2 domains: kiamatka.com, hanblga.com
- Image hosting: cheatseller.ru
- MediaFire folders: dmaaqrcqphy0d, hyewxkvve9m42

## 📝 YARA Rules

The `rules.yar` file contains YARA rules for:
- Cyrillic obfuscation detection
- README social engineering patterns
- Known malicious infrastructure
- Payload characteristics

## 🛠️ Additional Tools

### Rate Limit Monitor (`rate_limit_monitor.py`)
Monitor GitHub API rate limits in real-time to prevent workflow failures.

**Features:**
- Real-time rate limit checking for Core, Search, and GraphQL APIs
- Color-coded status indicators (🔴 Critical, 🟡 Warning, 🟢 Safe)
- Watch mode for continuous monitoring
- Time-until-reset calculations
- JSON output for automation

**Usage:**
```bash
# Quick check
python rate_limit_monitor.py

# Continuous monitoring (refresh every 30 seconds)
python rate_limit_monitor.py --watch --interval 30

# JSON output for scripts
python rate_limit_monitor.py --json
```

### Detection Statistics Analyzer (`analyze_detections.py`)
Comprehensive analysis of detection results with false positive identification.

**Features:**
- Severity and detection type distribution
- Score range analysis and percentiles
- Top threats by score
- Potential false positive identification
- Actionable recommendations

**Usage:**
```bash
# Full analysis
python analyze_detections.py

# Show top 50 threats
python analyze_detections.py --top 50

# False positive analysis with details
python analyze_detections.py --false-positive --verbose
```

### Mass Reporter (`mass_reporter.py`)
Automate GitHub abuse reporting for detected malicious repositories.

**See:** [MASS_REPORTER_GUIDE.md](MASS_REPORTER_GUIDE.md) for detailed usage instructions.

## ⚠️ Disclaimer

This tool is for security research and abuse reporting purposes only. 
Do not download or execute any malware samples.

## 📧 Reporting

Found malicious repos can be reported to:
- GitHub: https://github.com/contact/report-abuse
- Cloudflare: https://abuse.cloudflare.com
- MediaFire: https://www.mediafire.com/help/submit_abuse.php

## 📄 License

MIT License - See LICENSE file for details.

---

**Stay safe! 🛡️**

