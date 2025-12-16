# 🔍 Delta Force Malware Hunter

Automated GitHub malware repository detection tool targeting the "Delta Force hack" malware distribution campaign.

## 🎯 Features

- **Cyrillic Obfuscation Detection**: Detects Unicode homoglyph attacks (e.g., Cyrillic 'о' instead of Latin 'o')
- **README Pattern Analysis**: Identifies bot-generated content and social engineering tactics
- **Known Infrastructure Matching**: Checks against known C2 domains and payload hosts
- **Suspicion Scoring**: Calculates risk score based on multiple indicators
- **Automated Reporting**: Generates JSON, CSV, and Markdown reports

## 📊 Campaign Statistics

As of December 2025:
- **35+ malicious repositories** identified
- **20+ repos** using Cyrillic filename obfuscation
- **2 confirmed Trojans** (Wacatac.H!ml, Kepavll!rfn)
- **2 phishing sites** (GitHub Pages, Google Sites)

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/egemenguney/deltaforcemalwarehunter.git
cd deltaforcemalwarehunter

# Install dependencies
pip install -r requirements.txt

# Set your GitHub token (optional but recommended for higher rate limits)
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
```

## 🚀 Usage

### Quick Check Single Repository
```bash
python malware_hunter.py https://github.com/USERNAME/REPO
```

### Full Scan (All Delta Force Searches)
```bash
python malware_hunter.py
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

The `delta_force_malware.yar` file contains YARA rules for:
- Cyrillic obfuscation detection
- README social engineering patterns
- Known malicious infrastructure
- Payload characteristics

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

