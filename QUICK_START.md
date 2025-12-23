# 🚀 Quick Start Guide - Threat Hunter

Quick reference guide for using Threat Hunter tools effectively.

## 📋 Table of Contents
- [Initial Setup](#initial-setup)
- [Daily Usage](#daily-usage)
- [Analyzing Results](#analyzing-results)
- [Reporting Threats](#reporting-threats)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## Initial Setup

### 1. Clone and Install
```bash
git clone https://github.com/egemenguney/threat_hunter.git
cd threat_hunter
pip install -r requirements.txt
```

### 2. Configure GitHub Token
```bash
# Linux/macOS
export GITHUB_TOKEN="ghp_your_token_here"

# Windows (PowerShell)
$env:GITHUB_TOKEN="ghp_your_token_here"

# Or create .env file
echo "GITHUB_TOKEN=ghp_your_token_here" > .env
```

### 3. Test Installation
```bash
python rate_limit_monitor.py
python threat_hunter.py --help
```

---

## Daily Usage

### Running a Full Scan
```bash
# Full scan with default settings
python threat_hunter.py

# Check a specific repository
python threat_hunter.py https://github.com/username/repo
```

### What Gets Generated?
- ✅ `detected_repos.json` - Machine-readable full results
- ✅ `detected_repos.csv` - Spreadsheet-friendly format
- ✅ `AUTO_GENERATED_REPORT.md` - Human-readable report
- ✅ `SUGGESTED_PATTERNS.txt` - New patterns to add to YARA rules

---

## Analyzing Results

### Quick Statistics
```bash
# Basic statistics
python analyze_detections.py

# Top 50 threats
python analyze_detections.py --top 50

# With false positive analysis
python analyze_detections.py --false-positive --verbose
```

### Understanding Scores

| Score Range | Severity | Action |
|-------------|----------|--------|
| 90-100 | 🔴 CRITICAL | Report immediately |
| 70-89 | 🔴 VERY HIGH | Report within 24h |
| 50-69 | 🟡 HIGH | Review and report |
| 30-49 | 🟡 MEDIUM | Monitor |
| 0-29 | 🟢 LOW | Track only |

### Detection Types Explained

- **YARA_MATCH**: Matched one or more YARA rules
- **CYRILLIC_OBFUSCATION**: Uses Cyrillic characters to hide filenames
- **PATTERN_MATCH**: README contains malicious patterns
- **HIGH_ENTROPY**: Encrypted/packed files detected
- **CRITICAL_INFRA**: Known C2 or malware infrastructure

---

## Reporting Threats

### Manual Reporting
For critical threats (score ≥90):
1. Review the detection in `detected_repos.json`
2. Verify it's a true positive
3. Report via: https://github.com/contact/report-abuse

### Bulk Reporting (Top Priority)
```bash
# Report top 50 critical threats
python mass_reporter.py --auto --max 50 --delay 60

# Dry run (no actual reporting)
python mass_reporter.py --dry-run --max 10
```

**See:** [MASS_REPORTER_GUIDE.md](MASS_REPORTER_GUIDE.md) for detailed instructions.

---

## Monitoring

### Rate Limit Status
```bash
# Quick check
python rate_limit_monitor.py

# Continuous monitoring (refresh every 60s)
python rate_limit_monitor.py --watch --interval 60
```

### Understanding Rate Limits

**Core API** (with token): 5000 requests/hour
- 🟢 Safe: >1000 remaining
- 🟡 Warning: 500-1000 remaining
- 🔴 Critical: <500 remaining

**Search API** (with token): 30 requests/minute
- 🟢 Safe: >10 remaining
- 🟡 Warning: 5-10 remaining
- 🔴 Critical: <5 remaining

### What to Do When Rate Limited?

1. **Wait for Reset**
   ```bash
   # Check time until reset
   python rate_limit_monitor.py
   ```

2. **Use DuckDuckGo Fallback**
   - Automatically activated when Search API is exhausted
   - Slower but doesn't count against GitHub limits

3. **Adjust Scanning Parameters**
   Edit `threat_hunter.py`:
   ```python
   SEARCH_CONCURRENT_LIMIT = 5  # Reduce to 3
   SEARCH_DELAY = 1.0           # Increase to 2.0
   ```

---

## Troubleshooting

### Common Issues

#### 1. "ModuleNotFoundError: No module named 'yara'"
```bash
pip install yara-python
```

#### 2. "Rate limit exceeded"
```bash
# Check status
python rate_limit_monitor.py

# Wait or use token
export GITHUB_TOKEN="ghp_your_token"
```

#### 3. "detected_repos.json not found"
```bash
# Run a scan first
python threat_hunter.py
```

#### 4. GitHub Actions workflow failing
Check workflow logs:
1. Go to Actions tab on GitHub
2. Click on failed workflow
3. Check "Run malware scan" step
4. Common fixes:
   - Verify `SCAN_TOKEN` secret is set
   - Check rate limits before scan
   - Ensure Python dependencies are installed

### Getting Help

1. **Check Documentation**
   - [README.md](README.md) - Main documentation
   - [MASS_REPORTER_GUIDE.md](MASS_REPORTER_GUIDE.md) - Reporting guide
   - [ANALYSIS_ISSUE_7.md](ANALYSIS_ISSUE_7.md) - Latest analysis

2. **Review Issues**
   - Check GitHub Issues for similar problems
   - Latest scan results in issues with 🚨 label

3. **Debug Mode**
   ```python
   # Add to threat_hunter.py temporarily
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

---

## Best Practices

### ✅ Do's
- ✅ Check rate limits before large scans
- ✅ Analyze results before mass reporting
- ✅ Update YARA rules with new patterns
- ✅ Verify critical threats manually
- ✅ Use automation for routine tasks

### ❌ Don'ts
- ❌ Don't run multiple scans simultaneously
- ❌ Don't report without verification
- ❌ Don't ignore rate limit warnings
- ❌ Don't skip false positive analysis
- ❌ Don't use tokens without proper scopes

---

## Workflow Example

### Daily Routine
```bash
# 1. Check rate limits
python rate_limit_monitor.py

# 2. Run scan (GitHub Actions does this automatically)
# python threat_hunter.py

# 3. Analyze results
python analyze_detections.py --top 20 --false-positive

# 4. Report critical threats
python mass_reporter.py --auto --max 20 --delay 60

# 5. Check final rate limits
python rate_limit_monitor.py
```

### Weekly Review
```bash
# 1. Analyze detection trends
python analyze_detections.py --top 100

# 2. Review false positives
python analyze_detections.py --false-positive --verbose > fp_review.txt

# 3. Update YARA rules if needed
# Edit rules.yar with new patterns from SUGGESTED_PATTERNS.txt

# 4. Check GitHub Issues
# Review automated issues for patterns
```

---

## 🎯 Quick Commands Cheat Sheet

```bash
# Scanning
python threat_hunter.py                              # Full scan
python threat_hunter.py https://github.com/...      # Single repo

# Analysis
python analyze_detections.py                         # Basic stats
python analyze_detections.py --top 50                # Top 50 threats
python analyze_detections.py --false-positive        # FP analysis

# Monitoring
python rate_limit_monitor.py                         # Rate limit check
python rate_limit_monitor.py --watch                 # Continuous watch
python rate_limit_monitor.py --json                  # JSON output

# Reporting
python mass_reporter.py --dry-run --max 10           # Test run
python mass_reporter.py --auto --max 50              # Report 50 repos
```

---

## 📚 Additional Resources

- **GitHub API Documentation**: https://docs.github.com/en/rest
- **YARA Documentation**: https://yara.readthedocs.io/
- **GitHub Abuse Reporting**: https://github.com/contact/report-abuse
- **Unicode Homoglyphs**: https://util.unicode.org/UnicodeJsps/confusables.jsp

---

**Last Updated:** 2025-12-23  
**Version:** 1.0
