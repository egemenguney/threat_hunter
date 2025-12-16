# 🤖 Delta Force Mass Reporter Guide

Automated GitHub malware repository reporting tool for the Delta Force Malware Hunter project.

## 🎯 Features

- ✅ **Automated Reporting** - Mass report malicious repositories
- ✅ **Progress Tracking** - Resume from interruptions
- ✅ **Rate Limiting** - Respects GitHub's limits
- ✅ **Duplicate Prevention** - Avoids re-reporting
- ✅ **Detailed Logging** - Full audit trail
- ✅ **Dry Run Mode** - Test before actual reporting
- ✅ **Batch Processing** - Handles large datasets

## 🚀 Quick Start

### 1. Basic Usage

```bash
# Report all HIGH severity repositories (dry run)
python mass_reporter.py scan-results-archive-2025-12-16.json --dry-run

# Actual reporting (requires GitHub token)
python mass_reporter.py detected_repos.json --severity HIGH

# Report LOW severity repositories
python mass_reporter.py detected_repos.json --severity LOW
```

### 2. With Custom Token

```bash
python mass_reporter.py detected_repos.json --token ghp_your_token_here
```

### 3. Environment Setup

```bash
# Set GitHub token in environment
export GITHUB_TOKEN="ghp_your_token_here"

# Or create .env file
echo "GITHUB_TOKEN=ghp_your_token_here" > .env
```

## 📊 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `scan_results` | Path to JSON scan results file | Required |
| `--severity` | Severity level to report (HIGH/LOW) | HIGH |
| `--dry-run` | Simulate without actual reporting | False |
| `--token` | GitHub token (overrides env var) | None |

## 📁 Output Files

### Generated Reports
- `reports/report_{owner}_{repo}.md` - Individual repository reports
- `mass_report_log.json` - Detailed results log
- `mass_report_summary.md` - Human-readable summary

### Example Report Structure
```
reports/
├── report_pcyunus57_delta-force-tactical-enhancer.md
├── report_BananaCH836_Delta-Force-COV-V3.md
└── ...
```

## 🔧 Configuration

### Rate Limiting
```python
REPORT_DELAY = 30  # Seconds between reports
BATCH_SIZE = 10    # Reports per batch
MAX_RETRIES = 3    # Retry attempts
```

### Customization
Edit `mass_reporter.py` to modify:
- Report templates
- Rate limiting settings
- Output formats
- Error handling

## 📈 Usage Examples

### Example 1: Test Run
```bash
# Test with our archived results
python mass_reporter.py scan-results-archive-2025-12-16.zip --dry-run
```

### Example 2: Production Run
```bash
# Report HIGH severity repositories
python mass_reporter.py detected_repos.json --severity HIGH

# Check progress
tail -f mass_report_log.json
```

### Example 3: Resume Interrupted Run
```bash
# The tool automatically skips previously reported repositories
python mass_reporter.py detected_repos.json --severity HIGH
```

## 🛡️ Security Considerations

### Token Security
- ✅ Use environment variables for tokens
- ✅ Never commit tokens to Git
- ✅ Use minimal required permissions
- ✅ Rotate tokens regularly

### Rate Limiting
- ✅ Built-in delays between requests
- ✅ Respects GitHub's abuse reporting limits
- ✅ Automatic retry with backoff

### Data Privacy
- ✅ No sensitive data in logs
- ✅ Local file storage only
- ✅ Configurable output locations

## 🚨 Important Notes

### GitHub Reporting Process
This tool generates detailed abuse reports but **does not directly submit them to GitHub** due to API limitations. The generated reports should be:

1. **Manual Submission**: Copy report content to GitHub's abuse report form
2. **Email Integration**: Send reports to GitHub Security team
3. **API Integration**: Use when GitHub provides abuse reporting API

### Legal Compliance
- ✅ Only report actual malware
- ✅ Provide detailed evidence
- ✅ Follow responsible disclosure
- ✅ Respect GitHub's Terms of Service

## 🔍 Troubleshooting

### Common Issues

**"No GitHub token provided"**
```bash
export GITHUB_TOKEN="your_token_here"
```

**"Could not load scan results"**
```bash
# Check file path and format
python -c "import json; json.load(open('detected_repos.json'))"
```

**"Rate limit exceeded"**
```bash
# Increase delay in configuration
REPORT_DELAY = 60  # Increase to 60 seconds
```

### Debug Mode
```bash
# Enable verbose logging
python mass_reporter.py detected_repos.json --dry-run -v
```

## 📞 Support

For issues or questions:
1. Check this guide
2. Review error logs
3. Test with `--dry-run`
4. Check GitHub token permissions

## 🎯 Next Steps

After running the mass reporter:
1. Review generated reports in `reports/` directory
2. Check `mass_report_summary.md` for overview
3. Submit reports to GitHub manually or via email
4. Monitor repository takedown status
5. Update detection patterns based on results

---

**⚠️ Remember: This tool generates reports but requires manual submission to GitHub's abuse reporting system.**
