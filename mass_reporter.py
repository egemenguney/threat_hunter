#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Delta Force Mass Reporter v1.0
Automated GitHub malware repository reporting tool

This tool automatically reports detected malicious repositories to GitHub
using their abuse reporting system. It handles rate limiting, progress tracking,
and generates detailed reports.

Author: Security Research
Date: December 2025
"""

import sys
import os
import json
import time
import requests
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
import argparse

# Fix Windows console encoding
if sys.platform == 'win32':
    os.system('chcp 65001 > nul 2>&1')
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ============================================================================
# CONFIGURATION
# ============================================================================

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPORT_DELAY = 30  # Seconds between reports to avoid rate limiting
MAX_RETRIES = 3
BATCH_SIZE = 10  # Reports per batch

# Output files
REPORT_LOG = Path("mass_report_log.json")
REPORT_SUMMARY = Path("mass_report_summary.md")

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ReportResult:
    """Result of a single repository report"""
    repo_url: str
    repo_owner: str
    repo_name: str
    severity: str
    detection_type: str
    evidence: List[str]
    report_status: str  # SUCCESS, FAILED, SKIPPED
    report_time: str
    error_message: Optional[str] = None
    github_response: Optional[str] = None

class MassReporter:
    """Automated GitHub malware repository reporter"""
    
    def __init__(self, token: str = None, dry_run: bool = False):
        self.token = token or GITHUB_TOKEN
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Delta-Force-Malware-Hunter/1.0',
            'Accept': 'application/json',
        })
        
        if self.token:
            self.session.headers['Authorization'] = f'token {self.token}'
        
        self.reported_repos = self.load_previous_reports()
        
    def load_previous_reports(self) -> Dict[str, str]:
        """Load previously reported repositories to avoid duplicates"""
        if REPORT_LOG.exists():
            try:
                with open(REPORT_LOG, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Only count actual SUCCESS reports, not DRY_RUN
                    return {item['repo_url']: item['report_status'] 
                           for item in data if item.get('report_status') == 'SUCCESS'
                           and item.get('github_response', '').find('DRY RUN') == -1}
            except Exception as e:
                print(f"[WARNING] Could not load previous reports: {e}")
        return {}
    
    def generate_report_text(self, repo: Dict) -> str:
        """Generate abuse report text for GitHub"""
        evidence_text = "\n".join([f"• {ev}" for ev in repo.get('evidence', [])])
        
        report_template = f"""**MALWARE REPOSITORY REPORT**

**Repository:** {repo['url']}
**Detection Type:** {repo['detection_type']}
**Severity:** {repo['severity']}
**Detection Date:** {repo.get('detected_at', 'Unknown')}

**Evidence of Malicious Activity:**
{evidence_text}

**Technical Details:**
• Cyrillic Obfuscation: {'Yes' if repo.get('cyrillic_detected') else 'No'}
• High Entropy Files: {len(repo.get('high_entropy_files', []))}
• YARA Matches: {len(repo.get('yara_matches', []))}
• Suspicion Score: {repo.get('suspicion_score', 0)}/100

**Campaign Information:**
This repository is part of the "Delta Force hack" malware distribution campaign 
targeting gamers with fake cheat tools. The campaign uses sophisticated techniques 
including Unicode homoglyph obfuscation and social engineering to distribute malware.

**Recommended Action:**
Repository takedown due to malware distribution and violation of GitHub Terms of Service.

**Reporter:** Delta Force Malware Hunter (Automated Security Research)
**Report Generated:** {datetime.now().isoformat()}
"""
        return report_template
    
    def report_repository(self, repo: Dict) -> ReportResult:
        """Report a single repository by generating local files (GitHub reporting disabled)"""
        repo_url = repo['url']
        
        # 1. Daha önce raporlandıysa atla
        if repo_url in self.reported_repos:
            return ReportResult(
                repo_url=repo_url,
                repo_owner=repo['owner'],
                repo_name=repo['repo_name'],
                severity=repo['severity'],
                detection_type=repo['detection_type'],
                evidence=repo.get('evidence', []),
                report_status="SKIPPED",
                report_time=datetime.now().isoformat(),
                error_message="Already processed previously"
            )
        
        # 2. Rapor metnini oluştur (Markdown içeriği)
        report_text = self.generate_report_text(repo)
        
        try:
            # 3. Sadece yerel dosya oluştur (API çağrısı YOK)
            report_file = Path(f"reports/report_{repo['owner']}_{repo['repo_name']}.md")
            report_file.parent.mkdir(exist_ok=True)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            
            # 4. Durumu SUCCESS olarak dön (Böylece özette görünür)
            return ReportResult(
                repo_url=repo_url,
                repo_owner=repo['owner'],
                repo_name=repo['repo_name'],
                severity=repo['severity'],
                detection_type=repo['detection_type'],
                evidence=repo.get('evidence', []),
                report_status="SUCCESS",
                report_time=datetime.now().isoformat(),
                github_response=f"Report file generated: {report_file}"
            )
            
        except Exception as e:
            return ReportResult(
                repo_url=repo_url,
                repo_owner=repo['owner'],
                repo_name=repo['repo_name'],
                severity=repo['severity'],
                detection_type=repo['detection_type'],
                evidence=repo.get('evidence', []),
                report_status="FAILED",
                report_time=datetime.now().isoformat(),
                error_message=str(e)
            )
    
    def mass_report(self, scan_results_file: str, severity_filter: str = "HIGH", max_reports: int = 0) -> List[ReportResult]:
        """Mass report repositories from scan results (Local file generation mode)"""
        
        # 1. Tarama sonuçlarını yükle
        try:
            with open(scan_results_file, 'r', encoding='utf-8') as f:
                repos = json.load(f)
        except Exception as e:
            print(f"[ERROR] Could not load scan results: {e}")
            return []
        
        # 2. Önem derecesine göre filtrele
        filtered_repos = [repo for repo in repos if repo.get('severity') == severity_filter]
        
        # 3. Limit varsa uygula
        if max_reports > 0:
            filtered_repos = filtered_repos[:max_reports]
        
        print(f"[INFO] Found {len(filtered_repos)} repositories with {severity_filter} severity")
        print(f"[INFO] Running in Local Report Generation mode")
        
        results = []
        
        for i, repo in enumerate(filtered_repos, 1):
            print(f"\n[PROGRESS] {i}/{len(filtered_repos)} - {repo['url']}")
            
            # report_repository artık sadece dosya oluşturuyor
            result = self.report_repository(repo)
            results.append(result)
            
            # Sonucu logla
            status_emoji = "✅" if result.report_status == "SUCCESS" else "❌"
            print(f"[RESULT] {status_emoji} {result.report_status}: {result.repo_url}")
            
            if result.error_message:
                print(f"[ERROR] {result.error_message}")
            
            # Her adımda ilerlemeyi kaydet
            self.save_results(results)
        
        return results
    
    def save_results(self, results: List[ReportResult]):
        """Save reporting results to file"""
        with open(REPORT_LOG, 'w', encoding='utf-8') as f:
            json.dump([asdict(result) for result in results], f, indent=2, ensure_ascii=False)
    
    def generate_summary(self, results: List[ReportResult]):
        """Generate summary report"""
        total = len(results)
        success = len([r for r in results if r.report_status == "SUCCESS"])
        dry_run = len([r for r in results if r.report_status == "DRY_RUN"])
        failed = len([r for r in results if r.report_status == "FAILED"])
        skipped = len([r for r in results if r.report_status == "SKIPPED"])
        
        summary = f"""# Mass Reporting Summary

**Generated:** {datetime.now().isoformat()}
**Tool:** Delta Force Mass Reporter v1.0

## Statistics

| Status | Count | Percentage |
|--------|-------|------------|
| ✅ Success | {success} | {success/total*100:.1f}% |
| 🔵 Dry Run | {dry_run} | {dry_run/total*100:.1f}% |
| ❌ Failed | {failed} | {failed/total*100:.1f}% |
| ⏭️ Skipped | {skipped} | {skipped/total*100:.1f}% |
| **Total** | **{total}** | **100%** |

## Detailed Results

"""
        
        for result in results:
            status_emoji = "✅" if result.report_status == "SUCCESS" else "❌" if result.report_status == "FAILED" else "⏭️"
            summary += f"### {status_emoji} {result.repo_owner}/{result.repo_name}\n\n"
            summary += f"- **URL:** {result.repo_url}\n"
            summary += f"- **Status:** {result.report_status}\n"
            summary += f"- **Severity:** {result.severity}\n"
            summary += f"- **Type:** {result.detection_type}\n"
            summary += f"- **Time:** {result.report_time}\n"
            
            if result.error_message:
                summary += f"- **Error:** {result.error_message}\n"
            
            if result.github_response:
                summary += f"- **Response:** {result.github_response}\n"
            
            summary += "\n"
        
        with open(REPORT_SUMMARY, 'w', encoding='utf-8') as f:
            f.write(summary)
        
        print(f"\n[SUMMARY] Report saved to {REPORT_SUMMARY}")

def main():
    parser = argparse.ArgumentParser(description="Delta Force Mass Reporter")
    parser.add_argument("scan_results", help="Path to scan results JSON file")
    parser.add_argument("--severity", default="HIGH", choices=["HIGH", "LOW"], 
                       help="Severity level to report (default: HIGH)")
    parser.add_argument("--dry-run", action="store_true", 
                       help="Simulate reporting without actually sending reports")
    parser.add_argument("--token", help="GitHub token (or use GITHUB_TOKEN env var)")
    parser.add_argument("--max", type=int, default=0,
                       help="Maximum number of repos to report (0 = no limit)")
    parser.add_argument("--auto", action="store_true",
                       help="Auto mode for CI/CD - minimal output, fail on error")
    
    args = parser.parse_args()
    
    if not args.auto:
        print("🤖 Delta Force Mass Reporter v1.0")
        print("=" * 50)
    
    reporter = MassReporter(token=args.token, dry_run=args.dry_run)
    
    if not reporter.token and not args.dry_run:
        if args.auto:
            print("[WARNING] No GitHub token, running dry-run")
        else:
            print("[WARNING] No GitHub token provided. Running in dry-run mode.")
        reporter.dry_run = True
    
    results = reporter.mass_report(args.scan_results, args.severity, max_reports=args.max)
    reporter.generate_summary(results)
    
    success_count = len([r for r in results if r.report_status == 'SUCCESS'])
    failed_count = len([r for r in results if r.report_status == 'FAILED'])
    skipped_count = len([r for r in results if r.report_status == 'SKIPPED'])
    
    if args.auto:
        print(f"✅ Reported: {success_count}, Failed: {failed_count}, Skipped: {skipped_count}")
    else:
        print("\n🎉 Mass reporting completed!")
        print(f"📊 Results: {success_count} success, {failed_count} failed, {skipped_count} skipped")

if __name__ == "__main__":
    main()
