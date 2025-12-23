#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
THREAT HUNTER PIPELINE v1.0
===========================
Tek komutla tüm analizi çalıştır:
  1. Repo tarama (threat_hunter sonuçlarını kullan)
  2. Clustering (github.io, index.html, script.js, zip, easylauncher)
  3. Deep analysis (her cluster için raw dosya analizi)
  4. Final rapor + mass report hazırlığı

Kullanım:
  python pipeline.py              # Tam pipeline
  python pipeline.py --stage 2    # Sadece clustering
  python pipeline.py --stage 3    # Sadece deep analysis
"""

import sys
import os
import json
import re
import httpx
import asyncio
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Set
from collections import defaultdict

# Windows console fix
if sys.platform == 'win32':
    os.system('chcp 65001 > nul 2>&1')
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

# Load .env.local if exists
env_file = Path('.env.local')
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()

# ============================================================================
# CONFIGURATION
# ============================================================================

GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
HEADERS = {'Authorization': f'token {GITHUB_TOKEN}'} if GITHUB_TOKEN else {}

# Malware indicators
MALWARE_DOMAINS = [
    'easylauncher.su',
    'easyio.live',           # YENİ KEŞİF - polopaa.github.io redirect
    'sites.google.com/view',
    'quotexapp.download',
    'filesilo.cloud',
    'meetingbooks.xyz',
    'mediafire.com',
    'mega.nz',
    'gofile.io',
    'anonfiles.com'
]

MALWARE_EXTENSIONS = ['.zip', '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.rar', '.7z']

# Output paths
OUTPUT_DIR = Path('pipeline_output')
CLUSTER_FILE = OUTPUT_DIR / 'clusters.json'
ANALYSIS_FILE = OUTPUT_DIR / 'deep_analysis.json'
REPORT_FILE = OUTPUT_DIR / 'FINAL_REPORT.md'
MASS_REPORT_FILE = OUTPUT_DIR / 'repos_to_report.json'


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class RepoCluster:
    """Kategorize edilmis repo"""
    url: str
    owner: str
    name: str
    severity: str
    categories: List[str] = field(default_factory=list)  # github_io, has_index, has_script, has_zip, easylauncher
    raw_files: Dict[str, str] = field(default_factory=dict)  # filename -> content
    malware_links: List[str] = field(default_factory=list)
    source_repo: Optional[str] = None
    source_files: List[str] = field(default_factory=list)
    analysis_notes: List[str] = field(default_factory=list)
    risk_score: int = 0


# ============================================================================
# STAGE 1: LOAD THREAT HUNTER RESULTS
# ============================================================================

def stage1_load_repos() -> List[Dict]:
    """threat_hunter.py sonuçlarını yükle"""
    
    print("\n" + "="*70)
    print("STAGE 1: LOADING THREAT HUNTER RESULTS")
    print("="*70)
    
    # Try different input files
    input_files = [
        'detected_repos.json',
        'malware_analysis/quick_analysis_async.json'
    ]
    
    repos = []
    for input_file in input_files:
        if Path(input_file).exists():
            print(f"[+] Loading: {input_file}")
            with open(input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle different formats
            if isinstance(data, list):
                repos = data
            elif isinstance(data, dict) and 'results' in data:
                repos = data['results']
            else:
                repos = list(data.values()) if isinstance(data, dict) else []
            
            break
    
    if not repos:
        print("[!] No input file found. Run threat_hunter.py first!")
        return []
    
    # Filter HIGH severity
    high_repos = [r for r in repos if r.get('severity') == 'HIGH']
    
    print(f"[+] Total repos: {len(repos)}")
    print(f"[+] HIGH severity: {len(high_repos)}")
    
    return high_repos


# ============================================================================
# STAGE 2: CLUSTERING
# ============================================================================

async def stage2_cluster_repos(repos: List[Dict], client: httpx.AsyncClient) -> List[RepoCluster]:
    """Repoları kategorilere ayır"""
    
    print("\n" + "="*70)
    print("STAGE 2: CLUSTERING REPOS")
    print("="*70)
    print(f"Analyzing {len(repos)} repos...")
    
    clusters = []
    semaphore = asyncio.Semaphore(20)  # Max 20 concurrent requests
    
    async def analyze_single(repo: Dict, index: int) -> RepoCluster:
        async with semaphore:
            url = repo.get('url', '')
            if not url:
                return None
            
            # Parse owner/name
            parts = url.rstrip('/').split('/')
            owner = parts[-2] if len(parts) >= 2 else ''
            name = parts[-1] if len(parts) >= 1 else ''
            
            cluster = RepoCluster(
                url=url,
                owner=owner,
                name=name,
                severity=repo.get('severity', 'UNKNOWN'),
                categories=[],
                raw_files={},
                malware_links=[],
                risk_score=repo.get('suspicion_score', 0) or repo.get('score', 0)
            )
            
            try:
                # 1. Get repo tree (all files)
                tree_url = f'https://api.github.com/repos/{owner}/{name}/git/trees/main?recursive=1'
                resp = await client.get(tree_url, headers=HEADERS, timeout=10)
                
                if resp.status_code == 200:
                    tree = resp.json()
                    files = [item['path'] for item in tree.get('tree', [])]
                    
                    # Categorize by file types
                    for f in files:
                        f_lower = f.lower()
                        if f_lower == 'index.html' or f_lower.endswith('/index.html'):
                            if 'has_index' not in cluster.categories:
                                cluster.categories.append('has_index')
                        
                        if 'script' in f_lower and f_lower.endswith('.js'):
                            if 'has_script' not in cluster.categories:
                                cluster.categories.append('has_script')
                        
                        if any(f_lower.endswith(ext) for ext in MALWARE_EXTENSIONS):
                            if 'has_zip' not in cluster.categories:
                                cluster.categories.append('has_zip')
                            cluster.analysis_notes.append(f"Malware file: {f}")
                
                # 2. Check README for patterns
                readme_url = f'https://raw.githubusercontent.com/{owner}/{name}/main/README.md'
                resp = await client.get(readme_url, timeout=10)
                
                if resp.status_code == 200:
                    readme = resp.text
                    cluster.raw_files['README.md'] = readme[:5000]  # First 5KB
                    
                    # Check for github.io links
                    if f'{owner}.github.io' in readme.lower():
                        cluster.categories.append('github_io')
                    
                    # Check for malware domains
                    for domain in MALWARE_DOMAINS:
                        pattern = rf'https?://[^\s\)\]\"\'<>]*{re.escape(domain)}[^\s\)\]\"\'<>]*'
                        matches = re.findall(pattern, readme, re.IGNORECASE)
                        if matches:
                            cluster.malware_links.extend(matches)
                            if 'easylauncher' in domain:
                                cluster.categories.append('easylauncher')
                            else:
                                cluster.categories.append('malware_link')
                
                # 3. Check if github.io source repo exists
                if 'github_io' in cluster.categories:
                    source_url = f'https://api.github.com/repos/{owner}/{owner}.github.io'
                    resp = await client.get(source_url, headers=HEADERS, timeout=10)
                    if resp.status_code == 200:
                        cluster.source_repo = f'https://github.com/{owner}/{owner}.github.io'
                        
                        # Get source repo files - try main first, then master
                        for branch in ['main', 'master']:
                            source_tree_url = f'https://api.github.com/repos/{owner}/{owner}.github.io/git/trees/{branch}?recursive=1'
                            resp2 = await client.get(source_tree_url, headers=HEADERS, timeout=10)
                            if resp2.status_code == 200:
                                source_tree = resp2.json()
                                files = [item['path'] for item in source_tree.get('tree', [])]
                                if files:
                                    cluster.source_files = files
                                    break
                
            except Exception as e:
                cluster.analysis_notes.append(f"Error: {str(e)[:50]}")
            
            # Progress indicator
            if index % 50 == 0:
                print(f"  [{index}/{len(repos)}] {owner}/{name} -> {cluster.categories}")
            
            return cluster
    
    # Run all analyses concurrently
    tasks = [analyze_single(repo, i) for i, repo in enumerate(repos, 1)]
    results = await asyncio.gather(*tasks)
    
    clusters = [c for c in results if c is not None]
    
    # Summary
    print(f"\n[+] Clustering complete!")
    print(f"    github_io: {sum(1 for c in clusters if 'github_io' in c.categories)}")
    print(f"    has_index: {sum(1 for c in clusters if 'has_index' in c.categories)}")
    print(f"    has_script: {sum(1 for c in clusters if 'has_script' in c.categories)}")
    print(f"    has_zip: {sum(1 for c in clusters if 'has_zip' in c.categories)}")
    print(f"    easylauncher: {sum(1 for c in clusters if 'easylauncher' in c.categories)}")
    print(f"    malware_link: {sum(1 for c in clusters if 'malware_link' in c.categories)}")
    print(f"    obfuscated_js: {sum(1 for c in clusters if 'obfuscated_js' in c.categories)}")
    print(f"    redirect: {sum(1 for c in clusters if 'redirect' in c.categories)}")
    
    return clusters


# ============================================================================
# STAGE 3: DEEP ANALYSIS
# ============================================================================

async def stage3_deep_analysis(clusters: List[RepoCluster], client: httpx.AsyncClient) -> List[RepoCluster]:
    """Her cluster için deep analysis yap"""
    
    print("\n" + "="*70)
    print("STAGE 3: DEEP ANALYSIS")
    print("="*70)
    
    semaphore = asyncio.Semaphore(10)  # Slower for deep analysis
    
    async def deep_analyze(cluster: RepoCluster, index: int) -> RepoCluster:
        async with semaphore:
            owner = cluster.owner
            name = cluster.name
            
            try:
                # A. Analyze index.html if exists
                if 'has_index' in cluster.categories:
                    index_url = f'https://raw.githubusercontent.com/{owner}/{name}/main/index.html'
                    resp = await client.get(index_url, timeout=10)
                    if resp.status_code == 200:
                        html = resp.text
                        cluster.raw_files['index.html'] = html[:10000]
                        
                        # Search for malware domains in HTML
                        for domain in MALWARE_DOMAINS:
                            pattern = rf'https?://[^\s\)\]\"\'<>]*{re.escape(domain)}[^\s\)\]\"\'<>]*'
                            matches = re.findall(pattern, html, re.IGNORECASE)
                            cluster.malware_links.extend(matches)
                        
                        # Check for suspicious redirects
                        redirect_patterns = [
                            r'window\.location\s*=\s*["\']([^"\']+)["\']',
                            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                            r'location\.replace\s*\(["\']([^"\']+)["\']\)',
                            r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*url=([^"\'>\s]+)'
                        ]
                        for pattern in redirect_patterns:
                            matches = re.findall(pattern, html, re.IGNORECASE)
                            for match in matches:
                                if any(d in match.lower() for d in MALWARE_DOMAINS):
                                    cluster.malware_links.append(match)
                                    cluster.analysis_notes.append(f"Redirect to: {match[:60]}")
                
                # B. Analyze script.js if exists
                if 'has_script' in cluster.categories:
                    for script_name in ['script.js', 'scripts.js', 'main.js', 'app.js']:
                        script_url = f'https://raw.githubusercontent.com/{owner}/{name}/main/{script_name}'
                        resp = await client.get(script_url, timeout=10)
                        if resp.status_code == 200:
                            js = resp.text
                            cluster.raw_files[script_name] = js[:10000]
                            
                            # Search for malware domains in JS
                            for domain in MALWARE_DOMAINS:
                                pattern = rf'https?://[^\s\)\]\"\'<>]*{re.escape(domain)}[^\s\)\]\"\'<>]*'
                                matches = re.findall(pattern, js, re.IGNORECASE)
                                cluster.malware_links.extend(matches)
                            
                            break  # Found one script, stop
                
                # C. Analyze github.io source repo - KRITIK ADIM!
                if cluster.source_repo:
                    source_owner = cluster.owner
                    source_name = f'{cluster.owner}.github.io'
                    
                    # If source_files empty, try to get them now
                    if not cluster.source_files:
                        for branch in ['main', 'master']:
                            source_tree_url = f'https://api.github.com/repos/{source_owner}/{source_name}/git/trees/{branch}?recursive=1'
                            resp = await client.get(source_tree_url, headers=HEADERS, timeout=10)
                            if resp.status_code == 200:
                                source_tree = resp.json()
                                files = [item['path'] for item in source_tree.get('tree', [])]
                                if files:
                                    cluster.source_files = files
                                    break
                    
                    # Check source index.html
                    if 'index.html' in cluster.source_files or not cluster.source_files:
                        # Try to read index.html even if source_files is empty
                        for branch in ['main', 'master']:
                            src_index_url = f'https://raw.githubusercontent.com/{source_owner}/{source_name}/{branch}/index.html'
                            resp = await client.get(src_index_url, timeout=10)
                            if resp.status_code == 200:
                                html = resp.text
                                html_size = len(html)
                                cluster.raw_files['source_index.html'] = html[:10000]
                                
                                # OBFUSCATED JS DETECTION (277KB pattern)
                                if html_size > 100000:  # 100KB+ = obfuscated
                                    if 'obfuscated_js' not in cluster.categories:
                                        cluster.categories.append('obfuscated_js')
                                    cluster.analysis_notes.append(f"OBFUSCATED: index.html {html_size} bytes")
                                
                                # Check for Function() obfuscation pattern
                                if 'Function("' in html or "Function('" in html:
                                    if 'obfuscated_js' not in cluster.categories:
                                        cluster.categories.append('obfuscated_js')
                                    cluster.analysis_notes.append("OBFUSCATED: Function() pattern detected")
                                
                                # Check for eval() pattern
                                if 'eval(' in html.lower():
                                    if 'obfuscated_js' not in cluster.categories:
                                        cluster.categories.append('obfuscated_js')
                                    cluster.analysis_notes.append("OBFUSCATED: eval() pattern detected")
                                
                                # REDIRECT DETECTION (easyio.live pattern)
                                redirect_patterns = [
                                    (r'window\.location\.replace\s*\(["\']([^"\']+)["\']\)', 'location.replace'),
                                    (r'window\.location\s*=\s*["\']([^"\']+)["\']', 'window.location'),
                                    (r'window\.location\.href\s*=\s*["\']([^"\']+)["\']', 'location.href'),
                                    (r'setTimeout\s*\([^)]*location[^)]*\)', 'setTimeout redirect'),
                                    (r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*url=([^"\'>\s]+)', 'meta refresh')
                                ]
                                for pattern, ptype in redirect_patterns:
                                    matches = re.findall(pattern, html, re.IGNORECASE)
                                    for match in matches:
                                        if isinstance(match, str) and match.startswith('http'):
                                            cluster.malware_links.append(match)
                                            cluster.analysis_notes.append(f"REDIRECT ({ptype}): {match[:60]}")
                                            if 'redirect' not in cluster.categories:
                                                cluster.categories.append('redirect')
                                
                                # Search for malware domains
                                for domain in MALWARE_DOMAINS:
                                    pattern = rf'https?://[^\s\)\]\"\'<>]*{re.escape(domain)}[^\s\)\]\"\'<>]*'
                                    matches = re.findall(pattern, html, re.IGNORECASE)
                                    cluster.malware_links.extend(matches)
                                
                                # ATOB DECODE - base64 hidden URLs
                                atob_pattern = r'atob\s*\(["\']([A-Za-z0-9+/=]+)["\']\)'
                                atob_matches = re.findall(atob_pattern, html)
                                for b64 in atob_matches:
                                    try:
                                        import base64
                                        decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                                        if decoded.startswith('http'):
                                            cluster.malware_links.append(decoded)
                                            cluster.analysis_notes.append(f"BASE64 DECODED: {decoded[:60]}")
                                    except:
                                        pass
                                
                                break  # Found index.html, stop trying branches
                    
                    # Check source scripts
                    for f in cluster.source_files:
                        if f.endswith('.js') and 'script' in f.lower():
                            for branch in ['main', 'master']:
                                src_js_url = f'https://raw.githubusercontent.com/{source_owner}/{source_name}/{branch}/{f}'
                                resp = await client.get(src_js_url, timeout=10)
                                if resp.status_code == 200:
                                    js = resp.text
                                    cluster.raw_files[f'source_{f}'] = js[:10000]
                                    
                                    # Check obfuscation in JS files too
                                    if len(js) > 50000:
                                        if 'obfuscated_js' not in cluster.categories:
                                            cluster.categories.append('obfuscated_js')
                                        cluster.analysis_notes.append(f"OBFUSCATED JS: {f} ({len(js)} bytes)")
                                    
                                    for domain in MALWARE_DOMAINS:
                                        pattern = rf'https?://[^\s\)\]\"\'<>]*{re.escape(domain)}[^\s\)\]\"\'<>]*'
                                        matches = re.findall(pattern, js, re.IGNORECASE)
                                        cluster.malware_links.extend(matches)
                                    break
                            break
                
                # Deduplicate malware links
                cluster.malware_links = list(set(cluster.malware_links))
                
                # Calculate risk score
                cluster.risk_score = calculate_risk_score(cluster)
                
            except Exception as e:
                cluster.analysis_notes.append(f"Deep analysis error: {str(e)[:50]}")
            
            # Progress
            if index % 25 == 0:
                print(f"  [{index}] {owner}/{name} -> {len(cluster.malware_links)} malware links")
            
            return cluster
    
    # Run deep analysis on repos with interesting categories
    interesting = [c for c in clusters if c.categories]
    print(f"Deep analyzing {len(interesting)} repos with categories...")
    
    tasks = [deep_analyze(c, i) for i, c in enumerate(interesting, 1)]
    results = await asyncio.gather(*tasks)
    
    # Merge back
    interesting_urls = {c.url for c in interesting}
    final = results + [c for c in clusters if c.url not in interesting_urls]
    
    # Sort by risk score
    final.sort(key=lambda x: x.risk_score, reverse=True)
    
    print(f"\n[+] Deep analysis complete!")
    print(f"    With malware links: {sum(1 for c in final if c.malware_links)}")
    print(f"    With obfuscated JS: {sum(1 for c in final if 'obfuscated_js' in c.categories)}")
    print(f"    With redirects: {sum(1 for c in final if 'redirect' in c.categories)}")
    
    return final


def calculate_risk_score(cluster: RepoCluster) -> int:
    """Risk skoru hesapla"""
    score = cluster.risk_score or 0
    
    # Category bonuses
    if 'easylauncher' in cluster.categories:
        score += 50
    if 'obfuscated_js' in cluster.categories:
        score += 40  # YENİ: Obfuscated JS = çok şüpheli
    if 'redirect' in cluster.categories:
        score += 35  # YENİ: Redirect pattern
    if 'has_zip' in cluster.categories:
        score += 30
    if 'github_io' in cluster.categories and cluster.source_repo:
        score += 20
    if 'has_index' in cluster.categories:
        score += 10
    if 'has_script' in cluster.categories:
        score += 10
    
    # Malware link bonuses
    score += len(cluster.malware_links) * 15
    
    # Cap at 100
    return min(score, 100)


# ============================================================================
# STAGE 4: GENERATE REPORTS
# ============================================================================

def stage4_generate_reports(clusters: List[RepoCluster]):
    """Final rapor ve mass report dosyası oluştur"""
    
    print("\n" + "="*70)
    print("STAGE 4: GENERATING REPORTS")
    print("="*70)
    
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    # 1. Save clusters JSON
    clusters_data = [asdict(c) for c in clusters]
    with open(CLUSTER_FILE, 'w', encoding='utf-8') as f:
        json.dump(clusters_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved: {CLUSTER_FILE}")
    
    # 2. Generate final report
    report = generate_markdown_report(clusters)
    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"[+] Saved: {REPORT_FILE}")
    
    # 3. Generate mass report JSON (repos to report)
    to_report = []
    for c in clusters:
        # YENİ: obfuscated_js ve redirect de raporlanacak
        if (c.malware_links or 'easylauncher' in c.categories or 'has_zip' in c.categories 
            or 'obfuscated_js' in c.categories or 'redirect' in c.categories):
            to_report.append({
                'url': c.url,
                'owner': c.owner,
                'repo_name': c.name,
                'severity': 'CRITICAL' if c.risk_score >= 80 else 'HIGH' if c.risk_score >= 50 else 'MEDIUM',
                'detection_type': ', '.join(set(c.categories)),
                'evidence': c.malware_links[:5] + c.analysis_notes[:5],
                'risk_score': c.risk_score
            })
    
    with open(MASS_REPORT_FILE, 'w', encoding='utf-8') as f:
        json.dump(to_report, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved: {MASS_REPORT_FILE} ({len(to_report)} repos)")
    
    # 4. Print summary
    print(f"\n" + "="*70)
    print("PIPELINE COMPLETE!")
    print("="*70)
    print(f"Total repos analyzed: {len(clusters)}")
    print(f"Repos to report: {len(to_report)}")
    print(f"\nTop 10 most dangerous:")
    for i, c in enumerate(clusters[:10], 1):
        print(f"  {i}. [{c.risk_score}] {c.owner}/{c.name}")
        if c.malware_links:
            print(f"      -> {c.malware_links[0][:60]}")


def generate_markdown_report(clusters: List[RepoCluster]) -> str:
    """Markdown formatında rapor oluştur"""
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    
    # Statistics
    total = len(clusters)
    with_malware = sum(1 for c in clusters if c.malware_links)
    easylauncher_count = sum(1 for c in clusters if 'easylauncher' in c.categories)
    github_io_count = sum(1 for c in clusters if 'github_io' in c.categories)
    has_zip_count = sum(1 for c in clusters if 'has_zip' in c.categories)
    has_index_count = sum(1 for c in clusters if 'has_index' in c.categories)
    has_script_count = sum(1 for c in clusters if 'has_script' in c.categories)
    obfuscated_count = sum(1 for c in clusters if 'obfuscated_js' in c.categories)
    redirect_count = sum(1 for c in clusters if 'redirect' in c.categories)
    
    # Collect all unique malware domains
    all_domains = set()
    for c in clusters:
        for link in c.malware_links:
            for domain in MALWARE_DOMAINS:
                if domain in link.lower():
                    all_domains.add(domain)
    
    report = f"""# THREAT HUNTER FINAL REPORT
Generated: {now}

## EXECUTIVE SUMMARY

| Metric | Count |
|--------|-------|
| Total Repos Analyzed | {total} |
| With Malware Links | {with_malware} |
| easylauncher.su | {easylauncher_count} |
| github.io Pattern | {github_io_count} |
| Direct Malware Files | {has_zip_count} |
| Obfuscated JS | {obfuscated_count} |
| Redirect Pattern | {redirect_count} |
| index.html Present | {has_index_count} |
| script.js Present | {has_script_count} |

## MALWARE DOMAINS DETECTED

"""
    for domain in sorted(all_domains):
        count = sum(1 for c in clusters if any(domain in link.lower() for link in c.malware_links))
        report += f"- **{domain}**: {count} repos\n"
    
    report += f"""

## CLUSTER BREAKDOWN

### 1. EASYLAUNCHER.SU ({easylauncher_count} repos)
*Hidden malware links in badge images*

"""
    for c in clusters:
        if 'easylauncher' in c.categories:
            report += f"- [{c.owner}/{c.name}]({c.url}) - Score: {c.risk_score}\n"
            for link in c.malware_links[:2]:
                report += f"  - `{link}`\n"
    
    report += f"""

### 2. GITHUB.IO WITH SOURCE ({sum(1 for c in clusters if c.source_repo)} repos)
*Has github.io source repository*

"""
    for c in clusters:
        if c.source_repo:
            report += f"- [{c.owner}/{c.name}]({c.url})\n"
            report += f"  - Source: [{c.owner}.github.io]({c.source_repo})\n"
            if c.source_files:
                report += f"  - Files: {', '.join(c.source_files[:5])}\n"
    
    report += f"""

### 3. DIRECT MALWARE FILES ({has_zip_count} repos)
*Contains .zip, .exe, .dll or similar*

"""
    for c in clusters:
        if 'has_zip' in c.categories:
            report += f"- [{c.owner}/{c.name}]({c.url})\n"
            for note in c.analysis_notes:
                if 'Malware file' in note:
                    report += f"  - {note}\n"
    
    report += f"""

### 4. OBFUSCATED JS ({obfuscated_count} repos)
*Contains heavily obfuscated JavaScript (100KB+ or Function()/eval() patterns)*

"""
    for c in clusters:
        if 'obfuscated_js' in c.categories:
            report += f"- [{c.owner}/{c.name}]({c.url}) - Score: {c.risk_score}\n"
            for note in c.analysis_notes:
                if 'OBFUSCATED' in note:
                    report += f"  - {note}\n"
    
    report += f"""

### 5. REDIRECT PATTERNS ({redirect_count} repos)
*Contains JavaScript redirect to malware sites*

"""
    for c in clusters:
        if 'redirect' in c.categories:
            report += f"- [{c.owner}/{c.name}]({c.url}) - Score: {c.risk_score}\n"
            for note in c.analysis_notes:
                if 'REDIRECT' in note or 'BASE64' in note:
                    report += f"  - {note}\n"
    
    report += f"""

### 6. OTHER MALWARE LINKS ({with_malware - easylauncher_count} repos)
*Contains links to known malware domains*

"""
    for c in clusters:
        if c.malware_links and 'easylauncher' not in c.categories:
            report += f"- [{c.owner}/{c.name}]({c.url})\n"
            for link in c.malware_links[:3]:
                report += f"  - `{link}`\n"
    
    report += f"""

## TOP 20 MOST DANGEROUS

| Rank | Repo | Score | Categories | Malware Links |
|------|------|-------|------------|---------------|
"""
    for i, c in enumerate(clusters[:20], 1):
        cats = ', '.join(set(c.categories)) if c.categories else '-'
        links = len(c.malware_links)
        report += f"| {i} | [{c.owner}/{c.name}]({c.url}) | {c.risk_score} | {cats} | {links} |\n"
    
    report += f"""

## RECOMMENDED ACTIONS

1. **CRITICAL**: Report all easylauncher.su repos ({easylauncher_count})
2. **CRITICAL**: Report repos with obfuscated JS ({obfuscated_count})
3. **HIGH**: Report repos with redirect patterns ({redirect_count})
4. **HIGH**: Report repos with direct malware files ({has_zip_count})
5. **MEDIUM**: Report repos with other malware links ({with_malware - easylauncher_count})
6. **INVESTIGATE**: github.io source repos for hidden content

## FILES GENERATED

- `clusters.json` - All clustered repos with categories
- `repos_to_report.json` - Repos ready for mass reporting
- `FINAL_REPORT.md` - This report

---
*Report generated by Threat Hunter Pipeline v2.0*
"""
    
    return report


# ============================================================================
# MAIN PIPELINE
# ============================================================================

async def run_pipeline(start_stage: int = 1):
    """Run the complete pipeline"""
    
    print("\n" + "="*70)
    print("  THREAT HUNTER PIPELINE v1.0")
    print("="*70)
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    clusters = []
    
    async with httpx.AsyncClient() as client:
        
        # Stage 1: Load repos
        if start_stage <= 1:
            repos = stage1_load_repos()
            if not repos:
                print("[!] No repos to analyze. Exiting.")
                return
        else:
            # Load from previous run
            if CLUSTER_FILE.exists():
                with open(CLUSTER_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                clusters = [RepoCluster(**d) for d in data]
                print(f"[+] Loaded {len(clusters)} clusters from previous run")
            else:
                print("[!] No previous clusters found. Starting from stage 1.")
                repos = stage1_load_repos()
        
        # Stage 2: Clustering
        if start_stage <= 2 and not clusters:
            clusters = await stage2_cluster_repos(repos, client)
        
        # Stage 3: Deep analysis
        if start_stage <= 3:
            clusters = await stage3_deep_analysis(clusters, client)
        
        # Stage 4: Generate reports
        stage4_generate_reports(clusters)
    
    print(f"\n  Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Threat Hunter Pipeline')
    parser.add_argument('--stage', type=int, default=1, help='Start from stage (1-4)')
    args = parser.parse_args()
    
    asyncio.run(run_pipeline(start_stage=args.stage))


if __name__ == '__main__':
    main()
