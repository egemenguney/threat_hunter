#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Delta Force Malware Hunter v2.0
Automated GitHub malware repository detection tool

Features:
- Cyrillic filename obfuscation detection
- High entropy file detection (encrypted/packed payloads)
- YARA rule matching
- README pattern analysis
- Known infrastructure matching
- PyGithub integration

Author: Security Research
Date: December 2025
"""

import sys
import os
import math

# Fix Windows console encoding
if sys.platform == 'win32':
    os.system('chcp 65001 > nul 2>&1')
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import re
import json
import csv
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict, field
import base64

# PyGithub for better API handling
try:
    from github import Github, GithubException, RateLimitExceededException
    PYGITHUB_AVAILABLE = True
except ImportError:
    PYGITHUB_AVAILABLE = False
    import requests

# YARA for signature matching
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# ============================================================================
# CONFIGURATION
# ============================================================================

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_API = "https://api.github.com"
REQUEST_DELAY = 2

# Output files
OUTPUT_DIR = Path(".")
RESULTS_JSON = OUTPUT_DIR / "detected_repos.json"
RESULTS_CSV = OUTPUT_DIR / "detected_repos.csv"
REPORT_MD = OUTPUT_DIR / "AUTO_GENERATED_REPORT.md"
YARA_RULES_FILE = OUTPUT_DIR / "rules.yar"

# Entropy threshold for detecting encrypted/packed content
ENTROPY_THRESHOLD = 7.0  # Max is 8.0, >7.0 = likely encrypted

# ============================================================================
# DETECTION PATTERNS
# ============================================================================

CYRILLIC_PATTERNS = {
    'о': 'o',  # U+043E
    'а': 'a',  # U+0430
    'е': 'e',  # U+0435
    'р': 'p',  # U+0440
    'с': 'c',  # U+0441
    'х': 'x',  # U+0445
    'і': 'i',  # U+0456
    'у': 'y',  # U+0443
}

# Dynamic year-aware red flags
def get_dynamic_red_flags():
    """Generate red flags including current year patterns"""
    current_year = datetime.now().year
    base_years = [2023, 2024, 2025]
    
    # Add current year if newer
    if current_year > max(base_years) and current_year not in base_years:
        base_years.append(current_year)
    
    # Year-based suspicious patterns
    year_red_flags = []
    for year in base_years:
        year_red_flags.extend([
            rf'Delta.*Force.*{year}',
            rf'{year}.*hack.*tool',
            rf'latest.*{year}.*version',
            rf'{year}.*cracked',
        ])
    
    return year_red_flags

README_RED_FLAGS = [
    r'disable.*antivirus',
    r'turn off.*antivirus',
    r'disable.*defender',
    r'disable.*av',
    r'antivirus.*interference',
    r'PASS\s*[-:=]\s*\d+',
    r'anti[- ]?ban',
    r'undetected',
    r'bypass.*detection',
    r'stealth\s*mode',
    r'GITHUB\s*VERIF[IY]ED',
    r'VirusTotal\s*Certified',
] + get_dynamic_red_flags()

# Dynamic year detection - automatically includes current and recent years
def get_dynamic_year_patterns():
    """Generate year patterns for current and recent years"""
    current_year = datetime.now().year
    # Base years we always check (last 3 years minimum)
    base_years = [2023, 2024, 2025]
    
    # Add current year if it's newer than our base list
    if current_year > max(base_years) and current_year not in base_years:
        base_years.append(current_year)
    
    # Generate patterns for each year
    year_patterns = []
    for year in base_years:
        year_patterns.extend([
            rf'{year}.*Edition',
            rf'Windows\s*{year}',
            rf'{year}.*Version',
            rf'Updated.*{year}',
        ])
    
    return year_patterns

BOT_INDICATORS = [
    r'🚀.*🔥.*💥',
    r'MIT\s*License.*hack',
    r'educational.*purposes.*only',
    r'SEO.*Keywords?:',
] + get_dynamic_year_patterns()

MALICIOUS_DOMAINS = [
    'kiamatka.com',
    'hanblga.com',
    'cheatseller.ru',
    'get-hacks.xyz',
]

MALICIOUS_MEDIAFIRE = [
    'dmaaqrcqphy0d',
    'hyewxkvve9m42',
]

SEARCH_QUERIES = [
    'delta force hack',
    'delta force cheat',
    'delta force aimbot',
    'delta force loader',
    'delta force trainer',
    'delta force esp',
    'delta force wallhack',
    'deltaforce hack',
    'DeltaForce-Hack',
    'delta-force-hack',
]

# Exclude our own repos from detection (false positives)
EXCLUDED_REPOS = [
    'egemenguney/deltaforcemalwarehunter',
    'egemenguney/Delta-Force-Hacker',
]

SUSPICIOUS_EXTENSIONS = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class DetectedRepo:
    """Represents a detected malicious repository"""
    url: str
    owner: str
    repo_name: str
    detection_type: str
    severity: str
    evidence: List[str]
    detected_at: str
    cyrillic_detected: bool = False
    high_entropy_files: List[str] = field(default_factory=list)
    yara_matches: List[str] = field(default_factory=list)
    readme_flags: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    suspicion_score: int = 0
    report_status: str = "PENDING"

# ============================================================================
# ENTROPY DETECTION
# ============================================================================

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data
    Returns: 0.0-8.0 (higher = more random/encrypted)
    """
    if not data:
        return 0.0
    
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    
    entropy = 0.0
    data_len = len(data)
    
    for f in freq:
        if f > 0:
            p = f / data_len
            entropy -= p * math.log2(p)
    
    return entropy

def analyze_file_entropy(content: bytes, filename: str) -> Tuple[bool, float, str]:
    """
    Analyze file content for high entropy (encrypted/packed)
    Returns: (is_suspicious, entropy_value, description)
    """
    entropy = calculate_entropy(content)
    
    if entropy >= ENTROPY_THRESHOLD:
        return True, entropy, f"HIGH ENTROPY ({entropy:.2f}/8.0) - likely encrypted/packed"
    elif entropy >= 6.5:
        return False, entropy, f"MEDIUM ENTROPY ({entropy:.2f}/8.0) - possibly compressed"
    else:
        return False, entropy, f"LOW ENTROPY ({entropy:.2f}/8.0) - normal"

# ============================================================================
# YARA INTEGRATION
# ============================================================================

class YaraScanner:
    """YARA rule scanner for malware signatures"""
    
    def __init__(self, rules_file: Path = None):
        self.rules = None
        self.available = YARA_AVAILABLE
        
        if not YARA_AVAILABLE:
            print("[!] YARA not available - signature matching disabled")
            return
        
        rules_file = rules_file or YARA_RULES_FILE
        
        if rules_file.exists():
            try:
                self.rules = yara.compile(filepath=str(rules_file))
                print(f"[+] YARA rules loaded from {rules_file}")
            except yara.Error as e:
                print(f"[!] YARA compile error: {e}")
                self.available = False
        else:
            print(f"[!] YARA rules file not found: {rules_file}")
            self.available = False
    
    def scan_content(self, content: bytes, identifier: str = "unknown") -> List[str]:
        """Scan content against YARA rules"""
        if not self.available or not self.rules:
            return []
        
        matches = []
        try:
            results = self.rules.match(data=content)
            for match in results:
                matches.append(f"YARA:{match.rule} ({match.meta.get('description', 'No description')})")
        except yara.Error as e:
            print(f"[!] YARA scan error for {identifier}: {e}")
        
        return matches
    
    def scan_text(self, text: str, identifier: str = "unknown") -> List[str]:
        """Scan text content against YARA rules"""
        return self.scan_content(text.encode('utf-8', errors='ignore'), identifier)

# ============================================================================
# GITHUB API (PyGithub + fallback)
# ============================================================================

class GitHubClient:
    """GitHub API client with PyGithub or requests fallback"""
    
    def __init__(self, token: str = None):
        self.token = token or GITHUB_TOKEN
        self.use_pygithub = PYGITHUB_AVAILABLE and self.token
        
        if self.use_pygithub:
            self.client = Github(self.token)
            print("[+] Using PyGithub with authentication")
        else:
            self.client = None
            if not PYGITHUB_AVAILABLE:
                print("[!] PyGithub not available - using requests")
            else:
                print("[!] No token provided - using unauthenticated requests")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for requests fallback"""
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'MalwareHunter/2.0'
        }
        if self.token:
            headers['Authorization'] = f'token {self.token}'
        return headers
    
    def search_repositories(self, query: str, max_results: int = 30) -> List[Dict]:
        """Search for repositories"""
        results = []
        
        if self.use_pygithub:
            try:
                repos = self.client.search_repositories(query, sort='updated', order='desc')
                for i, repo in enumerate(repos):
                    if i >= max_results:
                        break
                    results.append({
                        'id': repo.id,
                        'name': repo.name,
                        'full_name': repo.full_name,
                        'html_url': repo.html_url,
                        'owner': {'login': repo.owner.login},
                        'stargazers_count': repo.stargazers_count,
                        'forks_count': repo.forks_count,
                        'created_at': repo.created_at.isoformat() if repo.created_at else None,
                    })
                    time.sleep(0.5)  # Gentle rate limiting
            except RateLimitExceededException:
                print("[!] Rate limit exceeded, waiting 60s...")
                time.sleep(60)
            except GithubException as e:
                print(f"[X] GitHub API error: {e}")
        else:
            # Fallback to requests
            page = 1
            while len(results) < max_results:
                url = f"{GITHUB_API}/search/repositories"
                params = {'q': query, 'sort': 'updated', 'order': 'desc', 'page': page, 'per_page': 30}
                try:
                    response = requests.get(url, headers=self._get_headers(), params=params)
                    if response.status_code == 403:
                        print("[!] Rate limited, waiting 60s...")
                        time.sleep(60)
                        continue
                    response.raise_for_status()
                    items = response.json().get('items', [])
                    if not items:
                        break
                    results.extend(items)
                    page += 1
                    time.sleep(REQUEST_DELAY)
                except Exception as e:
                    print(f"[X] Search error: {e}")
                    break
        
        return results[:max_results]
    
    def get_repo(self, owner: str, repo: str) -> Optional[Dict]:
        """Get repository data"""
        if self.use_pygithub:
            try:
                r = self.client.get_repo(f"{owner}/{repo}")
                return {
                    'id': r.id,
                    'name': r.name,
                    'full_name': r.full_name,
                    'html_url': r.html_url,
                    'owner': {'login': r.owner.login},
                    'stargazers_count': r.stargazers_count,
                    'forks_count': r.forks_count,
                    'created_at': r.created_at.isoformat() if r.created_at else None,
                }
            except GithubException as e:
                print(f"[X] Error getting repo {owner}/{repo}: {e}")
                return None
        else:
            try:
                response = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=self._get_headers())
                response.raise_for_status()
                return response.json()
            except Exception as e:
                print(f"[X] Error getting repo: {e}")
                return None
    
    def get_contents(self, owner: str, repo: str) -> List[Dict]:
        """Get repository contents"""
        if self.use_pygithub:
            try:
                r = self.client.get_repo(f"{owner}/{repo}")
                contents = r.get_contents("")
                return [{'name': c.name, 'type': c.type, 'html_url': c.html_url, 
                        'download_url': c.download_url, 'size': c.size} 
                       for c in contents if isinstance(contents, list) or True]
            except GithubException:
                return []
        else:
            try:
                response = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}/contents", 
                                       headers=self._get_headers())
                response.raise_for_status()
                return response.json()
            except:
                return []
    
    def get_readme(self, owner: str, repo: str) -> str:
        """Get README content"""
        if self.use_pygithub:
            try:
                r = self.client.get_repo(f"{owner}/{repo}")
                readme = r.get_readme()
                return base64.b64decode(readme.content).decode('utf-8', errors='ignore')
            except GithubException:
                return ""
        else:
            try:
                response = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}/readme", 
                                       headers=self._get_headers())
                response.raise_for_status()
                content = response.json().get('content', '')
                return base64.b64decode(content).decode('utf-8', errors='ignore') if content else ""
            except:
                return ""
    
    def get_file_content(self, owner: str, repo: str, path: str) -> Optional[bytes]:
        """Get raw file content for entropy analysis"""
        if self.use_pygithub:
            try:
                r = self.client.get_repo(f"{owner}/{repo}")
                content = r.get_contents(path)
                if content.encoding == 'base64':
                    return base64.b64decode(content.content)
                return content.content.encode() if isinstance(content.content, str) else content.content
            except GithubException:
                return None
        else:
            try:
                response = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}", 
                                       headers=self._get_headers())
                response.raise_for_status()
                data = response.json()
                if data.get('encoding') == 'base64':
                    return base64.b64decode(data.get('content', ''))
                return None
            except:
                return None

# ============================================================================
# DETECTION FUNCTIONS
# ============================================================================

def detect_cyrillic_in_filename(filename: str) -> Tuple[bool, str]:
    """Detect Cyrillic character obfuscation in filenames"""
    detected_chars = []
    for cyrillic, latin in CYRILLIC_PATTERNS.items():
        if cyrillic in filename:
            detected_chars.append(f"'{cyrillic}' (U+{ord(cyrillic):04X}) instead of '{latin}'")
    if detected_chars:
        return True, f"Cyrillic obfuscation: {', '.join(detected_chars)}"
    return False, ""

def check_url_encoded_cyrillic(url: str) -> Tuple[bool, str]:
    """Check for URL-encoded Cyrillic characters"""
    cyrillic_encodings = {
        '%D0%BE': 'о (U+043E)', '%D0%B0': 'а (U+0430)',
        '%D0%B5': 'е (U+0435)', '%D1%80': 'р (U+0440)',
        '%D1%81': 'с (U+0441)', '%D0%B8': 'і (U+0456)',
    }
    detected = [f"{enc} = {char}" for enc, char in cyrillic_encodings.items() 
                if enc.upper() in url.upper()]
    if detected:
        return True, f"URL-encoded Cyrillic: {', '.join(detected)}"
    return False, ""

def analyze_readme(content: str) -> List[str]:
    """Analyze README for red flags"""
    flags = []
    content_lower = content.lower()
    
    for pattern in README_RED_FLAGS:
        if re.search(pattern, content, re.IGNORECASE):
            flags.append(f"RED FLAG: {pattern}")
    
    for pattern in BOT_INDICATORS:
        if re.search(pattern, content, re.IGNORECASE):
            flags.append(f"BOT INDICATOR: {pattern}")
    
    for domain in MALICIOUS_DOMAINS:
        if domain in content_lower:
            flags.append(f"MALICIOUS DOMAIN: {domain}")
    
    for folder_id in MALICIOUS_MEDIAFIRE:
        if folder_id in content_lower:
            flags.append(f"KNOWN MALWARE MEDIAFIRE: {folder_id}")
    
    return flags

def calculate_suspicion_score(repo_data: Dict, files: List[str], readme_content: str,
                              cyrillic: bool, high_entropy: bool, yara_matches: List[str]) -> int:
    """Calculate comprehensive suspicion score (0-100)"""
    score = 0
    
    # Stars/forks
    if repo_data.get('stargazers_count', 0) == 0:
        score += 10
    if repo_data.get('forks_count', 0) == 0:
        score += 5
    
    # Cyrillic = major indicator
    if cyrillic:
        score += 35
    
    # High entropy = likely packed/encrypted
    if high_entropy:
        score += 20
    
    # YARA matches
    score += len(yara_matches) * 15
    
    # README flags
    readme_flags = analyze_readme(readme_content)
    score += len(readme_flags) * 8
    
    # Suspicious extensions
    for f in files:
        if any(f.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            score += 10
            break
    
    return min(score, 100)

# ============================================================================
# MAIN ANALYZER
# ============================================================================

class MalwareHunter:
    """Main malware hunting engine"""
    
    def __init__(self):
        self.github = GitHubClient()
        self.yara = YaraScanner()
        self.detected: List[DetectedRepo] = []
        self.seen_repos = set()
    
    def analyze_repository(self, repo_data: Dict) -> Optional[DetectedRepo]:
        """Analyze a single repository"""
        owner = repo_data['owner']['login']
        repo_name = repo_data['name']
        full_name = f"{owner}/{repo_name}"
        url = repo_data['html_url']
        
        # Skip excluded repos (our own tools)
        if full_name in EXCLUDED_REPOS:
            print(f"[SKIP] {full_name} (excluded)")
            return None
        
        print(f"[*] Analyzing: {owner}/{repo_name}")
        
        evidence = []
        cyrillic_detected = False
        high_entropy_files = []
        yara_matches = []
        detected_files = []
        
        # Get contents
        time.sleep(REQUEST_DELAY)
        contents = self.github.get_contents(owner, repo_name)
        
        for item in contents:
            if item.get('type') != 'file':
                continue
            
            filename = item['name']
            file_url = item.get('html_url', '')
            file_size = item.get('size', 0)
            
            # Cyrillic detection
            is_cyrillic, cyrillic_details = detect_cyrillic_in_filename(filename)
            if is_cyrillic:
                cyrillic_detected = True
                evidence.append(f"CYRILLIC FILENAME: {filename} - {cyrillic_details}")
                detected_files.append(filename)
            
            is_encoded, encoded_details = check_url_encoded_cyrillic(file_url)
            if is_encoded:
                cyrillic_detected = True
                evidence.append(f"URL ENCODED CYRILLIC: {encoded_details}")
            
            # Entropy analysis for suspicious files (limit size to avoid large downloads)
            if file_size > 0 and file_size < 5000000:  # < 5MB
                ext = os.path.splitext(filename)[1].lower()
                if ext in ['.zip', '.rar', '.exe', '.dll', '.bin', '.dat']:
                    file_content = self.github.get_file_content(owner, repo_name, filename)
                    if file_content:
                        is_suspicious, entropy, desc = analyze_file_entropy(file_content, filename)
                        if is_suspicious:
                            high_entropy_files.append(f"{filename}: {desc}")
                            evidence.append(f"HIGH ENTROPY: {filename} ({entropy:.2f}/8.0)")
                        
                        # YARA scan
                        matches = self.yara.scan_content(file_content, filename)
                        yara_matches.extend(matches)
                        for m in matches:
                            evidence.append(m)
        
        # README analysis
        time.sleep(REQUEST_DELAY)
        readme_content = self.github.get_readme(owner, repo_name)
        readme_flags = []
        
        if readme_content:
            readme_flags = analyze_readme(readme_content)
            for flag in readme_flags:
                evidence.append(flag)
            
            # YARA scan on README
            matches = self.yara.scan_text(readme_content, "README.md")
            yara_matches.extend(matches)
            for m in matches:
                if m not in evidence:
                    evidence.append(m)
        
        # Calculate score
        has_high_entropy = len(high_entropy_files) > 0
        score = calculate_suspicion_score(repo_data, detected_files, readme_content,
                                          cyrillic_detected, has_high_entropy, yara_matches)
        
        # Check for critical infrastructure indicators (always HIGH severity)
        CRITICAL_INDICATORS = [
            "KNOWN MALWARE MEDIAFIRE",
            "MALICIOUS DOMAIN",
            "disable.*antivirus",
            "disable.*defender", 
            "bypass.*detection",
            "turn off.*antivirus",
            "undetected",
        ]
        has_critical_indicator = any(
            any(re.search(ind, flag, re.IGNORECASE) for ind in CRITICAL_INDICATORS)
            for flag in readme_flags
        )
        
        # Determine severity
        if cyrillic_detected or yara_matches or has_critical_indicator or score >= 60:
            severity = "HIGH"
        elif has_high_entropy or score >= 40:
            severity = "MEDIUM"
        elif score >= 20:
            severity = "LOW"
        else:
            return None  # Not suspicious enough
        
        evidence.append(f"SUSPICION SCORE: {score}/100")
        
        detection_type = "CYRILLIC_OBFUSCATION" if cyrillic_detected else \
                        "YARA_MATCH" if yara_matches else \
                        "CRITICAL_INFRA" if has_critical_indicator else \
                        "HIGH_ENTROPY" if has_high_entropy else "PATTERN_MATCH"
        
        return DetectedRepo(
            url=url, owner=owner, repo_name=repo_name,
            detection_type=detection_type, severity=severity,
            evidence=evidence, detected_at=datetime.now().isoformat(),
            cyrillic_detected=cyrillic_detected, high_entropy_files=high_entropy_files,
            yara_matches=yara_matches, readme_flags=readme_flags,
            files=detected_files, suspicion_score=score
        )
    
    def quick_check(self, repo_url: str) -> Optional[DetectedRepo]:
        """Quick check a single repository"""
        match = re.match(r'https?://github\.com/([^/]+)/([^/]+)', repo_url)
        if not match:
            print(f"[X] Invalid GitHub URL: {repo_url}")
            return None
        
        owner, repo = match.groups()
        repo_data = self.github.get_repo(owner, repo)
        
        if not repo_data:
            return None
        
        return self.analyze_repository(repo_data)
    
    def run_scan(self, queries: List[str] = None, max_per_query: int = 100):
        """Run full malware scan"""
        print("""
+====================================================================+
|  DELTA FORCE MALWARE HUNTER v2.0                                  |
|  Features: Cyrillic + Entropy + YARA + PyGithub                   |
+====================================================================+
        """)
        
        print(f"[+] PyGithub: {'Enabled' if PYGITHUB_AVAILABLE else 'Disabled'}")
        print(f"[+] YARA: {'Enabled' if self.yara.available else 'Disabled'}")
        print(f"[+] Entropy Analysis: Enabled (threshold: {ENTROPY_THRESHOLD})")
        
        queries = queries or SEARCH_QUERIES
        
        for query in queries:
            print(f"\n[?] Searching: '{query}'")
            repos = self.github.search_repositories(query, max_per_query)
            print(f"    Found {len(repos)} repositories")
            
            for repo_data in repos:
                repo_id = repo_data.get('id')
                if repo_id in self.seen_repos:
                    continue
                self.seen_repos.add(repo_id)
                
                detection = self.analyze_repository(repo_data)
                if detection:
                    self.detected.append(detection)
                    emoji = "[HIGH]" if detection.severity == "HIGH" else \
                           "[MED]" if detection.severity == "MEDIUM" else "[LOW]"
                    print(f"    {emoji} DETECTED: {detection.owner}/{detection.repo_name}")
        
        print(f"\n{'='*60}")
        print(f"[*] SCAN COMPLETE")
        print(f"    Repositories analyzed: {len(self.seen_repos)}")
        print(f"    Malicious detected: {len(self.detected)}")
        print(f"{'='*60}\n")
        
        if self.detected:
            self.save_results()
        
        return self.detected
    
    def save_results(self):
        """Save all results"""
        # JSON
        data = [asdict(d) for d in self.detected]
        with open(RESULTS_JSON, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[FILE] Saved to {RESULTS_JSON}")
        
        # CSV
        with open(RESULTS_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Owner', 'Repo', 'Severity', 'Type', 'Score',
                            'Cyrillic', 'Entropy Files', 'YARA Matches', 'Status'])
            for d in self.detected:
                writer.writerow([d.url, d.owner, d.repo_name, d.severity, d.detection_type,
                               d.suspicion_score, d.cyrillic_detected, len(d.high_entropy_files),
                               len(d.yara_matches), d.report_status])
        print(f"[FILE] Saved to {RESULTS_CSV}")
        
        # Markdown
        self._generate_report()
        
        # Pattern analysis
        self._analyze_new_patterns()
    
    def _generate_report(self):
        """Generate markdown report"""
        total = len(self.detected)
        high = len([d for d in self.detected if d.severity == "HIGH"])
        cyrillic = len([d for d in self.detected if d.cyrillic_detected])
        entropy = len([d for d in self.detected if d.high_entropy_files])
        yara = len([d for d in self.detected if d.yara_matches])
        
        report = f"""# AUTOMATED MALWARE DETECTION REPORT

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Tool:** Delta Force Malware Hunter v2.0

---

## SUMMARY

| Metric | Count |
|--------|-------|
| Total Detected | {total} |
| HIGH Severity | {high} |
| Cyrillic Obfuscation | {cyrillic} |
| High Entropy Files | {entropy} |
| YARA Matches | {yara} |

---

## DETECTED REPOSITORIES

"""
        for severity in ["HIGH", "MEDIUM", "LOW"]:
            repos = [d for d in self.detected if d.severity == severity]
            if repos:
                report += f"### {severity} SEVERITY ({len(repos)})\n\n"
                for d in repos:
                    report += f"#### [{d.owner}/{d.repo_name}]({d.url})\n\n"
                    report += f"- **Type:** {d.detection_type}\n"
                    report += f"- **Score:** {d.suspicion_score}/100\n"
                    report += f"- **Cyrillic:** {'Yes' if d.cyrillic_detected else 'No'}\n"
                    report += f"- **High Entropy Files:** {len(d.high_entropy_files)}\n"
                    report += f"- **YARA Matches:** {len(d.yara_matches)}\n\n"
                    report += "**Evidence:**\n"
                    for e in d.evidence[:10]:  # Limit evidence lines
                        report += f"- {e}\n"
                    report += "\n---\n\n"
        
        with open(REPORT_MD, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"[FILE] Saved to {REPORT_MD}")
    
    def _analyze_new_patterns(self):
        """Analyze detected repos for new patterns"""
        if not self.detected:
            return
        
        print(f"[PATTERN] Analyzing {len(self.detected)} repos for new patterns...")
        
        # Collect all README content from HIGH severity repos
        high_severity_readmes = []
        for repo in self.detected:
            if repo.severity == "HIGH" and repo.readme_flags:
                for flag in repo.readme_flags:
                    if not flag.startswith("RED FLAG:") and not flag.startswith("BOT INDICATOR:"):
                        continue
                    high_severity_readmes.append(flag)
        
        # Find common words in malicious READMEs
        word_counts = {}
        suspicious_phrases = []
        
        for readme in high_severity_readmes:
            # Extract potential new patterns
            words = re.findall(r'\b\w+\b', readme.lower())
            for word in words:
                if len(word) > 3 and word not in ['flag', 'indicator', 'repo', 'file']:
                    word_counts[word] = word_counts.get(word, 0) + 1
        
        # Find frequently occurring words (potential new patterns)
        frequent_words = [(word, count) for word, count in word_counts.items() 
                         if count >= 3 and word not in ['disable', 'antivirus', 'bypass']]
        
        if frequent_words:
            print(f"[PATTERN] Potential new patterns found:")
            pattern_suggestions = []
            for word, count in sorted(frequent_words, key=lambda x: x[1], reverse=True)[:10]:
                suggestion = f"r'{word}.*'"
                pattern_suggestions.append(f"    '{word}.*',  # Found {count} times")
                print(f"    {word}: {count} occurrences")
            
            # Save suggestions to file
            suggestions_file = OUTPUT_DIR / "SUGGESTED_PATTERNS.txt"
            with open(suggestions_file, 'w', encoding='utf-8') as f:
                f.write("# Suggested new patterns based on analysis\n")
                f.write("# Add these to README_RED_FLAGS if relevant:\n\n")
                f.write("README_RED_FLAGS += [\n")
                for suggestion in pattern_suggestions:
                    f.write(f"{suggestion}\n")
                f.write("]\n")
            
            print(f"[PATTERN] Suggestions saved to {suggestions_file}")
        else:
            print(f"[PATTERN] No new patterns detected")

# ============================================================================
# CLI
# ============================================================================

if __name__ == "__main__":
    hunter = MalwareHunter()
    
    if len(sys.argv) > 1:
        repo_url = sys.argv[1]
        print(f"[*] Quick checking: {repo_url}\n")
        result = hunter.quick_check(repo_url)
        
        if result:
            print(f"\n[!] MALICIOUS REPOSITORY DETECTED!")
            print(f"    Severity: {result.severity}")
            print(f"    Type: {result.detection_type}")
            print(f"    Score: {result.suspicion_score}/100")
            print(f"    Cyrillic: {result.cyrillic_detected}")
            print(f"    High Entropy Files: {len(result.high_entropy_files)}")
            print(f"    YARA Matches: {len(result.yara_matches)}")
            print(f"\n    Evidence:")
            for e in result.evidence:
                print(f"    - {e}")
        else:
            print("[OK] No obvious malicious indicators detected")
    else:
        hunter.run_scan()