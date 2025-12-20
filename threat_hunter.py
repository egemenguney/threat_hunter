#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Delta Force Malware Hunter v3.0
Automated GitHub malware repository detection tool

Features:
- Cyrillic filename obfuscation detection
- High entropy file detection (encrypted/packed payloads)
- YARA rule matching
- README pattern analysis
- Known infrastructure matching
- ASYNC httpx for fast parallel scanning
- Smart rate limit handling

Author: Security Research
Date: December 2025
"""

import sys
import os
import math
import asyncio


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
import binascii
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict, field
import base64

# Async HTTP client
import httpx

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

# Rate limiting configuration
# GitHub Search API: 30 requests/minute (authenticated)
# GitHub Core API: 5000 requests/hour (authenticated)
SEARCH_CONCURRENT_LIMIT = 2      # Max concurrent search queries (düşürüldü)
REPO_CONCURRENT_LIMIT = 10       # Max concurrent repo analyses (düşürüldü)
SEARCH_DELAY = 5.0               # Delay between search batches (artırıldı)
REQUEST_DELAY = 0.5              # Delay between individual requests
REQUEST_TIMEOUT = 30             # HTTP request timeout
RATE_LIMIT_BUFFER = 100          # Core API buffer (bu kadar kaldığında yavaşla)

# Output files - use script directory instead of current working directory
OUTPUT_DIR = Path(__file__).parent.resolve()
RESULTS_JSON = OUTPUT_DIR / "detected_repos.json"
RESULTS_CSV = OUTPUT_DIR / "detected_repos.csv"
REPORT_MD = OUTPUT_DIR / "AUTO_GENERATED_REPORT.md"
YARA_RULES_FILE = OUTPUT_DIR / "rules.yar"

# Entropy threshold for detecting encrypted/packed content
ENTROPY_THRESHOLD = 7.0  # Max is 8.0, >7.0 = likely encrypted

# ============================================================================
# DETECTION PATTERNS
# ============================================================================

# ============================================================================
# CYRILLIC HOMOGLYPH HUNTER
# ============================================================================

# Complete Latin-Cyrillic homoglyph pairs (19 pairs)
CYRILLIC_HOMOGLYPHS = {
    # Cyrillic -> Latin equivalent
    'а': 'a',  # U+0430 -> U+0061
    'А': 'A',  # U+0410 -> U+0041
    'В': 'B',  # U+0412 -> U+0042
    'с': 'c',  # U+0441 -> U+0063
    'С': 'C',  # U+0421 -> U+0043
    'е': 'e',  # U+0435 -> U+0065
    'Е': 'E',  # U+0415 -> U+0045
    'Н': 'H',  # U+041D -> U+0048
    'і': 'i',  # U+0456 -> U+0069
    'І': 'I',  # U+0406 -> U+0049
    'ј': 'j',  # U+0458 -> U+006A
    'К': 'K',  # U+041A -> U+004B
    'М': 'M',  # U+041C -> U+004D
    'о': 'o',  # U+043E -> U+006F
    'О': 'O',  # U+041E -> U+004F
    'р': 'p',  # U+0440 -> U+0070
    'Р': 'P',  # U+0420 -> U+0050
    'ѕ': 's',  # U+0455 -> U+0073
    'Ѕ': 'S',  # U+0405 -> U+0053
    'Т': 'T',  # U+0422 -> U+0054
    'у': 'y',  # U+0443 -> U+0079
    'У': 'Y',  # U+0423 -> U+0059
    'х': 'x',  # U+0445 -> U+0078
    'Х': 'X',  # U+0425 -> U+0058
    'ԁ': 'd',  # U+0501 -> U+0064
    'ɡ': 'g',  # U+0261 -> U+0067
    'һ': 'h',  # U+04BB -> U+0068
    'ӏ': 'l',  # U+04CF -> U+006C
    'ո': 'n',  # U+0578 -> U+006E
    'ԛ': 'q',  # U+051B -> U+0071
    'ʋ': 'v',  # U+028B -> U+0076
    'ѡ': 'w',  # U+0461 -> U+0077
    'ᴢ': 'z',  # U+1D22 -> U+007A
}

# Reverse mapping: Latin -> Cyrillic alternatives
LATIN_TO_CYRILLIC = {}
for cyr, lat in CYRILLIC_HOMOGLYPHS.items():
    if lat not in LATIN_TO_CYRILLIC:
        LATIN_TO_CYRILLIC[lat] = []
    LATIN_TO_CYRILLIC[lat].append(cyr)

# Legacy simple mapping for backward compatibility
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

class HomoglyphHunter:
    """Advanced Cyrillic homoglyph detection with mixed string analysis"""
    
    # Common malware-related words to check for homoglyph obfuscation
    SUSPICIOUS_WORDS = [
        'loader', 'setup', 'install', 'hack', 'cheat', 'crack', 
        'keygen', 'patch', 'trainer', 'injector', 'launcher',
        'activator', 'unlocker', 'spoofer', 'bypass', 'exploit',
        'delta', 'force', 'warzone', 'valorant', 'fortnite',
        'apex', 'rust', 'csgo', 'pubg', 'tarkov', 'gta'
    ]
    
    def __init__(self):
        self.detected_patterns = []
    
    def normalize_to_latin(self, text: str) -> str:
        """Convert all Cyrillic homoglyphs to Latin equivalents"""
        result = text
        for cyr, lat in CYRILLIC_HOMOGLYPHS.items():
            result = result.replace(cyr, lat)
        return result
    
    def detect_mixed_script(self, text: str) -> Tuple[bool, List[str]]:
        """
        Detect mixed Latin-Cyrillic strings (homoglyph obfuscation)
        Returns: (is_mixed, list of evidence strings)
        """
        evidence = []
        has_latin = bool(re.search(r'[a-zA-Z]', text))
        has_cyrillic = bool(re.search(r'[\u0400-\u04FF\u0500-\u052F]', text))
        
        if has_latin and has_cyrillic:
            # Find specific Cyrillic characters used
            cyrillic_chars = []
            for char in text:
                if char in CYRILLIC_HOMOGLYPHS:
                    cyrillic_chars.append(f"'{char}' (U+{ord(char):04X}) -> '{CYRILLIC_HOMOGLYPHS[char]}'")
            
            if cyrillic_chars:
                evidence.append(f"MIXED SCRIPT: {', '.join(set(cyrillic_chars))}")
                normalized = self.normalize_to_latin(text)
                evidence.append(f"NORMALIZED: '{text}' -> '{normalized}'")
                return True, evidence
        
        return False, evidence
    
    def generate_homoglyph_regex(self, word: str) -> str:
        """
        Generate regex pattern that matches all homoglyph variants of a word
        Example: 'loader' -> '[lӏ][oо][aа][dԁ][eе][r]'
        """
        pattern_parts = []
        for char in word.lower():
            if char in LATIN_TO_CYRILLIC:
                cyrillic_alts = LATIN_TO_CYRILLIC[char]
                char_class = f"[{char}{''.join(cyrillic_alts)}]"
                pattern_parts.append(char_class)
            else:
                # Escape special regex characters
                if char in r'\.[]{}()*+?^$|':
                    pattern_parts.append(f'\\{char}')
                else:
                    pattern_parts.append(char)
        
        return ''.join(pattern_parts)
    
    def scan_for_obfuscated_words(self, text: str) -> List[str]:
        """
        Scan text for suspicious words that may be obfuscated with homoglyphs
        Returns list of detected obfuscated words
        """
        findings = []
        
        for word in self.SUSPICIOUS_WORDS:
            # Generate regex for all homoglyph variants
            pattern = self.generate_homoglyph_regex(word)
            matches = re.findall(pattern, text, re.IGNORECASE)
            
            for match in matches:
                # Check if match contains actual Cyrillic (not just Latin)
                if any(c in CYRILLIC_HOMOGLYPHS for c in match):
                    normalized = self.normalize_to_latin(match)
                    findings.append(f"HOMOGLYPH '{match}' -> '{normalized}' (target: {word})")
        
        return findings
    
    def analyze_filename(self, filename: str) -> Tuple[bool, List[str]]:
        """
        Comprehensive filename analysis for homoglyph obfuscation
        Returns: (is_suspicious, list of evidence)
        """
        evidence = []
        is_suspicious = False
        
        # Check for mixed script
        mixed, mixed_evidence = self.detect_mixed_script(filename)
        if mixed:
            is_suspicious = True
            evidence.extend(mixed_evidence)
        
        # Check for obfuscated suspicious words
        obfuscated = self.scan_for_obfuscated_words(filename)
        if obfuscated:
            is_suspicious = True
            evidence.extend(obfuscated)
        
        # Check for pure Cyrillic that looks like Latin words
        normalized = self.normalize_to_latin(filename)
        if normalized != filename:
            for word in self.SUSPICIOUS_WORDS:
                if word in normalized.lower() and word not in filename.lower():
                    is_suspicious = True
                    evidence.append(f"HIDDEN WORD: '{word}' found after normalization")
        
        return is_suspicious, evidence

# ============================================================================
# DYNAMIC PATTERN DISCOVERY
# ============================================================================

class PatternDiscovery:
    """Dynamic pattern discovery using N-Gram analysis and Levenshtein distance"""
    
    def __init__(self, similarity_threshold: float = 0.85):
        self.similarity_threshold = similarity_threshold
        self.discovered_patterns = []
        self.filename_clusters = {}
        self.ngram_frequencies = {}
    
    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein (edit) distance between two strings"""
        if len(s1) < len(s2):
            return PatternDiscovery.levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    @staticmethod
    def similarity_ratio(s1: str, s2: str) -> float:
        """Calculate similarity ratio (0.0 - 1.0) between two strings"""
        if not s1 or not s2:
            return 0.0
        
        distance = PatternDiscovery.levenshtein_distance(s1.lower(), s2.lower())
        max_len = max(len(s1), len(s2))
        return 1.0 - (distance / max_len)
    
    def extract_ngrams(self, text: str, n: int = 3) -> List[str]:
        """Extract n-grams from text"""
        text = text.lower()
        words = re.findall(r'\b\w+\b', text)
        
        ngrams = []
        # Word-level n-grams
        for i in range(len(words) - n + 1):
            ngrams.append(' '.join(words[i:i + n]))
        
        # Character-level n-grams for short texts
        if len(text) >= n:
            for i in range(len(text) - n + 1):
                ngrams.append(text[i:i + n])
        
        return ngrams
    
    def analyze_readme_ngrams(self, readme_content: str) -> Dict[str, int]:
        """
        Analyze README content for suspicious n-gram patterns
        Returns: dict of n-gram -> frequency
        """
        suspicious_ngrams = {}
        
        # Define suspicious phrase patterns
        suspicious_patterns = [
            r'disable.*antivirus',
            r'turn.*off.*defender',
            r'password.*\d+',
            r'pass.*\d+',
            r'download.*link',
            r'click.*here',
            r'free.*download',
            r'working.*\d{4}',
            r'latest.*version',
            r'undetected',
        ]
        
        # Extract 2-grams and 3-grams
        for n in [2, 3]:
            ngrams = self.extract_ngrams(readme_content, n)
            for ngram in ngrams:
                # Check against suspicious patterns
                for pattern in suspicious_patterns:
                    if re.search(pattern, ngram, re.IGNORECASE):
                        suspicious_ngrams[ngram] = suspicious_ngrams.get(ngram, 0) + 1
        
        return suspicious_ngrams
    
    def cluster_similar_filenames(self, filenames: List[str]) -> Dict[str, List[str]]:
        """
        Cluster similar filenames together using Levenshtein distance
        Returns: dict of pattern -> list of matching filenames
        """
        if not filenames:
            return {}
        
        clusters = {}
        processed = set()
        
        for i, f1 in enumerate(filenames):
            if f1 in processed:
                continue
            
            cluster = [f1]
            processed.add(f1)
            
            for j, f2 in enumerate(filenames[i + 1:], i + 1):
                if f2 in processed:
                    continue
                
                similarity = self.similarity_ratio(f1, f2)
                if similarity >= self.similarity_threshold:
                    cluster.append(f2)
                    processed.add(f2)
            
            if len(cluster) >= 2:
                # Generate pattern from cluster
                pattern = self.generalize_pattern(cluster)
                clusters[pattern] = cluster
        
        return clusters
    
    def generalize_pattern(self, filenames: List[str]) -> str:
        """
        Generate a generalized regex pattern from similar filenames
        Example: ['loader_v1.zip', 'loader_v2.zip'] -> 'loader_v\\d+\\.zip'
        """
        if not filenames:
            return ""
        
        if len(filenames) == 1:
            return re.escape(filenames[0])
        
        # Find common prefix and suffix
        base = filenames[0]
        
        # Replace version numbers with \d+
        pattern = re.sub(r'\d+', r'\\d+', base)
        
        # Replace common variable parts
        pattern = re.sub(r'v\d+', r'v\\d+', pattern)
        pattern = re.sub(r'_\d+', r'_\\d+', pattern)
        pattern = re.sub(r'-\d+', r'-\\d+', pattern)
        
        # Escape dots for regex
        pattern = pattern.replace('.', r'\.')
        
        return pattern
    
    def discover_filename_patterns(self, filenames: List[str]) -> List[Dict]:
        """
        Discover patterns in a list of filenames
        Returns: list of discovered pattern info
        """
        patterns = []
        clusters = self.cluster_similar_filenames(filenames)
        
        for pattern, files in clusters.items():
            patterns.append({
                'pattern': pattern,
                'matches': files,
                'count': len(files),
                'confidence': len(files) / len(filenames) if filenames else 0
            })
        
        # Sort by count descending
        patterns.sort(key=lambda x: x['count'], reverse=True)
        
        return patterns
    
    def analyze_repository_patterns(self, filenames: List[str], 
                                     readme_content: str = "") -> Dict:
        """
        Comprehensive pattern analysis for a repository
        Returns: analysis results dict
        """
        results = {
            'filename_patterns': [],
            'readme_ngrams': {},
            'suspicious_sequences': [],
            'recommendations': []
        }
        
        # Analyze filenames
        if filenames:
            results['filename_patterns'] = self.discover_filename_patterns(filenames)
            
            # Check for suspicious filename sequences
            suspicious_names = ['loader', 'setup', 'install', 'crack', 'keygen', 
                               'patch', 'hack', 'cheat', 'trainer']
            for fname in filenames:
                fname_lower = fname.lower()
                for sus in suspicious_names:
                    if sus in fname_lower:
                        results['suspicious_sequences'].append(
                            f"Suspicious filename: {fname} (contains '{sus}')"
                        )
        
        # Analyze README
        if readme_content:
            results['readme_ngrams'] = self.analyze_readme_ngrams(readme_content)
            
            # Generate recommendations based on frequent n-grams
            for ngram, count in results['readme_ngrams'].items():
                if count >= 2:
                    results['recommendations'].append(
                        f"Consider adding pattern: r'{re.escape(ngram)}' (found {count}x)"
                    )
        
        return results

# Initialize global instances
homoglyph_hunter = HomoglyphHunter()
pattern_discovery = PatternDiscovery(similarity_threshold=0.85)

# Dynamic year-aware red flags
def get_dynamic_red_flags():
    """Generate red flags including current year patterns for all tracked games"""
    current_year = datetime.now().year
    base_years = [2023, 2024, 2025]
    
    # Add current year if newer
    if current_year > max(base_years) and current_year not in base_years:
        base_years.append(current_year)
    
    # All game names to track (matching SEARCH_QUERIES categories)
    game_patterns = [
        # 1. Delta Force
        r'Delta.*Force',
        r'DeltaForce',
        r'Hawk.*Ops',
        r'HawkOps',
        
        # 2. Call of Duty
        r'Warzone',
        r'Black.*Ops',
        r'BlackOps',
        r'Modern.*Warfare',
        r'Call.*of.*Duty',
        r'COD',
        r'MW3',
        r'BO6',
        r'BO7',
        
        # 3. Counter-Strike
        r'Counter.*Strike',
        r'CS2',
        r'CSGO',
        r'CS.*GO',
        
        # 4. Battlefield
        r'Battlefield',
        r'BF2042',
        r'BFV',
        r'BF.*V',
        
        # 5. Arma
        r'Arma.*3',
        r'Arma.*4',
        r'Arma.*Reforger',
        r'Reforger',
        
        # 6. Valorant
        r'Valorant',
        r'Valo',
        
        # 7. Warframe
        r'Warframe',
        
        # 8. Rust
        r'Rust',
        
        # 9. Outlast
        r'Outlast',
        r'Outlast.*Trials',
        
        # 10. Fortnite
        r'Fortnite',
        
        # 11. Apex Legends
        r'Apex.*Legends',
        r'Apex',
        
        # 12. PUBG
        r'PUBG',
        r'PlayerUnknown',
        
        # 13. Escape from Tarkov
        r'Tarkov',
        r'EFT',
        r'Escape.*from.*Tarkov',
        
        # 14. GTA
        r'GTA.*5',
        r'GTA.*V',
        r'GTA.*Online',
    ]
    
    # Year-based suspicious patterns
    year_red_flags = []
    for year in base_years:
        # Generic year patterns
        year_red_flags.extend([
            rf'{year}.*hack.*tool',
            rf'latest.*{year}.*version',
            rf'{year}.*cracked',
            rf'{year}.*undetected',
            rf'{year}.*working',
            rf'free.*{year}',
        ])
        
        # Game-specific year patterns
        for game in game_patterns:
            year_red_flags.append(rf'{game}.*{year}')
            year_red_flags.append(rf'{year}.*{game}')
    
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
    # =========================================================================
    # 1. DELTA FORCE
    # =========================================================================
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
    'delta force hwid spoofer',
    'hawk ops hack',
    'hawkops cheat',
    
    # =========================================================================
    # 2. CALL OF DUTY (Warzone, Black Ops 6/7, MW3)
    # =========================================================================
    # Warzone
    'warzone hack',
    'warzone cheat',
    'warzone aimbot',
    'warzone esp',
    'warzone wallhack',
    'warzone loader',
    'warzone unlocker',
    'warzone hwid spoofer',
    'warzone unlock all',
    'cod warzone hack',
    'warzone-hack',
    
    # Black Ops 6
    'black ops 6 hack',
    'black ops 6 cheat',
    'black ops 6 aimbot',
    'black ops 6 esp',
    'black ops 6 unlock all',
    'bo6 hack',
    'bo6 cheat',
    'bo6 aimbot',
    'bo6-hack',
    'blackops6 hack',
    
    # Black Ops 7
    'black ops 7 hack',
    'black ops 7 cheat',
    'bo7 hack',
    'bo7 cheat',
    
    # Modern Warfare 3
    'mw3 hack',
    'mw3 cheat',
    'mw3 aimbot',
    'mw3 esp',
    'mw3 unlock all',
    'modern warfare 3 hack',
    'modern warfare 3 cheat',
    'modern warfare hack',
    'mw3-hack',
    
    # General COD
    'call of duty hack',
    'call of duty cheat',
    'cod hack',
    'cod cheat',
    'cod aimbot',
    'cod hwid spoofer',
    
    # =========================================================================
    # 3. COUNTER-STRIKE (CS2, CSGO)
    # =========================================================================
    # CS2
    'cs2 hack',
    'cs2 cheat',
    'cs2 aimbot',
    'cs2 esp',
    'cs2 wallhack',
    'cs2 triggerbot',
    'cs2 skinchanger',
    'counter strike 2 hack',
    'counter-strike 2 hack',
    'cs2-hack',
    
    # CSGO
    'csgo hack',
    'csgo cheat',
    'csgo aimbot',
    'csgo esp',
    'csgo wallhack',
    'cs go hack',
    'counter strike go hack',
    'csgo-hack',
    
    # General CS
    'counter strike hack',
    'counter-strike hack',
    'cs hack',
    
    # =========================================================================
    # 4. BATTLEFIELD (BF2042, BFV)
    # =========================================================================
    'battlefield hack',
    'battlefield cheat',
    'battlefield aimbot',
    'battlefield esp',
    
    # BF2042
    'bf2042 hack',
    'bf2042 cheat',
    'bf2042 aimbot',
    'battlefield 2042 hack',
    'battlefield 2042 cheat',
    'bf2042-hack',
    
    # BFV / Battlefield V
    'bfv hack',
    'bfv cheat',
    'battlefield v hack',
    'battlefield 5 hack',
    'bfv-hack',
    
    # =========================================================================
    # 5. ARMA (Arma 3, Arma 4, Arma Reforger)
    # =========================================================================
    # Arma 3
    'arma 3 hack',
    'arma 3 cheat',
    'arma 3 aimbot',
    'arma 3 esp',
    'arma3 hack',
    'arma3 script',
    'arma-3-hack',
    
    # Arma 4
    'arma 4 hack',
    'arma 4 cheat',
    'arma4 hack',
    
    # Arma Reforger
    'arma reforger hack',
    'arma reforger cheat',
    'reforger hack',
    'reforger cheat',
    
    # General Arma
    'arma hack',
    'arma cheat',
    'arma script',
    
    # =========================================================================
    # 6. VALORANT
    # =========================================================================
    'valorant hack',
    'valorant cheat',
    'valorant aimbot',
    'valorant esp',
    'valorant wallhack',
    'valorant triggerbot',
    'valorant hwid spoofer',
    'valorant undetected',
    'valorant loader',
    'valorant-hack',
    'valo hack',
    'valo cheat',
    
    # =========================================================================
    # 7. WARFRAME
    # =========================================================================
    'warframe hack',
    'warframe cheat',
    'warframe platinum hack',
    'warframe plat hack',
    'warframe bot',
    'warframe trainer',
    'warframe-hack',
    
    # =========================================================================
    # 8. RUST
    # =========================================================================
    'rust hack',
    'rust cheat',
    'rust aimbot',
    'rust esp',
    'rust recoil script',
    'rust scripts',
    'rust hwid spoofer',
    'rust undetected',
    'rust-hack',
    'rustcheat',
    
    # =========================================================================
    # 9. THE OUTLAST / OUTLAST TRIALS
    # =========================================================================
    'outlast hack',
    'outlast cheat',
    'outlast trainer',
    'outlast trials hack',
    'outlast trials cheat',
    
    # =========================================================================
    # 10. FORTNITE (Bonus - common malware target)
    # =========================================================================
    'fortnite hack',
    'fortnite cheat',
    'fortnite aimbot',
    'fortnite esp',
    'fortnite vbucks hack',
    'fortnite hwid spoofer',
    'fortnite softaim',
    'fortnite-hack',
    
    # =========================================================================
    # 11. APEX LEGENDS (Bonus - common malware target)
    # =========================================================================
    'apex hack',
    'apex cheat',
    'apex aimbot',
    'apex esp',
    'apex legends hack',
    'apex legends cheat',
    'apex hwid spoofer',
    'apex-hack',
    
    # =========================================================================
    # 12. PUBG (Bonus - common malware target)
    # =========================================================================
    'pubg hack',
    'pubg cheat',
    'pubg aimbot',
    'pubg esp',
    'pubg mobile hack',
    'pubg hwid spoofer',
    'pubg-hack',
    
    # =========================================================================
    # 13. ESCAPE FROM TARKOV (Bonus - common malware target)
    # =========================================================================
    'tarkov hack',
    'tarkov cheat',
    'tarkov aimbot',
    'tarkov esp',
    'eft hack',
    'eft cheat',
    'escape from tarkov hack',
    'tarkov radar',
    'tarkov-hack',
    
    # =========================================================================
    # 14. GTA V / GTA Online (Bonus - common malware target)
    # =========================================================================
    'gta 5 hack',
    'gta 5 mod menu',
    'gta online hack',
    'gta v mod menu',
    'gta money hack',
    'gta5 hack',
    'gtav mod menu',
]

# Exclude our own repos from detection (false positives)
EXCLUDED_REPOS = [
    'egemenguney/threat_hunter',    
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
# ASYNC GITHUB API CLIENT
# ============================================================================

class AsyncGitHubClient:
    """Async GitHub API client using httpx with smart rate limiting"""
    
    def __init__(self, token: str = None):
        self.token = token or GITHUB_TOKEN
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'MalwareHunter/3.0'
        }
        if self.token:
            self.headers['Authorization'] = f'token {self.token}'
            print("[+] Using authenticated GitHub API")
        else:
            print("[!] No token - using unauthenticated API (lower rate limits)")
        
        # Semaphores for rate limiting
        self.search_semaphore = asyncio.Semaphore(SEARCH_CONCURRENT_LIMIT)
        self.repo_semaphore = asyncio.Semaphore(REPO_CONCURRENT_LIMIT)
        
        # Rate limit tracking
        self.rate_limit_remaining = 5000
        self.rate_limit_reset = 0
        self.search_rate_remaining = 30
        self.search_rate_reset = 0
    
    def _update_rate_limits(self, response: httpx.Response, is_search: bool = False):
        """Update rate limit info from response headers"""
        try:
            if is_search:
                self.search_rate_remaining = int(response.headers.get('X-RateLimit-Remaining', 30))
                self.search_rate_reset = int(response.headers.get('X-RateLimit-Reset', 0))
            else:
                self.rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 5000))
                self.rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))
        except (ValueError, TypeError):
            pass
    
    async def _check_rate_limit_buffer(self, is_search: bool = False):
        """Proaktif rate limit kontrolü - buffer'a yaklaşınca yavaşla"""
        if is_search:
            # Search API: 30/dakika - 5 kaldığında 30 sn bekle
            if self.search_rate_remaining <= 5 and self.search_rate_remaining > 0:
                wait_time = max(self.search_rate_reset - time.time(), 30)
                print(f"[RATE] Search API buffer low ({self.search_rate_remaining}), waiting {wait_time:.0f}s...")
                await asyncio.sleep(wait_time)
        else:
            # Core API: 5000/saat - buffer'a yaklaşınca yavaşla
            if self.rate_limit_remaining <= RATE_LIMIT_BUFFER and self.rate_limit_remaining > 0:
                # Her istek arasına ekstra delay ekle
                extra_delay = (RATE_LIMIT_BUFFER - self.rate_limit_remaining) * 0.5
                print(f"[RATE] Core API buffer low ({self.rate_limit_remaining}), adding {extra_delay:.1f}s delay...")
                await asyncio.sleep(extra_delay)
    
    async def _handle_rate_limit(self, response: httpx.Response, is_search: bool = False) -> bool:
        """Handle rate limit response, returns True if should retry"""
        if response.status_code == 403:
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            remaining = int(response.headers.get('X-RateLimit-Remaining', -1))
            
            # Rate limit mi yoksa başka bir 403 mü?
            if remaining == 0 or 'rate limit' in response.text.lower():
                if reset_time:
                    wait_time = max(reset_time - time.time(), 1)
                    # GitHub Actions'da 60 dakikaya kadar bekle (workflow zaten uzun sürebilir)
                    max_wait = int(os.environ.get('RATE_LIMIT_MAX_WAIT', 3600))  # Default 60 min
                    if wait_time <= max_wait:
                        limit_type = "Search" if is_search else "API"
                        wait_min = wait_time / 60
                        print(f"[!] {limit_type} rate limit hit (remaining: {remaining})")
                        print(f"[!] Waiting {wait_min:.1f} minutes for reset...")
                        await asyncio.sleep(wait_time + 5)  # +5 saniye güvenlik payı
                        return True
                    else:
                        print(f"[!] Rate limit reset too far ({wait_time/60:.1f} min), exceeds max wait ({max_wait/60:.0f} min)")
        return False
    
    async def search_repositories(self, client: httpx.AsyncClient, query: str, 
                                   max_results: int = 30) -> List[Dict]:
        """Search for repositories with rate limiting"""
        results = []
        page = 1
        retry_count = 0
        max_retries = 3
        
        async with self.search_semaphore:
            while len(results) < max_results:
                # Proaktif rate limit kontrolü
                await self._check_rate_limit_buffer(is_search=True)
                
                url = f"{GITHUB_API}/search/repositories"
                params = {
                    'q': query, 
                    'sort': 'updated', 
                    'order': 'desc', 
                    'page': page, 
                    'per_page': min(30, max_results - len(results))
                }
                
                try:
                    response = await client.get(url, params=params, timeout=REQUEST_TIMEOUT)
                    self._update_rate_limits(response, is_search=True)
                    
                    if response.status_code == 403:
                        if await self._handle_rate_limit(response, is_search=True):
                            retry_count += 1
                            if retry_count <= max_retries:
                                continue
                            else:
                                print(f"[!] Max retries ({max_retries}) exceeded for '{query}'")
                                break
                        break
                    
                    if response.status_code == 422:
                        # Validation error - query might be invalid
                        break
                    
                    response.raise_for_status()
                    data = response.json()
                    items = data.get('items', [])
                    
                    if not items:
                        break
                    
                    results.extend(items)
                    page += 1
                    retry_count = 0  # Reset retry counter on success
                    
                    # Search API için daha uzun delay (30 req/min = 2 sn/req)
                    await asyncio.sleep(2.5)
                    
                except httpx.TimeoutException:
                    print(f"[!] Search timeout for '{query}'")
                    retry_count += 1
                    if retry_count <= max_retries:
                        await asyncio.sleep(5)
                        continue
                    break
                except Exception as e:
                    print(f"[X] Search error for '{query}': {e}")
                    break
        
        return results[:max_results]
    
    async def get_repo(self, client: httpx.AsyncClient, owner: str, repo: str) -> Optional[Dict]:
        """Get repository data"""
        async with self.repo_semaphore:
            # Proaktif rate limit kontrolü
            await self._check_rate_limit_buffer(is_search=False)
            
            try:
                url = f"{GITHUB_API}/repos/{owner}/{repo}"
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                self._update_rate_limits(response)
                
                if response.status_code == 403:
                    if await self._handle_rate_limit(response):
                        response = await client.get(url, timeout=REQUEST_TIMEOUT)
                    else:
                        return None
                
                if response.status_code == 404:
                    return None
                
                response.raise_for_status()
                await asyncio.sleep(REQUEST_DELAY)  # Küçük delay
                return response.json()
            except Exception as e:
                print(f"[X] Error getting repo {owner}/{repo}: {e}")
                return None
    
    async def get_contents(self, client: httpx.AsyncClient, owner: str, repo: str) -> List[Dict]:
        """Get repository contents"""
        async with self.repo_semaphore:
            # Proaktif rate limit kontrolü
            await self._check_rate_limit_buffer(is_search=False)
            
            try:
                url = f"{GITHUB_API}/repos/{owner}/{repo}/contents"
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                self._update_rate_limits(response)
                
                if response.status_code == 403:
                    if await self._handle_rate_limit(response):
                        response = await client.get(url, timeout=REQUEST_TIMEOUT)
                
                if response.status_code in [403, 404]:
                    return []
                
                response.raise_for_status()
                data = response.json()
                await asyncio.sleep(REQUEST_DELAY)  # Küçük delay
                return data if isinstance(data, list) else []
            except Exception:
                return []
    
    async def get_readme(self, client: httpx.AsyncClient, owner: str, repo: str) -> str:
        """Get README content"""
        async with self.repo_semaphore:
            # Proaktif rate limit kontrolü
            await self._check_rate_limit_buffer(is_search=False)
            
            try:
                url = f"{GITHUB_API}/repos/{owner}/{repo}/readme"
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                self._update_rate_limits(response)
                
                if response.status_code == 403:
                    if await self._handle_rate_limit(response):
                        response = await client.get(url, timeout=REQUEST_TIMEOUT)
                
                if response.status_code in [403, 404]:
                    return ""
                
                response.raise_for_status()
                content = response.json().get('content', '')
                await asyncio.sleep(REQUEST_DELAY)  # Küçük delay
                return base64.b64decode(content).decode('utf-8', errors='ignore') if content else ""
            except (ValueError, KeyError, binascii.Error):
                return ""
            except Exception:
                return ""
    
    async def get_file_content(self, client: httpx.AsyncClient, owner: str, 
                                repo: str, path: str) -> Optional[bytes]:
        """Get raw file content for entropy analysis"""
        async with self.repo_semaphore:
            # Proaktif rate limit kontrolü
            await self._check_rate_limit_buffer(is_search=False)
            
            try:
                url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                self._update_rate_limits(response)
                
                if response.status_code == 403:
                    if await self._handle_rate_limit(response):
                        response = await client.get(url, timeout=REQUEST_TIMEOUT)
                
                if response.status_code in [403, 404]:
                    return None
                
                response.raise_for_status()
                data = response.json()
                
                if data.get('encoding') == 'base64':
                    return base64.b64decode(data.get('content', ''))
                return None
            except Exception:
                return None
    
    def get_rate_limit_status(self) -> str:
        """Get current rate limit status"""
        return f"API: {self.rate_limit_remaining} | Search: {self.search_rate_remaining}"

# ============================================================================
# DETECTION FUNCTIONS
# ============================================================================

def detect_cyrillic_in_filename(filename: str) -> Tuple[bool, str]:
    """Detect Cyrillic character obfuscation in filenames (legacy simple detection)"""
    detected_chars = []
    for cyrillic, latin in CYRILLIC_PATTERNS.items():
        if cyrillic in filename:
            detected_chars.append(f"'{cyrillic}' (U+{ord(cyrillic):04X}) instead of '{latin}'")
    if detected_chars:
        return True, f"Cyrillic obfuscation: {', '.join(detected_chars)}"
    return False, ""

def detect_homoglyph_obfuscation(filename: str) -> Tuple[bool, List[str]]:
    """
    Advanced homoglyph detection using HomoglyphHunter
    Returns: (is_suspicious, list of evidence strings)
    """
    return homoglyph_hunter.analyze_filename(filename)

def check_url_encoded_cyrillic(url: str) -> Tuple[bool, str]:
    """Check for URL-encoded Cyrillic characters"""
    cyrillic_encodings = {
        '%D0%BE': 'о (U+043E)', '%D0%B0': 'а (U+0430)',
        '%D0%B5': 'е (U+0435)', '%D1%80': 'р (U+0440)',
        '%D1%81': 'с (U+0441)', '%D0%B8': 'і (U+0456)',
        '%D0%90': 'А (U+0410)', '%D0%92': 'В (U+0412)',
        '%D0%A1': 'С (U+0421)', '%D0%95': 'Е (U+0415)',
        '%D0%9D': 'Н (U+041D)', '%D0%9E': 'О (U+041E)',
        '%D0%A0': 'Р (U+0420)', '%D0%A2': 'Т (U+0422)',
        '%D0%A5': 'Х (U+0425)', '%D0%A3': 'У (U+0423)',
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
    
    # N-gram analysis for suspicious patterns
    ngram_results = pattern_discovery.analyze_readme_ngrams(content)
    for ngram, count in ngram_results.items():
        if count >= 2:
            flags.append(f"SUSPICIOUS N-GRAM ({count}x): {ngram}")
    
    return flags

def analyze_filename_patterns(filenames: List[str]) -> List[str]:
    """
    Analyze filenames for suspicious patterns using PatternDiscovery
    Returns: list of findings
    """
    findings = []
    
    if not filenames:
        return findings
    
    # Cluster similar filenames
    patterns = pattern_discovery.discover_filename_patterns(filenames)
    
    for p in patterns:
        if p['count'] >= 2:
            findings.append(
                f"FILENAME PATTERN: {p['pattern']} (matches {p['count']} files: {', '.join(p['matches'][:3])}...)"
            )
    
    return findings

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
# ASYNC MAIN ANALYZER
# ============================================================================

class MalwareHunter:
    """Main async malware hunting engine"""
    
    def __init__(self):
        self.github = AsyncGitHubClient()
        self.yara = YaraScanner()
        self.detected: List[DetectedRepo] = []
        self.seen_repos = set()
        self.stats = {
            'total_queries': 0,
            'total_repos_found': 0,
            'repos_analyzed': 0,
            'repos_skipped': 0,
        }
    
    async def analyze_repository(self, client: httpx.AsyncClient, 
                                  repo_data: Dict) -> Optional[DetectedRepo]:
        """Analyze a single repository asynchronously"""
        owner = repo_data['owner']['login']
        repo_name = repo_data['name']
        full_name = f"{owner}/{repo_name}"
        url = repo_data['html_url']
        
        # Skip excluded repos (our own tools)
        if full_name in EXCLUDED_REPOS:
            return None
        
        evidence = []
        cyrillic_detected = False
        high_entropy_files = []
        yara_matches = []
        detected_files = []
        all_filenames = []  # For pattern discovery
        
        # Get contents and README in parallel
        contents_task = self.github.get_contents(client, owner, repo_name)
        readme_task = self.github.get_readme(client, owner, repo_name)
        
        contents, readme_content = await asyncio.gather(contents_task, readme_task)
        
        # Process files
        for item in contents:
            if item.get('type') != 'file':
                continue
            
            filename = item.get('name', '')
            file_url = item.get('html_url', '')
            file_size = item.get('size', 0)
            all_filenames.append(filename)
            
            # === ADVANCED HOMOGLYPH DETECTION ===
            # 1. Legacy simple Cyrillic detection
            is_cyrillic, cyrillic_details = detect_cyrillic_in_filename(filename)
            if is_cyrillic:
                cyrillic_detected = True
                evidence.append(f"CYRILLIC FILENAME: {filename} - {cyrillic_details}")
                detected_files.append(filename)
            
            # 2. Advanced homoglyph detection (mixed script, hidden words)
            is_homoglyph, homoglyph_evidence = detect_homoglyph_obfuscation(filename)
            if is_homoglyph:
                cyrillic_detected = True
                evidence.extend(homoglyph_evidence)
                if filename not in detected_files:
                    detected_files.append(filename)
            
            # 3. URL-encoded Cyrillic check
            is_encoded, encoded_details = check_url_encoded_cyrillic(file_url)
            if is_encoded:
                cyrillic_detected = True
                evidence.append(f"URL ENCODED CYRILLIC: {encoded_details}")
            
            # Entropy analysis for suspicious files
            if file_size > 0 and file_size < 5000000:
                ext = os.path.splitext(filename)[1].lower()
                if ext in ['.zip', '.rar', '.exe', '.dll', '.bin', '.dat']:
                    file_content = await self.github.get_file_content(client, owner, repo_name, filename)
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
        
        # === DYNAMIC PATTERN DISCOVERY ===
        # Analyze filename patterns (Levenshtein clustering)
        filename_pattern_findings = analyze_filename_patterns(all_filenames)
        evidence.extend(filename_pattern_findings)
        
        # README analysis (includes N-gram analysis)
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
        
        # Check for critical infrastructure indicators
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
            return None
        
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
    
    async def process_repo_batch(self, client: httpx.AsyncClient, 
                                  repos: List[Dict]) -> List[DetectedRepo]:
        """Process a batch of repositories in parallel"""
        tasks = []
        for repo_data in repos:
            repo_id = repo_data.get('id')
            if repo_id in self.seen_repos:
                continue
            self.seen_repos.add(repo_id)
            tasks.append(self.analyze_repository(client, repo_data))
        
        if not tasks:
            return []
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        detections = []
        for result in results:
            if isinstance(result, Exception):
                continue
            if result is not None:
                detections.append(result)
        
        return detections
    
    async def search_and_analyze(self, client: httpx.AsyncClient, 
                                  query: str, max_results: int = 30) -> List[DetectedRepo]:
        """Search for repos and analyze them"""
        repos = await self.github.search_repositories(client, query, max_results)
        self.stats['total_repos_found'] += len(repos)
        
        if not repos:
            return []
        
        # Process repos in batches
        batch_size = REPO_CONCURRENT_LIMIT
        all_detections = []
        
        for i in range(0, len(repos), batch_size):
            batch = repos[i:i + batch_size]
            detections = await self.process_repo_batch(client, batch)
            all_detections.extend(detections)
            self.stats['repos_analyzed'] += len(batch)
        
        return all_detections
    
    async def quick_check(self, repo_url: str) -> Optional[DetectedRepo]:
        """Quick check a single repository"""
        match = re.match(r'https?://github\.com/([^/]+)/([^/]+)', repo_url)
        if not match:
            print(f"[X] Invalid GitHub URL: {repo_url}")
            return None
        
        owner, repo = match.groups()
        repo = repo.rstrip('/')  # Remove trailing slash if present
        
        async with httpx.AsyncClient(headers=self.github.headers) as client:
            repo_data = await self.github.get_repo(client, owner, repo)
            
            if not repo_data:
                print(f"[X] Repository not found: {owner}/{repo}")
                return None
            
            return await self.analyze_repository(client, repo_data)
    
    async def run_scan_async(self, queries: List[str] = None, max_per_query: int = 30):
        """Run full async malware scan"""
        print("""
+====================================================================+
|  DELTA FORCE MALWARE HUNTER v3.0 (ASYNC)                          |
|  Features: Cyrillic + Entropy + YARA + Async httpx                |
+====================================================================+
        """)
        
        print(f"[+] Mode: Async (httpx)")
        print(f"[+] YARA: {'Enabled' if self.yara.available else 'Disabled'}")
        print(f"[+] Entropy Analysis: Enabled (threshold: {ENTROPY_THRESHOLD})")
        print(f"[+] Concurrent searches: {SEARCH_CONCURRENT_LIMIT}")
        print(f"[+] Concurrent repo analyses: {REPO_CONCURRENT_LIMIT}")
        
        queries = queries or SEARCH_QUERIES
        total_queries = len(queries)
        
        print(f"\n[*] Starting scan with {total_queries} search queries...")
        start_time = time.time()
        
        async with httpx.AsyncClient(headers=self.github.headers, timeout=REQUEST_TIMEOUT) as client:
            # Process queries in batches
            batch_size = SEARCH_CONCURRENT_LIMIT
            
            for batch_idx in range(0, len(queries), batch_size):
                batch_queries = queries[batch_idx:batch_idx + batch_size]
                batch_num = batch_idx // batch_size + 1
                total_batches = (len(queries) + batch_size - 1) // batch_size
                
                print(f"\n[BATCH {batch_num}/{total_batches}] Processing {len(batch_queries)} queries...")
                
                # Create tasks for this batch
                tasks = [
                    self.search_and_analyze(client, query, max_per_query)
                    for query in batch_queries
                ]
                
                # Run batch concurrently
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for i, result in enumerate(batch_results):
                    query = batch_queries[i]
                    self.stats['total_queries'] += 1
                    
                    if isinstance(result, Exception):
                        print(f"  [X] '{query}': Error - {result}")
                        continue
                    
                    if result:
                        self.detected.extend(result)
                        high_count = len([d for d in result if d.severity == "HIGH"])
                        print(f"  [✓] '{query}': {len(result)} detected ({high_count} HIGH)")
                        
                        for detection in result:
                            emoji = "🔴" if detection.severity == "HIGH" else \
                                   "🟡" if detection.severity == "MEDIUM" else "🟢"
                            print(f"      {emoji} {detection.owner}/{detection.repo_name} (Score: {detection.suspicion_score})")
                    else:
                        print(f"  [·] '{query}': No threats detected")
                
                # Rate limit status
                print(f"  [RATE] {self.github.get_rate_limit_status()}")
                
                # Delay between batches
                if batch_idx + batch_size < len(queries):
                    await asyncio.sleep(SEARCH_DELAY)
        
        elapsed = time.time() - start_time
        
        print(f"\n{'='*60}")
        print(f"[*] SCAN COMPLETE in {elapsed:.1f}s")
        print(f"    Queries executed: {self.stats['total_queries']}")
        print(f"    Repos found: {self.stats['total_repos_found']}")
        print(f"    Repos analyzed: {len(self.seen_repos)}")
        print(f"    Malicious detected: {len(self.detected)}")
        print(f"      - HIGH: {len([d for d in self.detected if d.severity == 'HIGH'])}")
        print(f"      - MEDIUM: {len([d for d in self.detected if d.severity == 'MEDIUM'])}")
        print(f"      - LOW: {len([d for d in self.detected if d.severity == 'LOW'])}")
        print(f"{'='*60}\n")
        
        if self.detected:
            self.save_results()
        
        return self.detected
    
    def run_scan(self, queries: List[str] = None, max_per_query: int = 30):
        """Synchronous wrapper for async scan"""
        return asyncio.run(self.run_scan_async(queries, max_per_query))
    
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
        
        # Count homoglyph detections
        homoglyph_count = 0
        pattern_cluster_count = 0
        for d in self.detected:
            for ev in d.evidence:
                if "HOMOGLYPH" in ev or "MIXED_SCRIPT" in ev:
                    homoglyph_count += 1
                    break
            for ev in d.evidence:
                if "FILENAME_CLUSTER" in ev or "PATTERN_CLUSTER" in ev:
                    pattern_cluster_count += 1
                    break
        
        report = f"""# AUTOMATED MALWARE DETECTION REPORT

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Tool:** Delta Force Malware Hunter v3.0 (Async)

---

## SUMMARY

| Metric | Count |
|--------|-------|
| Total Detected | {total} |
| HIGH Severity | {high} |
| Cyrillic Obfuscation | {cyrillic} |
| Homoglyph Attacks | {homoglyph_count} |
| Pattern Clusters | {pattern_cluster_count} |
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

async def main():
    """Main entry point"""
    hunter = MalwareHunter()
    
    if len(sys.argv) > 1:
        repo_url = sys.argv[1]
        print(f"[*] Quick checking: {repo_url}\n")
        result = await hunter.quick_check(repo_url)
        
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
        await hunter.run_scan_async()

if __name__ == "__main__":
    asyncio.run(main())