#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detection Statistics Analyzer for Threat Hunter
Analyzes detected_repos.json and generates insights

Usage:
    python analyze_detections.py                    # Full analysis
    python analyze_detections.py --top 20           # Show top 20 threats
    python analyze_detections.py --false-positive   # Flag potential false positives

Author: Security Research
Date: December 2025
"""

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import argparse
import statistics


def load_detections(filepath: str = "detected_repos.json") -> List[Dict[str, Any]]:
    """Load detections from JSON file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: {filepath} not found")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"❌ Error: Invalid JSON in {filepath}")
        sys.exit(1)


def analyze_severity(detections: List[Dict]) -> Dict[str, int]:
    """Analyze severity distribution"""
    severity_counts = Counter()
    for d in detections:
        severity = d.get('severity', 'UNKNOWN')
        severity_counts[severity] += 1
    return dict(severity_counts)


def analyze_detection_types(detections: List[Dict]) -> Dict[str, int]:
    """Analyze detection type distribution"""
    type_counts = Counter()
    for d in detections:
        det_type = d.get('detection_type', 'UNKNOWN')
        type_counts[det_type] += 1
    return dict(type_counts)


def analyze_scores(detections: List[Dict]) -> Dict[str, Any]:
    """Analyze score distribution"""
    scores = [d.get('suspicion_score', 0) for d in detections]
    
    if not scores:
        return {}
    
    return {
        'min': min(scores),
        'max': max(scores),
        'avg': sum(scores) / len(scores),
        'median': statistics.median(scores),
        'critical_90_plus': len([s for s in scores if s >= 90]),
        'very_high_70_89': len([s for s in scores if 70 <= s < 90]),
        'high_50_69': len([s for s in scores if 50 <= s < 70]),
        'medium_30_49': len([s for s in scores if 30 <= s < 50]),
        'low_below_30': len([s for s in scores if s < 30])
    }


def get_top_threats(detections: List[Dict], n: int = 20) -> List[Dict]:
    """Get top N threats by score"""
    sorted_detections = sorted(
        detections,
        key=lambda x: x.get('suspicion_score', 0),
        reverse=True
    )
    return sorted_detections[:n]


def identify_potential_false_positives(detections: List[Dict]) -> List[Dict]:
    """Identify potential false positives based on heuristics"""
    potential_fps = []
    
    for d in detections:
        score = d.get('suspicion_score', 0)
        detection_type = d.get('detection_type', '')
        reasons = d.get('detection_reasons', [])
        
        # Heuristic 1: Low score but marked as HIGH severity
        if score < 40 and d.get('severity') == 'HIGH':
            potential_fps.append({
                **d,
                'fp_reason': 'Low score for HIGH severity'
            })
        
        # Heuristic 2: Only single detection reason
        elif len(reasons) == 1 and score < 60:
            potential_fps.append({
                **d,
                'fp_reason': 'Single detection reason with moderate score'
            })
        
        # Heuristic 3: Very generic repo names
        elif score < 70:
            repo_name = d.get('repo_name', '').lower()
            generic_patterns = ['test', 'demo', 'example', 'sample', 'tutorial']
            if any(pattern in repo_name for pattern in generic_patterns):
                potential_fps.append({
                    **d,
                    'fp_reason': 'Generic repo name pattern'
                })
    
    return potential_fps


def print_analysis(detections: List[Dict], args: argparse.Namespace) -> None:
    """Print comprehensive analysis"""
    total = len(detections)
    
    print("\n" + "="*70)
    print("📊 THREAT HUNTER - DETECTION STATISTICS")
    print("="*70 + "\n")
    
    print(f"📁 Total Repositories Detected: {total}")
    print(f"⏰ Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Severity Distribution
    print("🔴 SEVERITY DISTRIBUTION")
    print("-" * 70)
    severity_dist = analyze_severity(detections)
    for severity, count in sorted(severity_dist.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total * 100) if total > 0 else 0
        emoji = "🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🟢"
        print(f"  {emoji} {severity:12s}: {count:4d} ({percentage:5.1f}%)")
    print()
    
    # Detection Type Distribution
    print("🎯 DETECTION TYPE DISTRIBUTION")
    print("-" * 70)
    type_dist = analyze_detection_types(detections)
    for det_type, count in sorted(type_dist.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total * 100) if total > 0 else 0
        print(f"  • {det_type:25s}: {count:4d} ({percentage:5.1f}%)")
    print()
    
    # Score Analysis
    print("📈 SCORE DISTRIBUTION")
    print("-" * 70)
    score_stats = analyze_scores(detections)
    print(f"  Minimum Score:      {score_stats.get('min', 0)}")
    print(f"  Maximum Score:      {score_stats.get('max', 0)}")
    print(f"  Average Score:      {score_stats.get('avg', 0):.1f}")
    print(f"  Median Score:       {score_stats.get('median', 0)}")
    print()
    print("  Score Ranges:")
    print(f"    🔴 90-100 (CRITICAL):   {score_stats.get('critical_90_plus', 0):4d} repos")
    print(f"    🔴 70-89  (VERY HIGH):  {score_stats.get('very_high_70_89', 0):4d} repos")
    print(f"    🟡 50-69  (HIGH):       {score_stats.get('high_50_69', 0):4d} repos")
    print(f"    🟡 30-49  (MEDIUM):     {score_stats.get('medium_30_49', 0):4d} repos")
    print(f"    🟢 0-29   (LOW):        {score_stats.get('low_below_30', 0):4d} repos")
    print()
    
    # Top Threats
    if args.top:
        print(f"🎯 TOP {args.top} THREATS BY SCORE")
        print("-" * 70)
        top_threats = get_top_threats(detections, args.top)
        for i, threat in enumerate(top_threats, 1):
            owner = threat.get('owner', 'unknown')
            repo = threat.get('repo_name', 'unknown')
            score = threat.get('suspicion_score', 0)
            det_type = threat.get('detection_type', 'unknown')
            print(f"  {i:2d}. [{score:3d}/100] {owner}/{repo}")
            print(f"      Type: {det_type}")
        print()
    
    # False Positive Analysis
    potential_fps = None
    if args.false_positive:
        print("🔍 POTENTIAL FALSE POSITIVE ANALYSIS")
        print("-" * 70)
        potential_fps = identify_potential_false_positives(detections)
        print(f"  Found {len(potential_fps)} potential false positives ({len(potential_fps)/total*100:.1f}%)")
        print()
        
        if potential_fps and args.verbose:
            print("  Top 10 Potential False Positives:")
            for i, fp in enumerate(potential_fps[:10], 1):
                owner = fp.get('owner', 'unknown')
                repo = fp.get('repo_name', 'unknown')
                score = fp.get('suspicion_score', 0)
                reason = fp.get('fp_reason', 'unknown')
                print(f"    {i:2d}. {owner}/{repo} (Score: {score})")
                print(f"        Reason: {reason}")
        print()
    
    # Recommendations
    print("💡 RECOMMENDATIONS")
    print("-" * 70)
    high_severity_count = severity_dist.get('HIGH', 0)
    
    if high_severity_count > 1000:
        print("  ⚠️  URGENT: Very high number of HIGH severity detections")
        print("      → Conduct false positive analysis")
        print("      → Review and tune YARA rules")
        print("      → Implement two-stage verification")
    
    if score_stats.get('critical_90_plus', 0) > 100:
        print("  🔴 CRITICAL: 100+ repos with score ≥90")
        print("      → Prioritize these for immediate reporting")
        print("      → Enable auto-reporter for critical threats")
    
    # Calculate false positive percentage only if not already calculated
    if potential_fps is None:
        potential_fps = identify_potential_false_positives(detections)
    potential_fp_percentage = len(potential_fps) / total * 100
    if potential_fp_percentage > 20:
        print(f"  ⚠️  WARNING: {potential_fp_percentage:.1f}% potential false positives")
        print("      → Manual verification recommended")
        print("      → Consider adjusting detection thresholds")
    
    print("\n" + "="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Threat Hunter detection statistics"
    )
    parser.add_argument(
        "--file",
        default="detected_repos.json",
        help="Path to detected_repos.json (default: detected_repos.json)"
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Number of top threats to show (default: 20)"
    )
    parser.add_argument(
        "--false-positive",
        action="store_true",
        help="Identify potential false positives"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    
    args = parser.parse_args()
    
    detections = load_detections(args.file)
    print_analysis(detections, args)


if __name__ == "__main__":
    main()
