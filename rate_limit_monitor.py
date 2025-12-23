#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rate Limit Monitor for Threat Hunter
Monitors GitHub API rate limits and provides alerts

Usage:
    python rate_limit_monitor.py           # Check current status
    python rate_limit_monitor.py --watch   # Continuous monitoring
    python rate_limit_monitor.py --json    # JSON output

Author: Security Research
Date: December 2025
"""

import os
import sys
import time
import json
import argparse
from datetime import datetime, timedelta
from typing import Dict, Optional

try:
    import httpx
except ImportError:
    print("Error: httpx not installed. Run: pip install httpx")
    sys.exit(1)

# Configuration
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_API = "https://api.github.com"

# Thresholds
CRITICAL_THRESHOLD = 100
WARNING_THRESHOLD = 500
SAFE_THRESHOLD = 1000

# Colors for terminal output
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def get_rate_limit_status() -> Optional[Dict]:
    """Fetch current rate limit status from GitHub API"""
    headers = {}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    
    try:
        response = httpx.get(
            f"{GITHUB_API}/rate_limit",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching rate limit: {e}")
        return None


def format_timestamp(timestamp: int) -> str:
    """Convert Unix timestamp to readable format"""
    dt = datetime.fromtimestamp(timestamp)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def get_time_until_reset(reset_timestamp: int) -> str:
    """Calculate time until rate limit reset"""
    now = datetime.now()
    reset_time = datetime.fromtimestamp(reset_timestamp)
    delta = reset_time - now
    
    if delta.total_seconds() < 0:
        return "NOW"
    
    minutes = int(delta.total_seconds() / 60)
    seconds = int(delta.total_seconds() % 60)
    
    if minutes > 60:
        hours = minutes // 60
        minutes = minutes % 60
        return f"{hours}h {minutes}m"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"


def get_status_color(remaining: int, limit: int) -> str:
    """Get color based on remaining quota"""
    percentage = (remaining / limit * 100) if limit > 0 else 0
    
    if remaining < CRITICAL_THRESHOLD or percentage < 10:
        return Colors.RED
    elif remaining < WARNING_THRESHOLD or percentage < 20:
        return Colors.YELLOW
    else:
        return Colors.GREEN


def get_status_emoji(remaining: int, limit: int) -> str:
    """Get emoji based on remaining quota"""
    percentage = (remaining / limit * 100) if limit > 0 else 0
    
    if remaining < CRITICAL_THRESHOLD or percentage < 10:
        return "🔴"
    elif remaining < WARNING_THRESHOLD or percentage < 20:
        return "🟡"
    else:
        return "🟢"


def print_status(data: Dict, json_output: bool = False) -> None:
    """Print rate limit status in human-readable format"""
    if json_output:
        print(json.dumps(data, indent=2))
        return
    
    resources = data.get("resources", {})
    
    print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}🔍 GitHub API Rate Limit Status{Colors.END}")
    print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")
    print(f"⏰ Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🔑 Token: {'✅ Authenticated' if GITHUB_TOKEN else '❌ Unauthenticated'}\n")
    
    # Core API
    core = resources.get("core", {})
    core_remaining = core.get("remaining", 0)
    core_limit = core.get("limit", 0)
    core_reset = core.get("reset", 0)
    core_color = get_status_color(core_remaining, core_limit)
    core_emoji = get_status_emoji(core_remaining, core_limit)
    
    print(f"{Colors.BOLD}📦 Core API{Colors.END}")
    print(f"  Status: {core_emoji} {core_color}{core_remaining}/{core_limit}{Colors.END}")
    print(f"  Percentage: {core_color}{(core_remaining/core_limit*100):.1f}%{Colors.END}")
    print(f"  Reset: {format_timestamp(core_reset)} ({get_time_until_reset(core_reset)})")
    
    # Search API
    search = resources.get("search", {})
    search_remaining = search.get("remaining", 0)
    search_limit = search.get("limit", 0)
    search_reset = search.get("reset", 0)
    search_color = get_status_color(search_remaining, search_limit)
    search_emoji = get_status_emoji(search_remaining, search_limit)
    
    print(f"\n{Colors.BOLD}🔍 Search API{Colors.END}")
    print(f"  Status: {search_emoji} {search_color}{search_remaining}/{search_limit}{Colors.END}")
    print(f"  Percentage: {search_color}{(search_remaining/search_limit*100):.1f}%{Colors.END}")
    print(f"  Reset: {format_timestamp(search_reset)} ({get_time_until_reset(search_reset)})")
    
    # GraphQL API
    graphql = resources.get("graphql", {})
    if graphql:
        graphql_remaining = graphql.get("remaining", 0)
        graphql_limit = graphql.get("limit", 0)
        graphql_reset = graphql.get("reset", 0)
        graphql_color = get_status_color(graphql_remaining, graphql_limit)
        graphql_emoji = get_status_emoji(graphql_remaining, graphql_limit)
        
        print(f"\n{Colors.BOLD}📊 GraphQL API{Colors.END}")
        print(f"  Status: {graphql_emoji} {graphql_color}{graphql_remaining}/{graphql_limit}{Colors.END}")
        print(f"  Percentage: {graphql_color}{(graphql_remaining/graphql_limit*100):.1f}%{Colors.END}")
        print(f"  Reset: {format_timestamp(graphql_reset)} ({get_time_until_reset(graphql_reset)})")
    
    # Warnings
    print(f"\n{Colors.BOLD}⚠️  Alerts{Colors.END}")
    alerts = []
    
    if core_remaining < CRITICAL_THRESHOLD:
        alerts.append(f"{Colors.RED}🔴 CRITICAL: Core API below {CRITICAL_THRESHOLD}!{Colors.END}")
    elif core_remaining < WARNING_THRESHOLD:
        alerts.append(f"{Colors.YELLOW}🟡 WARNING: Core API below {WARNING_THRESHOLD}{Colors.END}")
    
    if search_remaining < 5:
        alerts.append(f"{Colors.RED}🔴 CRITICAL: Search API below 5!{Colors.END}")
    elif search_remaining < 10:
        alerts.append(f"{Colors.YELLOW}🟡 WARNING: Search API below 10{Colors.END}")
    
    if alerts:
        for alert in alerts:
            print(f"  {alert}")
    else:
        print(f"  {Colors.GREEN}✅ All systems operating normally{Colors.END}")
    
    print(f"\n{Colors.BOLD}{'='*70}{Colors.END}\n")


def watch_mode(interval: int = 60) -> None:
    """Continuously monitor rate limits"""
    print(f"🔄 Watching rate limits (refresh every {interval}s). Press Ctrl+C to stop.\n")
    
    try:
        while True:
            data = get_rate_limit_status()
            if data:
                # Clear screen
                os.system('clear' if os.name != 'nt' else 'cls')
                print_status(data)
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n✋ Monitoring stopped by user.")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor GitHub API rate limits for Threat Hunter"
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuous monitoring mode"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Refresh interval in seconds (default: 60)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )
    
    args = parser.parse_args()
    
    if not GITHUB_TOKEN and not args.json:
        print(f"{Colors.YELLOW}⚠️  Warning: No GITHUB_TOKEN found in environment.{Colors.END}")
        print(f"{Colors.YELLOW}   You'll see unauthenticated limits (60/hour for core API).{Colors.END}")
        print(f"{Colors.YELLOW}   Set GITHUB_TOKEN for authenticated limits (5000/hour).{Colors.END}\n")
    
    if args.watch:
        watch_mode(args.interval)
    else:
        data = get_rate_limit_status()
        if data:
            print_status(data, args.json)
        else:
            print(f"{Colors.RED}❌ Failed to fetch rate limit status{Colors.END}")
            sys.exit(1)


if __name__ == "__main__":
    main()
