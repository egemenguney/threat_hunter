#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Check if detected repos still exist (200) or are deleted (404)
Updates detected_repos.json with current status
"""

import json
import asyncio
import httpx
from pathlib import Path
from datetime import datetime
import os

# Load token from .env.local
ENV_FILE = Path(__file__).parent / '.env.local'
if ENV_FILE.exists():
    with open(ENV_FILE, 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value.strip('"\'')

GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
DETECTED_REPOS_FILE = Path(__file__).parent / 'detected_repos.json'

async def check_repo_exists(client: httpx.AsyncClient, repo_url: str) -> tuple[str, int, str]:
    """Check if a repo exists. Returns (url, status_code, status_text)"""
    try:
        # Convert github.com URL to API URL
        # https://github.com/owner/repo -> https://api.github.com/repos/owner/repo
        parts = repo_url.replace('https://github.com/', '').split('/')
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            
            response = await client.get(api_url)
            
            if response.status_code == 200:
                return (repo_url, 200, "EXISTS")
            elif response.status_code == 404:
                return (repo_url, 404, "DELETED")
            elif response.status_code == 403:
                return (repo_url, 403, "RATE_LIMITED")
            else:
                return (repo_url, response.status_code, f"HTTP_{response.status_code}")
        else:
            return (repo_url, 0, "INVALID_URL")
    except Exception as e:
        return (repo_url, 0, f"ERROR: {str(e)[:50]}")

async def check_all_repos(repos: list, batch_size: int = 50) -> dict:
    """Check all repos in batches"""
    
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'ThreatHunter-StatusChecker/1.0'
    }
    if GITHUB_TOKEN:
        headers['Authorization'] = f'token {GITHUB_TOKEN}'
    
    results = {
        'EXISTS': [],
        'DELETED': [],
        'RATE_LIMITED': [],
        'ERROR': []
    }
    
    async with httpx.AsyncClient(headers=headers, timeout=30.0) as client:
        # Check rate limit first
        rate_resp = await client.get('https://api.github.com/rate_limit')
        if rate_resp.status_code == 200:
            rate_data = rate_resp.json()
            remaining = rate_data['resources']['core']['remaining']
            print(f"[RATE] API calls remaining: {remaining}")
            
            if remaining < len(repos):
                print(f"[WARNING] Not enough API calls! Need {len(repos)}, have {remaining}")
                print(f"[INFO] Will check first {remaining} repos")
                repos = repos[:remaining]
        
        total = len(repos)
        print(f"[INFO] Checking {total} repositories...")
        
        for i in range(0, total, batch_size):
            batch = repos[i:i+batch_size]
            batch_urls = [r['url'] for r in batch]
            
            tasks = [check_repo_exists(client, url) for url in batch_urls]
            batch_results = await asyncio.gather(*tasks)
            
            for url, status_code, status_text in batch_results:
                if status_text == "EXISTS":
                    results['EXISTS'].append(url)
                elif status_text == "DELETED":
                    results['DELETED'].append(url)
                elif status_text == "RATE_LIMITED":
                    results['RATE_LIMITED'].append(url)
                else:
                    results['ERROR'].append((url, status_text))
            
            checked = min(i + batch_size, total)
            deleted_count = len(results['DELETED'])
            print(f"[PROGRESS] {checked}/{total} checked | {deleted_count} deleted found")
            
            # Small delay between batches
            if i + batch_size < total:
                await asyncio.sleep(0.5)
    
    return results

def update_detected_repos(results: dict):
    """Update detected_repos.json with deletion status"""
    
    with open(DETECTED_REPOS_FILE, 'r', encoding='utf-8') as f:
        repos = json.load(f)
    
    deleted_urls = set(results['DELETED'])
    
    updated_count = 0
    removed_count = 0
    
    # Option 1: Mark as DELETED
    # Option 2: Remove from list
    
    # We'll remove deleted repos from the list
    new_repos = []
    for repo in repos:
        if repo['url'] in deleted_urls:
            removed_count += 1
            print(f"[REMOVED] {repo['url']}")
        else:
            new_repos.append(repo)
    
    # Save updated list
    with open(DETECTED_REPOS_FILE, 'w', encoding='utf-8') as f:
        json.dump(new_repos, f, indent=2, ensure_ascii=False)
    
    print(f"\n[UPDATED] Removed {removed_count} deleted repos")
    print(f"[UPDATED] {len(new_repos)} repos remaining in detected_repos.json")
    
    return removed_count

async def main():
    print("=" * 60)
    print("REPOSITORY STATUS CHECKER")
    print("=" * 60)
    print(f"Token: {'✓ Loaded' if GITHUB_TOKEN else '✗ Not found'}")
    print()
    
    # Load repos
    with open(DETECTED_REPOS_FILE, 'r', encoding='utf-8') as f:
        repos = json.load(f)
    
    print(f"[LOADED] {len(repos)} repositories from detected_repos.json")
    
    # Check all repos
    results = await check_all_repos(repos)
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"✓ EXISTS:       {len(results['EXISTS'])}")
    print(f"✗ DELETED:      {len(results['DELETED'])}")
    print(f"⚠ RATE LIMITED: {len(results['RATE_LIMITED'])}")
    print(f"? ERRORS:       {len(results['ERROR'])}")
    
    if results['DELETED']:
        print(f"\n[INFO] Found {len(results['DELETED'])} deleted repositories!")
        
        # Ask to update (or auto-update in CI)
        response = input("\nRemove deleted repos from detected_repos.json? [y/N]: ").strip().lower()
        if response == 'y':
            update_detected_repos(results)
        else:
            print("[SKIPPED] No changes made")
            # Still save deleted list for reference
            with open('deleted_repos.json', 'w', encoding='utf-8') as f:
                json.dump(results['DELETED'], f, indent=2)
            print(f"[SAVED] Deleted repos list saved to deleted_repos.json")
    else:
        print("\n[INFO] No deleted repositories found. All repos still exist.")

if __name__ == "__main__":
    asyncio.run(main())
