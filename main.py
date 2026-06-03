#!/usr/bin/env python3
"""
AWS VDP Security Audit Pipeline v2 — Main Orchestrator

Usage:
    python main.py --kimi-api-key YOUR_KEY
    python main.py --max-repos 50 --batch-size 10
    python main.py --resume --workers 5
"""
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import time
import json
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from config.settings import (
    KIMI_API_KEY, KIMI_BASE_URL, KIMI_AUDIT_MODEL, GITHUB_TOKEN,
    BATCH_SIZE, MAX_REPOS, MAX_REPO_SIZE_MB, CLONE_DEPTH, CLONE_TIMEOUT,
    CLEANUP_AFTER_AUDIT, REPOS_DIR, REPORTS_DIR, DASHBOARD_DIR, SCOPES_CSV,
    MAX_WORKERS, MIN_DISK_GB, logger, compute_repo_id, get_settings_summary,
    validate_config,
)
from core.state_manager import StateManager
from core.disk_monitor import DiskMonitor
from core.progress_ui import ProgressUI, print_startup_banner
from core.clone_manager import clone_repo, get_repo_size_mb, cleanup_repo, get_audit_files
from core.audit_engine import audit_repo
from core.verification import verify_findings, filter_false_positives, deduplicate_findings
from core.reporter import generate_repo_report, generate_json_report, generate_html_dashboard


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="AWS VDP Security Audit Pipeline v2 — AI-Powered",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --kimi-api-key $KIMI_API_KEY
  python main.py --max-repos 100 --workers 5 --batch-size 10
  python main.py --resume --workers 3
  python main.py --only-direct --no-cleanup --severity-filter High
  python main.py --skip-orgs --max-repos 50
        """
    )
    parser.add_argument('--scopes-csv', type=Path, default=SCOPES_CSV, help='Path to scopes CSV')
    parser.add_argument('--max-repos', type=int, default=MAX_REPOS, help='Max repos to audit (0=unlimited)')
    parser.add_argument('--batch-size', type=int, default=BATCH_SIZE, help='Repos per batch')
    parser.add_argument('--workers', type=int, default=MAX_WORKERS, help='Parallel workers')
    parser.add_argument('--skip-orgs', action='store_true', help='Skip org enumeration')
    parser.add_argument('--only-direct', action='store_true', help='Only CSV direct repos')
    parser.add_argument('--resume', action='store_true', help='Resume interrupted run')
    parser.add_argument('--no-cleanup', action='store_true', help='Keep cloned repos')
    parser.add_argument('--severity-filter', choices=['Critical','High','Medium','Low','Info'], help='Min severity')
    parser.add_argument('--github-token', default=GITHUB_TOKEN, help='GitHub PAT')
    parser.add_argument('--kimi-api-key', default=KIMI_API_KEY, help='Kimi API key')
    parser.add_argument('--test-audit', action='store_true', help='Run a single test audit and exit')
    parser.add_argument('--verbose', '-v', action='store_true', help='Debug output')
    return parser


def discover_repos(args) -> list:
    """Discover all repos in scope."""
    state = StateManager()
    repos = []
    
    # Direct repos from CSV
    try:
        import csv
        with open(args.scopes_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                identifier = row.get('identifier', '').strip()
                asset_type = row.get('asset_type', '').strip()
                
                # Direct GitHub URLs
                if identifier.startswith('https://github.com/'):
                    # Handle wildcard orgs
                    if identifier.endswith('/*'):
                        org = identifier.replace('https://github.com/', '').replace('/*', '')
                        repos.extend(_enumerate_org(org, args.github_token))
                    else:
                        full_name = identifier.replace('https://github.com/', '')
                        repos.append({'full_name': full_name, 'url': identifier, 'source': 'csv_direct'})
                
                # Map notable OSS projects
                elif asset_type == 'OTHER':
                    mapped = _map_oss_name(identifier)
                    if mapped:
                        repos.append({'full_name': mapped, 'url': f'https://github.com/{mapped}', 'source': f'oss:{identifier}'})
    except Exception as e:
        logger.error(f"CSV read error: {e}")
    
    # Enumerate orgs
    if not args.skip_orgs and not args.only_direct:
        for org in ['aws-samples', 'awslabs', 'amazon-research']:
            repos.extend(_enumerate_org(org, args.github_token))
    
    # Also add the main aws org repos (SDKs, CLI, CDK, etc.)
    key_repos = [
        'aws/aws-cli', 'aws/aws-sdk-python', 'aws/aws-sdk-js', 'aws/aws-sdk-java',
        'aws/aws-sdk-go', 'aws/aws-sdk-ruby', 'aws/aws-sdk-net', 'aws/aws-sdk-php',
        'aws/aws-sdk-cpp', 'aws/aws-cdk', 'aws/aws-sam-cli', 'aws/chalice',
        'aws-amplify/amplify-cli', 'aws/s2n-tls', 'aws/amazon-ecs-agent',
        'firecracker-microvm/firecracker', 'bottlerocket-os/bottlerocket',
        'opensearch-project/OpenSearch', 'corretto/corretto-17',
        'FreeRTOS/FreeRTOS',
    ]
    for rn in key_repos:
        repos.append({'full_name': rn, 'url': f'https://github.com/{rn}', 'source': 'key_repo'})
    
    # Deduplicate
    seen = set()
    unique = []
    for r in repos:
        if r['full_name'] not in seen:
            seen.add(r['full_name'])
            unique.append(r)
    
    # Save to state
    for r in unique:
        rid = compute_repo_id(r['full_name'])
        state.upsert_repo(rid, r['full_name'], r['url'], r['source'])
    
    return unique


def _enumerate_org(org: str, token: str) -> list:
    """Enumerate repos in a GitHub org via API."""
    import requests
    repos = []
    headers = {'Accept': 'application/vnd.github.v3+json'}
    if token:
        headers['Authorization'] = f'token {token}'
    
    page = 1
    while page <= 10:  # Max 1000 repos per org
        try:
            resp = requests.get(
                f'https://api.github.com/orgs/{org}/repos',
                headers=headers,
                params={'per_page': 100, 'page': page, 'type': 'sources'},
                timeout=30
            )
            if resp.status_code != 200:
                break
            data = resp.json()
            if not data:
                break
            for r in data:
                if not r.get('fork', False) and not r.get('archived', False):
                    repos.append({
                        'full_name': r['full_name'],
                        'url': r['html_url'],
                        'source': f'org:{org}'
                    })
            page += 1
        except Exception as e:
            logger.warning(f"Org enumeration error for {org}: {e}")
            break
    
    logger.info(f"Enumerated {len(repos)} repos from {org}")
    return repos


def _map_oss_name(name: str) -> str:
    """Map service name to GitHub repo."""
    mapping = {
        'Firecracker': 'firecracker-microvm/firecracker',
        'FreeRTOS': 'FreeRTOS/FreeRTOS',
        'Bottlerocket': 'bottlerocket-os/bottlerocket',
        'OpenSearch': 'opensearch-project/OpenSearch',
        'Open Distro': 'opensearch-project/OpenSearch',
        'Babelfish': 'babelfish-for-postgresql/postgresql_modified_for_babelfish',
        'PartiQL': 'partiql/partiql-lang-kotlin',
        'Corretto': 'corretto/corretto-17',
        'Blazegraph': 'blazegraph/database',
        'Blox': 'aws/blox',
    }
    return mapping.get(name)


def audit_single_repo(repo_info: dict, args, ui: ProgressUI, state: StateManager, 
                      counter: dict, lock: Lock):
    """Audit a single repository — called by thread pool."""
    rid = compute_repo_id(repo_info['full_name'])
    repo_name = repo_info['full_name']
    
    with lock:
        counter['current'] += 1
        idx = counter['current']
        state.mark_started(rid)
    
    ui.print_repo_start(idx, counter['total'], repo_name, repo_info.get('source', ''))
    
    try:
        # Check disk
        if not DiskMonitor.has_enough_space(REPOS_DIR, MIN_DISK_GB):
            ui.print_error("Insufficient disk space!")
            state.mark_failed(rid, "Disk full")
            return None
        
        # Clone
        ui.print_stage("Cloning repository", "running")
        repo_path = clone_repo(repo_name, REPOS_DIR, CLONE_DEPTH, CLONE_TIMEOUT)
        if not repo_path:
            ui.print_stage("Cloning repository", "error")
            state.mark_failed(rid, "Clone failed")
            with lock:
                counter['failed'] += 1
            return None
        ui.print_stage("Cloning repository", "done")
        
        # Size check
        size_mb = get_repo_size_mb(repo_path)
        if size_mb > MAX_REPO_SIZE_MB:
            ui.print_warning(f"Repo too large ({size_mb:.0f}MB > {MAX_REPO_SIZE_MB}MB), skipping")
            cleanup_repo(repo_path)
            state.mark_failed(rid, f"Too large: {size_mb}MB")
            with lock:
                counter['skipped'] += 1
            return None
        
        # Extract files
        ui.print_stage("Extracting source files", "running")
        files = get_audit_files(repo_path)
        if not files:
            ui.print_stage("Extracting source files", "skip")
            cleanup_repo(repo_path)
            state.mark_completed(rid, 0, {})
            with lock:
                counter['completed'] += 1
            return None
        ui.print_stage(f"Extracting source files ({len(files)} files)", "done")
        
        # AI Audit
        ui.print_stage("AI security analysis (Kimi)", "running")
        start = time.time()
        result = audit_repo(repo_name, files, {'repo_id': rid})
        duration = time.time() - start
        ui.print_stage(f"AI security analysis ({duration:.1f}s)", "done")
        
        # Verify findings
        if result.get('findings'):
            ui.print_stage("Verifying findings", "running")
            result['findings'] = verify_findings(result['findings'], files)
            result['findings'] = filter_false_positives(result['findings'])
            result['findings'] = deduplicate_findings(result['findings'])
            ui.print_stage(f"Verifying findings ({len(result['findings'])} valid)", "done")
            
            # Print findings
            for f in sorted(result['findings'], 
                          key=lambda x: {'Critical':5,'High':4,'Medium':3,'Low':2,'Info':1}.get(x.get('severity','Info'),0),
                          reverse=True)[:5]:  # Show top 5
                ui.print_finding(f)
        else:
            ui.print_stage("Verifying findings", "skip")
        
        # Severity filter
        if args.severity_filter:
            rank = {'Critical':5,'High':4,'Medium':3,'Low':2,'Info':1}
            min_rank = rank.get(args.severity_filter, 0)
            result['findings'] = [f for f in result.get('findings', []) 
                                  if rank.get(f.get('severity','Info'),0) >= min_rank]
        
        # Save findings to state
        for finding in result.get('findings', []):
            state.save_finding(rid, finding)
        
        # Generate reports
        ui.print_stage("Generating reports", "running")
        generate_repo_report(result, REPORTS_DIR)
        generate_json_report(result, REPORTS_DIR)
        ui.print_stage("Generating reports", "done")
        
        # Update state
        summary = result.get('summary', {})
        state.mark_completed(rid, duration, {
            'files_analyzed': summary.get('total_files', 0),
            'critical': summary.get('critical_count', 0),
            'high': summary.get('high_count', 0),
            'medium': summary.get('medium_count', 0),
            'low': summary.get('low_count', 0),
            'info': summary.get('info_count', 0),
            'total': summary.get('total_findings', 0),
        })
        
        # Cleanup
        if not args.no_cleanup:
            cleanup_repo(repo_path)
        
        # Summary
        ui.print_repo_summary(
            len(result.get('findings', [])),
            summary
        )
        
        with lock:
            counter['completed'] += 1
            counter['findings'] += len(result.get('findings', []))
        
        return result
    
    except Exception as e:
        ui.print_error(f"Audit failed: {e}")
        state.mark_failed(rid, str(e))
        with lock:
            counter['failed'] += 1
        # Cleanup on failure
        repo_path = REPOS_DIR / repo_name.replace('/', '_')
        cleanup_repo(repo_path)
        return None


def run_test_audit(args):
    """Run a single test audit with a small repo."""
    print_startup_banner()
    
    ui = ProgressUI(total_repos=1)
    ui.print_stage_header("TEST AUDIT MODE")
    
    # Use a small AWS repo for testing
    test_repo = {'full_name': 'aws/aws-cli', 'url': 'https://github.com/aws/aws-cli', 'source': 'test'}
    
    state = StateManager()
    rid = compute_repo_id(test_repo['full_name'])
    state.upsert_repo(rid, test_repo['full_name'], test_repo['url'], 'test')
    
    ui.print_repo_start(1, 1, test_repo['full_name'], 'test')
    
    try:
        # Clone
        ui.print_stage("Cloning repository", "running")
        repo_path = clone_repo(test_repo['full_name'], REPOS_DIR, depth=1, timeout=300)
        if not repo_path:
            ui.print_error("Clone failed!")
            return 1
        ui.print_stage("Cloning repository", "done")
        
        # Extract files
        ui.print_stage("Extracting source files", "running")
        files = get_audit_files(repo_path)
        ui.print_stage(f"Extracting source files ({len(files)} files)", "done")
        
        if not files:
            ui.print_error("No files to analyze!")
            cleanup_repo(repo_path)
            return 1
        
        # AI Audit
        ui.print_stage("AI security analysis (Kimi)", "running")
        start = time.time()
        result = audit_repo(test_repo['full_name'], files, {'repo_id': rid})
        duration = time.time() - start
        ui.print_stage(f"AI security analysis ({duration:.1f}s)", "done")
        
        # Verify
        if result.get('findings'):
            ui.print_stage("Verifying findings", "running")
            result['findings'] = verify_findings(result['findings'], files)
            result['findings'] = filter_false_positives(result['findings'])
            ui.print_stage(f"Verifying findings ({len(result['findings'])} valid)", "done")
            
            for f in sorted(result['findings'],
                          key=lambda x: {'Critical':5,'High':4,'Medium':3,'Low':2,'Info':1}.get(x.get('severity','Info'),0),
                          reverse=True):
                ui.print_finding(f)
        
        # Reports
        ui.print_stage("Generating reports", "running")
        md_path = generate_repo_report(result, REPORTS_DIR)
        json_path = generate_json_report(result, REPORTS_DIR)
        ui.print_stage("Generating reports", "done")
        
        ui.print_success(f"Markdown report: {md_path}")
        ui.print_success(f"JSON report: {json_path}")
        
        # Cleanup
        cleanup_repo(repo_path)
        
        # Stats
        stats = state.get_stats()
        ui.print_stats(stats)
        
        summary = result.get('summary', {})
        ui.print_repo_summary(len(result.get('findings', [])), summary)
        
        if result.get('findings'):
            ui.print_success(f"\nFound {len(result['findings'])} security finding(s)!")
            return 0
        else:
            ui.print_success("No findings — repo looks clean!")
            return 0
    
    except Exception as e:
        ui.print_error(f"Test audit failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


def run_pipeline(args):
    """Run the full audit pipeline."""
    start_time = time.time()
    
    print_startup_banner()
    
    # Validate config
    issues = validate_config()
    for issue in issues:
        if issue.startswith('ERROR'):
            print(f"\033[91m{issue}\033[0m")
            return 1
        else:
            print(f"\033[93m{issue}\033[0m")
    
    # Override API key if provided
    if args.kimi_api_key:
        os.environ['KIMI_API_KEY'] = args.kimi_api_key
        import importlib
        import config.settings
        importlib.reload(config.settings)
        from config.settings import KIMI_API_KEY as KIMI_KEY
        if not KIMI_KEY:
            print("\033[91mERROR: Kimi API key not set!\033[0m")
            return 1
    
    # Settings summary
    ui = ProgressUI()
    ui.print_config([
        f"Kimi API: {KIMI_BASE_URL} (model: {KIMI_AUDIT_MODEL})",
        f"GitHub Token: {'Set' if (args.github_token or GITHUB_TOKEN) else 'Not set (limited rate)'}",
        f"Workers: {args.workers} | Batch Size: {args.batch_size}",
        f"Max Repos: {args.max_repos if args.max_repos else 'Unlimited'}",
        f"Max Repo Size: {MAX_REPO_SIZE_MB}MB | Min Disk: {MIN_DISK_GB}GB",
        f"Severity Filter: {args.severity_filter or 'None'}",
        f"Cleanup: {'No' if args.no_cleanup else 'Yes'}",
        f"Mode: {'Resume' if args.resume else 'Fresh start'}",
    ])
    
    # State
    state = StateManager()
    
    # Discover repos
    ui.print_stage_header("STAGE 1: Discovering Repositories")
    repos = discover_repos(args)
    
    if args.resume:
        pending = state.get_pending_repos()
        pending_names = {r['full_name'] for r in pending}
        repos = [r for r in repos if r['full_name'] in pending_names]
        ui.print_success(f"Resuming: {len(repos)} pending repos")
    
    if args.max_repos:
        repos = repos[:args.max_repos]
    
    if not repos:
        ui.print_error("No repositories to audit!")
        return 1
    
    ui.print_success(f"Discovered {len(repos)} repositories to audit")
    
    # Disk check
    total, used, free = DiskMonitor.get_disk_info(REPOS_DIR)
    ui.print_success(f"Disk: {free:.1f}GB free / {total:.1f}GB total")
    
    # Audit loop
    ui.print_stage_header("STAGE 2: Running Security Audits")
    
    counter = {
        'current': 0, 'total': len(repos),
        'completed': 0, 'failed': 0, 'skipped': 0,
        'findings': 0,
    }
    lock = Lock()
    all_results = []
    
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(audit_single_repo, repo, args, ui, state, counter, lock): repo
            for repo in repos
        }
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                all_results.append(result)
            
            # Periodic stats
            with lock:
                if counter['current'] % 10 == 0 or counter['current'] == counter['total']:
                    stats = state.get_stats()
                    elapsed = time.time() - start_time
                    rate = counter['current'] / elapsed if elapsed > 0 else 0
                    remaining = (counter['total'] - counter['current']) / rate if rate > 0 else 0
                    ui.print_success(
                        f"Progress: {counter['current']}/{counter['total']} repos | "
                        f"{counter['findings']} findings | "
                        f"{timedelta(seconds=int(elapsed))} elapsed | "
                        f"~{timedelta(seconds=int(remaining))} remaining"
                    )
    
    # Final stats
    ui.print_stage_header("STAGE 3: Finalizing")
    stats = state.get_stats()
    ui.print_stats(stats)
    
    # Top vulnerable repos
    top_repos = state.get_top_vulnerable_repos(10)
    ui.print_top_repos(top_repos)
    
    # Generate HTML dashboard
    if all_results:
        ui.print_stage("Generating HTML dashboard", "running")
        dash_path = generate_html_dashboard(all_results, stats)
        ui.print_stage("Generating HTML dashboard", "done")
        ui.print_success(f"Dashboard: {dash_path}")
    
    # Export CSV
    ui.print_stage("Exporting findings CSV", "running")
    csv_path = REPORTS_DIR / "all_findings.csv"
    state.export_findings_csv(csv_path)
    ui.print_stage("Exporting findings CSV", "done")
    ui.print_success(f"CSV export: {csv_path}")
    
    # Final summary
    elapsed = time.time() - start_time
    ui.print_stage_header("PIPELINE COMPLETE")
    ui.print_success(
        f"Audited {stats['completed']} repos in {timedelta(seconds=int(elapsed))} | "
        f"Found {stats['total_findings']} findings | "
        f"C:{stats['total_critical']} H:{stats['total_high']} M:{stats['total_medium']}"
    )
    
    return 0


def main():
    """Entry point."""
    parser = build_parser()
    args = parser.parse_args()
    
    # Set API key env var early so both test and full mode can use it
    if args.kimi_api_key:
        os.environ['KIMI_API_KEY'] = args.kimi_api_key
    
    if args.verbose:
        import logging
        logging.getLogger("aws_vdp_auditor").setLevel(logging.DEBUG)
    
    if args.test_audit:
        return run_test_audit(args)
    
    return run_pipeline(args)


if __name__ == '__main__':
    sys.exit(main())
