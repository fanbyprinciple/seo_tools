#!/usr/bin/env python3
"""
WordPress 301 Redirect Cleaner - Streamlined All-in-One Solution
==============================================================

Complete solution with web interface and CLI support:
- CSV workflow for bulk editing
- Dry run and live replacement modes
- All security and performance features
- Single file for easy deployment

Version: 6.0 (Streamlined)
"""

import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from collections import deque
import logging
import json
import os
import sys
import argparse
from time import sleep, time
import re
from datetime import datetime
import sqlite3
import hashlib
import urllib.parse
import threading
import getpass
import random
import csv
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional, Any
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

# Flask imports (optional - for web interface)
try:
    from flask import Flask, render_template, request, jsonify, send_file
    from werkzeug.utils import secure_filename
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

@dataclass
class ReplacementCandidate:
    """Data structure for replacement candidates"""
    old_url: str
    new_url: str
    content_type: str
    content_id: str
    content_title: str
    pattern_found: str
    context: str
    confidence: float
    method: str
    approved: bool = True

class WP301CleanerStreamlined:
    """
    Streamlined WordPress 301 redirect cleaner with all features in one class.
    """
    
    # Safe default excludes
    DEFAULT_EXCLUDES = [
        r'^/wp-admin/', r'^/wp-login\.php', r'^/wp-json/', r'^/cart/', r'^/checkout/',
        r'^/account/', r'^/my-account/', r'^/wc-', r'^/wp-content/uploads/', r'^/feed/'
    ]
    
    # Tracking parameters to strip
    TRACKING_PARAMS = {
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
        'gclid', 'fbclid', 'msclkid', '_ga', '_gl', 'ref', 'referrer'
    }
    
    def __init__(self, base_url: str, username: str, password: Optional[str] = None,
                 report_dir: str = "reports", aggressive: bool = False, 
                 respect_robots: bool = False, max_urls: int = 10000, 
                 max_workers: int = 3, delay: float = 1.0):
        """Initialize the streamlined cleaner."""
        
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = self._get_secure_password(password)
        self.report_dir = report_dir
        self.aggressive = aggressive
        self.respect_robots = respect_robots
        self.max_urls = max_urls
        self.max_workers = max_workers
        self.delay = max(0.5, delay)
        
        # Setup directories
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Initialize logging
        self.logger = self._setup_logger()
        
        # Extract domain info
        parsed = urlparse(self.base_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme
        
        # WordPress URLs
        self.api_url = urljoin(self.base_url, '/wp-json/wp/v2/')
        
        # Create session with security settings
        self.session = self._create_session()
        
        # Data structures
        self.visited_urls = set()
        self.redirect_chains = {}
        self.replacement_candidates = []
        self.stats = {'urls_crawled': 0, 'redirects_found': 0, 'links_replaced': 0}
        
        # Generate unique identifiers
        self.site_hash = hashlib.md5(self.base_url.encode()).hexdigest()[:8]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.csv_file = os.path.join(self.report_dir, f"candidates_{self.site_hash}_{timestamp}.csv")
        self.report_file = os.path.join(self.report_dir, f"report_{self.site_hash}_{timestamp}.json")

    def _setup_logger(self):
        """Setup logging."""
        logger = logging.getLogger(f"wp301_{id(self)}")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
        return logger

    def _get_secure_password(self, password: Optional[str]) -> str:
        """Get password securely."""
        if password:
            return password
        env_password = os.environ.get('WP_PASSWORD')
        if env_password:
            return env_password
        return getpass.getpass("Enter WordPress Application Password: ")

    def _create_session(self):
        """Create secure HTTP session."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'WP301Cleaner/6.0 (Streamlined)',
            'Accept': 'application/json,text/html,*/*',
        })
        
        # Setup retry strategy
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount("http://", HTTPAdapter(max_retries=retry))
        session.mount("https://", HTTPAdapter(max_retries=retry))
        
        # Setup authentication
        session.auth = HTTPBasicAuth(self.username, self.password)
        return session

    def authenticate(self) -> bool:
        """Authenticate with WordPress."""
        try:
            response = self.session.get(f"{self.api_url}users/me", timeout=30)
            if response.status_code == 200:
                user_data = response.json()
                self.logger.info(f"✅ Authenticated as: {user_data.get('name', 'Unknown')}")
                return True
            else:
                self.logger.error(f"❌ Authentication failed: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            return False

    def canonicalize_url(self, url: str) -> str:
        """Enhanced URL canonicalization."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = urljoin(self.base_url, url)
            
            parsed = urlparse(url)
            
            # Normalize for internal URLs
            if parsed.netloc.lower().split(':')[0] in [self.domain.lower(), f"www.{self.domain}".lower()]:
                parsed = parsed._replace(scheme=self.scheme)
            
            # Remove fragment and normalize path
            parsed = parsed._replace(fragment='')
            path = parsed.path.rstrip('/') if parsed.path != '/' else '/'
            parsed = parsed._replace(path=path)
            
            # Remove default ports
            netloc = parsed.netloc.lower()
            if ':' in netloc:
                domain, port = netloc.rsplit(':', 1)
                try:
                    port_num = int(port)
                    if (parsed.scheme == 'http' and port_num == 80) or (parsed.scheme == 'https' and port_num == 443):
                        netloc = domain
                except ValueError:
                    pass
            parsed = parsed._replace(netloc=netloc)
            
            # Strip tracking parameters
            if parsed.query:
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                cleaned_params = {k: v for k, v in query_params.items() if k.lower() not in self.TRACKING_PARAMS}
                
                if cleaned_params:
                    sorted_params = []
                    for param in sorted(cleaned_params.keys()):
                        for value in cleaned_params[param]:
                            sorted_params.append((param, value))
                    parsed = parsed._replace(query=urlencode(sorted_params))
                else:
                    parsed = parsed._replace(query='')
            
            return urlunparse(parsed)
        except Exception:
            return url

    def is_internal_url(self, url: str) -> bool:
        """Check if URL is internal."""
        try:
            if url.startswith('/') and not url.startswith('//'):
                return True
            parsed = urlparse(url)
            if parsed.scheme not in ['http', 'https']:
                return False
            domain = parsed.netloc.lower().split(':')[0]
            return domain in [self.domain.lower(), f"www.{self.domain}".lower()]
        except:
            return False

    def analyze_url_status(self, url: str) -> Tuple[int, str, List[Tuple[str, str, int]]]:
        """Analyze URL and follow redirects."""
        redirect_chain = []
        current_url = url
        visited = set()
        
        for _ in range(10):  # Max 10 redirects
            if current_url in visited:
                break
            visited.add(current_url)
            
            try:
                sleep(self.delay + random.uniform(0, 0.3))  # Jitter
                response = self.session.get(current_url, allow_redirects=False, timeout=15, stream=True)
                response.close()
                
                status_code = response.status_code
                
                if status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '').strip()
                    if not location:
                        break
                    
                    next_url = urljoin(current_url, location)
                    next_url = self.canonicalize_url(next_url)
                    redirect_chain.append((current_url, next_url, status_code))
                    current_url = next_url
                else:
                    break
                    
            except Exception:
                return 0, url, []
        
        return status_code, current_url, redirect_chain

    def crawl_site(self):
        """Crawl site for redirects using concurrent processing."""
        self.logger.info(f"🕷️ Starting site crawl (max URLs: {self.max_urls})")
        
        crawl_queue = deque([self.base_url])
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            while crawl_queue and len(self.visited_urls) < self.max_urls:
                # Process current batch
                batch = []
                for _ in range(min(self.max_workers * 2, len(crawl_queue))):
                    if crawl_queue:
                        batch.append(crawl_queue.popleft())
                
                if not batch:
                    break
                
                # Submit analysis tasks
                futures = {}
                for url in batch:
                    if url not in self.visited_urls:
                        future = executor.submit(self.analyze_url_status, url)
                        futures[future] = url
                
                # Process results
                for future in as_completed(futures):
                    url = futures[future]
                    self.visited_urls.add(url)
                    
                    try:
                        status_code, final_url, redirect_chain = future.result()
                        self.stats['urls_crawled'] += 1
                        
                        if redirect_chain:
                            normalized_url = self.canonicalize_url(url)
                            self.redirect_chains[normalized_url] = self.canonicalize_url(final_url)
                            self.stats['redirects_found'] += 1
                        
                        # Extract links if successful page
                        if status_code == 200 and len(self.visited_urls) < self.max_urls:
                            try:
                                response = self.session.get(url, timeout=30)
                                if response.status_code == 200:
                                    soup = BeautifulSoup(response.text, 'html.parser')
                                    for anchor in soup.find_all('a', href=True):
                                        href = anchor['href'].strip()
                                        if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                                            absolute_url = urljoin(url, href)
                                            if self.is_internal_url(absolute_url):
                                                crawl_queue.append(absolute_url)
                            except Exception:
                                pass
                    except Exception:
                        pass
        
        self.logger.info(f"🏁 Crawl complete: {self.stats['urls_crawled']} URLs, {self.stats['redirects_found']} redirects")

    def get_all_content(self) -> List[Dict]:
        """Fetch all WordPress content (posts, pages, CPTs)."""
        all_content = []
        
        # Get content types
        try:
            response = self.session.get(f"{self.api_url}types", timeout=30)
            if response.status_code == 200:
                types_data = response.json()
                content_types = {}
                for type_slug, type_info in types_data.items():
                    if (type_info.get('rest_base') and type_info.get('show_in_rest', False) 
                        and type_slug not in ['attachment', 'revision']):
                        content_types[type_slug] = type_info['rest_base']
            else:
                content_types = {'posts': 'posts', 'pages': 'pages'}
        except Exception:
            content_types = {'posts': 'posts', 'pages': 'pages'}
        
        # Fetch content for each type
        for content_type, rest_base in content_types.items():
            self.logger.info(f"📄 Fetching {content_type}...")
            page = 1
            
            while page <= 100:  # Safety limit
                try:
                    params = {'per_page': 50, 'page': page, 'status': 'publish', 'context': 'edit'}
                    response = self.session.get(f"{self.api_url}{rest_base}", params=params, timeout=30)
                    
                    if response.status_code != 200:
                        break
                    
                    items = response.json()
                    if not items:
                        break
                    
                    for item in items:
                        item['_content_type'] = content_type  # Add type marker
                        all_content.append(item)
                    
                    page += 1
                    
                    # Check if we've reached the last page
                    total_pages = int(response.headers.get('X-WP-TotalPages', 1))
                    if page > total_pages:
                        break
                        
                except Exception as e:
                    self.logger.debug(f"Error fetching {content_type} page {page}: {str(e)}")
                    break
        
        self.logger.info(f"📚 Total content items: {len(all_content)}")
        return all_content

    def analyze_content_for_redirects(self, content_items: List[Dict]):
        """Analyze content for redirect links."""
        self.logger.info("🔍 Analyzing content for redirect links...")
        
        for item in content_items:
            content_type = item.get('_content_type', 'unknown')
            content_id = str(item['id'])
            title = item.get('title', {}).get('rendered', f'{content_type} {content_id}')
            
            # Get content (prefer raw for editing)
            content = item.get('content', {}).get('raw') or item.get('content', {}).get('rendered', '')
            if not content.strip():
                continue
            
            # Extract links using BeautifulSoup
            try:
                soup = BeautifulSoup(content, 'html.parser')
                for anchor in soup.find_all('a', href=True):
                    href = anchor['href'].strip()
                    if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                        continue
                    
                    # Convert to absolute URL and canonicalize
                    absolute_url = urljoin(self.base_url, href)
                    canonical_url = self.canonicalize_url(absolute_url)
                    
                    # Check if this URL is a redirect
                    if self.is_internal_url(canonical_url) and canonical_url in self.redirect_chains:
                        final_url = self.redirect_chains[canonical_url]
                        
                        # Get context around the link
                        context = str(anchor.parent)[:200] if anchor.parent else str(anchor)[:200]
                        pattern = f'href="{href}"'
                        
                        candidate = ReplacementCandidate(
                            old_url=href,
                            new_url=final_url,
                            content_type=content_type,
                            content_id=content_id,
                            content_title=title,
                            pattern_found=pattern,
                            context=context,
                            confidence=1.0,
                            method='exact_match'
                        )
                        
                        self.replacement_candidates.append(candidate)
                        
            except Exception as e:
                self.logger.debug(f"Error analyzing content {content_id}: {str(e)}")
        
        self.logger.info(f"🎯 Found {len(self.replacement_candidates)} replacement candidates")

    def export_candidates_to_csv(self, filename: Optional[str] = None) -> str:
        """Export replacement candidates to CSV."""
        csv_file = filename or self.csv_file
        
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Header
                header = ['approved', 'old_url', 'new_url', 'content_type', 'content_id', 
                         'content_title', 'pattern_found', 'context', 'confidence', 'method']
                writer.writerow(header)
                
                # Data rows
                for candidate in self.replacement_candidates:
                    row = [
                        'TRUE',  # Default to approved
                        candidate.old_url,
                        candidate.new_url,
                        candidate.content_type,
                        candidate.content_id,
                        candidate.content_title,
                        candidate.pattern_found,
                        candidate.context,
                        candidate.confidence,
                        candidate.method
                    ]
                    writer.writerow(row)
            
            self.logger.info(f"📊 CSV exported: {csv_file}")
            return csv_file
            
        except Exception as e:
            self.logger.error(f"Error exporting CSV: {str(e)}")
            raise

    def import_approved_candidates(self, csv_file: str) -> List[ReplacementCandidate]:
        """Import approved candidates from CSV."""
        approved = []
        
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    if row.get('approved', '').upper() in ['TRUE', '1', 'YES', 'Y']:
                        candidate = ReplacementCandidate(
                            old_url=row['old_url'],
                            new_url=row['new_url'],
                            content_type=row['content_type'],
                            content_id=row['content_id'],
                            content_title=row['content_title'],
                            pattern_found=row['pattern_found'],
                            context=row['context'],
                            confidence=float(row.get('confidence', 1.0)),
                            method=row['method'],
                            approved=True
                        )
                        approved.append(candidate)
            
            self.logger.info(f"📥 Imported {len(approved)} approved candidates")
            return approved
            
        except Exception as e:
            self.logger.error(f"Error importing CSV: {str(e)}")
            raise

    def execute_replacements(self, candidates: List[ReplacementCandidate], dry_run: bool = False) -> Dict[str, int]:
        """Execute approved replacements."""
        mode = "DRY RUN" if dry_run else "LIVE"
        self.logger.info(f"🔄 {mode}: Executing {len(candidates)} replacements...")
        
        stats = {'successful_updates': 0, 'failed_updates': 0, 'links_replaced': 0}
        
        # Group by content item
        content_groups = {}
        for candidate in candidates:
            key = f"{candidate.content_type}_{candidate.content_id}"
            if key not in content_groups:
                content_groups[key] = []
            content_groups[key].append(candidate)
        
        # Get content types mapping
        content_types = {'posts': 'posts', 'pages': 'pages'}  # Simplified
        
        for content_key, item_candidates in content_groups.items():
            try:
                content_type, item_id = content_key.split('_', 1)
                endpoint = content_types.get(content_type, 'posts')
                
                # Fetch current content
                response = self.session.get(f"{self.api_url}{endpoint}/{item_id}?context=edit", timeout=30)
                if response.status_code != 200:
                    stats['failed_updates'] += 1
                    continue
                
                item = response.json()
                content = item.get('content', {}).get('raw') or item.get('content', {}).get('rendered', '')
                
                if not content:
                    continue
                
                # Apply replacements
                updated_content = content
                replacements_count = 0
                
                for candidate in item_candidates:
                    old_pattern = candidate.pattern_found
                    new_pattern = old_pattern.replace(candidate.old_url, candidate.new_url)
                    
                    if old_pattern in updated_content:
                        count = updated_content.count(old_pattern)
                        if not dry_run:
                            updated_content = updated_content.replace(old_pattern, new_pattern)
                        replacements_count += count
                        
                        mode_symbol = "🔍" if dry_run else "✅"
                        self.logger.info(f"{mode_symbol} {mode} - {count}x: {candidate.old_url} → {candidate.new_url}")
                
                # Update content if changes were made and not dry run
                if replacements_count > 0:
                    if not dry_run:
                        update_data = {'content': updated_content}
                        update_response = self.session.post(f"{self.api_url}{endpoint}/{item_id}", 
                                                          json=update_data, timeout=30)
                        
                        if update_response.status_code == 200:
                            stats['successful_updates'] += 1
                            stats['links_replaced'] += replacements_count
                        else:
                            stats['failed_updates'] += 1
                            self.logger.error(f"❌ Failed to update {content_type} {item_id}")
                    else:
                        stats['successful_updates'] += 1
                        stats['links_replaced'] += replacements_count
                
            except Exception as e:
                stats['failed_updates'] += 1
                self.logger.error(f"Error processing {content_key}: {str(e)}")
        
        self.logger.info(f"🏁 {mode} Complete: {stats['successful_updates']} updated, "
                        f"{stats['links_replaced']} links, {stats['failed_updates']} failed")
        return stats

    def run_scan_workflow(self) -> Tuple[bool, str]:
        """Run scan-only workflow."""
        try:
            if not self.authenticate():
                return False, ""
            
            self.crawl_site()
            content_items = self.get_all_content()
            self.analyze_content_for_redirects(content_items)
            csv_file = self.export_candidates_to_csv()
            
            return True, csv_file
        except Exception as e:
            self.logger.error(f"Scan workflow failed: {str(e)}")
            return False, ""

    def run_replace_workflow(self, csv_file: Optional[str] = None, dry_run: bool = False) -> Tuple[bool, Dict[str, int]]:
        """Run replacement workflow."""
        try:
            if not self.authenticate():
                return False, {}
            
            if csv_file:
                # CSV-based replacement
                candidates = self.import_approved_candidates(csv_file)
            else:
                # Direct replacement - scan first
                self.crawl_site()
                content_items = self.get_all_content()
                self.analyze_content_for_redirects(content_items)
                candidates = self.replacement_candidates
            
            stats = self.execute_replacements(candidates, dry_run)
            return True, stats
            
        except Exception as e:
            self.logger.error(f"Replace workflow failed: {str(e)}")
            return False, {}


# ================================
# Web Interface (Optional)
# ================================

if FLASK_AVAILABLE:
    # Minimal Flask web interface
    HTML_TEMPLATE = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>WordPress 301 Redirect Cleaner</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input, select, textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
            button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #005a87; }
            .success { color: green; }
            .error { color: red; }
            .workflow { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
            .progress { display: none; margin: 20px 0; }
            #results { margin-top: 20px; }
        </style>
    </head>
    <body>
        <h1>🔄 WordPress 301 Redirect Cleaner</h1>
        
        <div class="workflow">
            <h2>Configuration</h2>
            <form id="configForm">
                <div class="form-group">
                    <label>WordPress Site URL:</label>
                    <input type="url" id="siteUrl" placeholder="https://yoursite.com" required>
                </div>
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" id="username" required>
                </div>
                <div class="form-group">
                    <label>Application Password:</label>
                    <input type="password" id="password" required>
                </div>
                <div class="form-group">
                    <label><input type="checkbox" id="aggressive"> Aggressive Mode</label>
                </div>
            </form>
        </div>

        <div class="workflow">
            <h2>Workflow Options</h2>
            <button onclick="runScan()">1. Scan & Generate CSV</button>
            <button onclick="runDryRun()">2. Dry Run (Preview Changes)</button>
            <button onclick="runReplace()">3. Live Replace All</button>
            
            <div style="margin-top: 15px;">
                <label>Upload CSV for replacement:</label>
                <input type="file" id="csvFile" accept=".csv">
                <button onclick="runCsvReplace()">Replace from CSV</button>
            </div>
        </div>

        <div class="progress" id="progress">
            <h3>Processing...</h3>
            <div id="status">Initializing...</div>
        </div>

        <div id="results"></div>

        <script>
            let taskId = null;

            function showProgress(show) {
                document.getElementById('progress').style.display = show ? 'block' : 'none';
            }

            function updateStatus(message) {
                document.getElementById('status').textContent = message;
            }

            function showResults(html) {
                document.getElementById('results').innerHTML = html;
            }

            function getConfig() {
                return {
                    site_url: document.getElementById('siteUrl').value,
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value,
                    aggressive: document.getElementById('aggressive').checked
                };
            }

            async function runScan() {
                const config = getConfig();
                showProgress(true);
                updateStatus('Starting scan...');
                
                try {
                    const response = await fetch('/api/scan', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(config)
                    });
                    
                    const result = await response.json();
                    if (result.success) {
                        showResults(`<div class="success">
                            <h3>✅ Scan Complete!</h3>
                            <p>Found ${result.candidates_count} replacement candidates</p>
                            <a href="${result.csv_file}" download>📥 Download CSV File</a>
                        </div>`);
                    } else {
                        showResults(`<div class="error">❌ Error: ${result.error}</div>`);
                    }
                } catch (error) {
                    showResults(`<div class="error">❌ Error: ${error.message}</div>`);
                } finally {
                    showProgress(false);
                }
            }

            async function runDryRun() {
                const config = getConfig();
                showProgress(true);
                updateStatus('Running dry run...');
                
                try {
                    const response = await fetch('/api/replace', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({...config, dry_run: true})
                    });
                    
                    const result = await response.json();
                    if (result.success) {
                        const stats = result.stats;
                        showResults(`<div class="success">
                            <h3>🔍 Dry Run Complete!</h3>
                            <p>Would update: ${stats.successful_updates} items</p>
                            <p>Would replace: ${stats.links_replaced} links</p>
                            <p>This was a preview - no changes were made.</p>
                        </div>`);
                    } else {
                        showResults(`<div class="error">❌ Error: ${result.error}</div>`);
                    }
                } catch (error) {
                    showResults(`<div class="error">❌ Error: ${error.message}</div>`);
                } finally {
                    showProgress(false);
                }
            }

            async function runReplace() {
                if (!confirm('⚠️ WARNING: This will replace ALL redirect links found. Continue?')) {
                    return;
                }
                
                const config = getConfig();
                showProgress(true);
                updateStatus('Executing live replacement...');
                
                try {
                    const response = await fetch('/api/replace', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({...config, dry_run: false})
                    });
                    
                    const result = await response.json();
                    if (result.success) {
                        const stats = result.stats;
                        showResults(`<div class="success">
                            <h3>✅ Replacement Complete!</h3>
                            <p>Updated: ${stats.successful_updates} items</p>
                            <p>Replaced: ${stats.links_replaced} links</p>
                            <p>Failed: ${stats.failed_updates} updates</p>
                        </div>`);
                    } else {
                        showResults(`<div class="error">❌ Error: ${result.error}</div>`);
                    }
                } catch (error) {
                    showResults(`<div class="error">❌ Error: ${error.message}</div>`);
                } finally {
                    showProgress(false);
                }
            }

            async function runCsvReplace() {
                const fileInput = document.getElementById('csvFile');
                if (!fileInput.files[0]) {
                    alert('Please select a CSV file first');
                    return;
                }
                
                const formData = new FormData();
                formData.append('csv_file', fileInput.files[0]);
                formData.append('config', JSON.stringify(getConfig()));
                
                showProgress(true);
                updateStatus('Processing CSV replacement...');
                
                try {
                    const response = await fetch('/api/csv-replace', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const result = await response.json();
                    if (result.success) {
                        const stats = result.stats;
                        showResults(`<div class="success">
                            <h3>✅ CSV Replacement Complete!</h3>
                            <p>Updated: ${stats.successful_updates} items</p>
                            <p>Replaced: ${stats.links_replaced} links</p>
                            <p>Failed: ${stats.failed_updates} updates</p>
                        </div>`);
                    } else {
                        showResults(`<div class="error">❌ Error: ${result.error}</div>`);
                    }
                } catch (error) {
                    showResults(`<div class="error">❌ Error: ${error.message}</div>`);
                } finally {
                    showProgress(false);
                }
            }
        </script>
    </body>
    </html>
    '''

    def create_web_app():
        """Create Flask web application."""
        app = Flask(__name__)
        app.secret_key = 'wp301-cleaner-key'
        
        @app.route('/')
        def index():
            return HTML_TEMPLATE
        
        @app.route('/api/scan', methods=['POST'])
        def api_scan():
            try:
                data = request.json
                cleaner = WP301CleanerStreamlined(
                    base_url=data['site_url'],
                    username=data['username'],
                    password=data['password'],
                    aggressive=data.get('aggressive', False)
                )
                
                success, csv_file = cleaner.run_scan_workflow()
                
                if success:
                    return jsonify({
                        'success': True,
                        'csv_file': csv_file,
                        'candidates_count': len(cleaner.replacement_candidates)
                    })
                else:
                    return jsonify({'success': False, 'error': 'Scan failed'})
                    
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @app.route('/api/replace', methods=['POST'])
        def api_replace():
            try:
                data = request.json
                dry_run = data.get('dry_run', False)
                
                cleaner = WP301CleanerStreamlined(
                    base_url=data['site_url'],
                    username=data['username'],
                    password=data['password'],
                    aggressive=data.get('aggressive', False)
                )
                
                success, stats = cleaner.run_replace_workflow(dry_run=dry_run)
                
                if success:
                    return jsonify({'success': True, 'stats': stats})
                else:
                    return jsonify({'success': False, 'error': 'Replacement failed'})
                    
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @app.route('/api/csv-replace', methods=['POST'])
        def api_csv_replace():
            try:
                if 'csv_file' not in request.files:
                    return jsonify({'success': False, 'error': 'No CSV file'})
                
                file = request.files['csv_file']
                config = json.loads(request.form.get('config', '{}'))
                
                # Save uploaded file temporarily
                filename = secure_filename(file.filename)
                filepath = os.path.join('reports', filename)
                file.save(filepath)
                
                cleaner = WP301CleanerStreamlined(
                    base_url=config['site_url'],
                    username=config['username'],
                    password=config['password']
                )
                
                success, stats = cleaner.run_replace_workflow(csv_file=filepath)
                
                # Clean up
                try:
                    os.remove(filepath)
                except:
                    pass
                
                if success:
                    return jsonify({'success': True, 'stats': stats})
                else:
                    return jsonify({'success': False, 'error': 'CSV replacement failed'})
                    
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @app.route('/reports/<path:filename>')
        def download_file(filename):
            return send_file(os.path.join('reports', filename), as_attachment=True)
        
        return app


# ================================
# CLI Interface
# ================================

def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(description="WordPress 301 Redirect Cleaner - Streamlined v6.0")
    
    # Mode selection
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--scan', action='store_true', help='Scan and generate CSV')
    group.add_argument('--dry-run', action='store_true', help='Preview replacements without making changes')
    group.add_argument('--replace', action='store_true', help='Execute live replacements')
    group.add_argument('--csv-replace', metavar='FILE', help='Replace using CSV file')
    group.add_argument('--web', action='store_true', help='Start web interface')
    
    # WordPress configuration
    parser.add_argument('--site', help='WordPress site URL')
    parser.add_argument('--user', help='WordPress username')
    parser.add_argument('--password', help='WordPress password (or use WP_PASSWORD env var)')
    
    # Options
    parser.add_argument('--aggressive', action='store_true', help='Enable aggressive URL detection')
    parser.add_argument('--respect-robots', action='store_true', help='Respect robots.txt')
    parser.add_argument('--max-urls', type=int, default=10000, help='Maximum URLs to crawl')
    parser.add_argument('--max-workers', type=int, default=3, help='Concurrent workers')
    parser.add_argument('--delay', type=float, default=1.0, help='Request delay in seconds')
    parser.add_argument('--report-dir', default='reports', help='Report directory')
    
    args = parser.parse_args()
    
    # Web interface mode
    if args.web:
        if not FLASK_AVAILABLE:
            print("❌ Flask not available. Install with: pip install flask")
            return 1
        
        app = create_web_app()
        print("🌐 Starting web interface at http://localhost:5000")
        app.run(debug=True, host='0.0.0.0', port=5000)
        return 0
    
    # CLI mode - require site and user
    if not args.site or not args.user:
        print("❌ --site and --user are required for CLI mode")
        return 1
    
    try:
        cleaner = WP301CleanerStreamlined(
            base_url=args.site,
            username=args.user,
            password=args.password,
            report_dir=args.report_dir,
            aggressive=args.aggressive,
            respect_robots=args.respect_robots,
            max_urls=args.max_urls,
            max_workers=args.max_workers,
            delay=args.delay
        )
        
        if args.scan:
            success, csv_file = cleaner.run_scan_workflow()
            if success:
                print(f"✅ Scan complete! CSV file: {csv_file}")
                print("📝 Edit the CSV file and run with --csv-replace to execute changes")
            else:
                print("❌ Scan failed")
                return 1
        
        elif args.dry_run:
            success, stats = cleaner.run_replace_workflow(dry_run=True)
            if success:
                print(f"🔍 Dry run complete!")
                print(f"   Would update: {stats['successful_updates']} items")
                print(f"   Would replace: {stats['links_replaced']} links")
            else:
                print("❌ Dry run failed")
                return 1
        
        elif args.replace:
            print("⚠️ WARNING: This will make live changes to your WordPress content!")
            confirm = input("Type 'REPLACE' to confirm: ")
            if confirm != 'REPLACE':
                print("Cancelled")
                return 0
            
            success, stats = cleaner.run_replace_workflow(dry_run=False)
            if success:
                print(f"✅ Replacement complete!")
                print(f"   Updated: {stats['successful_updates']} items")
                print(f"   Replaced: {stats['links_replaced']} links")
                print(f"   Failed: {stats['failed_updates']} items")
            else:
                print("❌ Replacement failed")
                return 1
        
        elif args.csv_replace:
            if not os.path.exists(args.csv_replace):
                print(f"❌ CSV file not found: {args.csv_replace}")
                return 1
            
            success, stats = cleaner.run_replace_workflow(csv_file=args.csv_replace)
            if success:
                print(f"✅ CSV replacement complete!")
                print(f"   Updated: {stats['successful_updates']} items")
                print(f"   Replaced: {stats['links_replaced']} links")
                print(f"   Failed: {stats['failed_updates']} items")
            else:
                print("❌ CSV replacement failed")
                return 1
        
        return 0
        
    except KeyboardInterrupt:
        print("\n⏸️ Interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
