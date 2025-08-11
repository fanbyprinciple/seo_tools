#!/usr/bin/env python3
"""
WordPress 301 Redirect Cleaner Tool - ENHANCED WITH AGGRESSIVE REPLACEMENT
========================================================================

Enhanced version with aggressive replacement mode:
- Standard mode: Conservative pattern matching (existing behavior)
- Aggressive mode: Enhanced URL detection and matching with fuzzy matching
- Interactive confirmation: Review all links or confirm one-by-one
- Bulk operations: Replace all at once or selective replacement
- Enhanced pattern detection: Finds URLs in various formats and contexts

Author: WordPress SEO Optimization Tool
Version: 3.1 (Enhanced Aggressive Mode)
"""

import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
from collections import deque
import logging
import json
import os
import sys
import argparse
from time import sleep, time
import re
from datetime import datetime
import pickle
import hashlib
import urllib.parse
from difflib import SequenceMatcher

class WP301CleanerAggressive:
    """
    Enhanced WordPress 301 redirect cleaner with aggressive replacement capabilities
    and interactive confirmation features.
    """
    
    def __init__(self, base_url, username, password, report_dir="reports", delay=1, 
                 use_cache=True, use_app_password=True, dry_run=False, aggressive_mode=False,
                 path_includes=None, path_excludes=None):
        """Initialize the enhanced WordPress 301 cleaner tool."""
        
        # Initialize logger FIRST
        self.logger = logging.getLogger(__name__)
        
        # Basic configuration
        self.base_url = base_url.rstrip('/')
        if not self.base_url.startswith(('http://', 'https://')):
            raise ValueError("Base URL must start with http:// or https://")
        
        # Extract domain info
        parsed = urlparse(self.base_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme
        self.domain_variants = {
            self.domain,
            f"www.{self.domain}",
            self.domain.replace("www.", "")
        }
        
        # Configuration
        self.username = username
        self.password = password
        self.use_app_password = use_app_password
        self.delay = max(0.5, delay)
        self.use_cache = use_cache
        self.dry_run = dry_run
        self.aggressive_mode = aggressive_mode  # NEW: Aggressive replacement mode
        self.path_includes = path_includes or []
        self.path_excludes = path_excludes or []
        
        # Setup directories
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)
        
        self.site_hash = hashlib.md5(self.base_url.encode()).hexdigest()[:8]
        self.cache_file = os.path.join(self.report_dir, f"cache_{self.site_hash}.pkl")
        self.report_file = os.path.join(self.report_dir, f"report_{self.site_hash}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        # WordPress URLs
        self.login_url = urljoin(self.base_url, '/wp-login.php')
        self.admin_url = urljoin(self.base_url, '/wp-admin/')
        self.api_url = urljoin(self.base_url, '/wp-json/wp/v2/')
        
        # Initialize session with proper headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WP301CleanerBot/3.1 (Enhanced Aggressive WordPress SEO Tool)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Setup authentication
        if self.use_app_password:
            self.session.auth = HTTPBasicAuth(self.username, self.password)
        
        # Data structures
        self.visited_urls = set()
        self.crawl_queue = deque([self.base_url])
        self.internal_links = set()
        self.url_status = {}
        self.redirect_chains = {}
        self.posts_with_redirects = {}
        self.crawl_errors = {}
        self.wp_nonce = None
        
        # NEW: Enhanced data structures for aggressive mode
        self.aggressive_matches = {}  # Store potential aggressive matches
        self.replacement_confirmations = {}  # Track user confirmations
        
        # Statistics
        self.stats = {
            'urls_crawled': 0,
            'redirects_found': 0,
            'posts_scanned': 0,
            'links_replaced': 0,
            'errors_encountered': 0,
            'aggressive_matches_found': 0,  # NEW
            'user_confirmations': 0,  # NEW
            'user_rejections': 0  # NEW
        }

    def setup_logging(self, log_level=logging.INFO):
        """Setup comprehensive logging system."""
        log_dir = os.path.join(self.report_dir, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        log_file = os.path.join(log_dir, f"wp301_cleaner_{self.site_hash}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        # Clear existing handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("🔥 Enhanced WordPress 301 Cleaner v3.1 with Aggressive Mode initialized")
        self.logger.info(f"Authentication: {'Application Password' if self.use_app_password else 'Cookie-based'}")
        self.logger.info(f"Replacement Mode: {'Aggressive' if self.aggressive_mode else 'Conservative'}")
        self.logger.info(f"Dry run mode: {'Enabled' if self.dry_run else 'Disabled'}")
        self.logger.info(f"Log file: {log_file}")

    def normalize_url(self, url, base_url=None):
        """Enhanced URL normalization for aggressive matching."""
        try:
            # Resolve relative URLs
            if base_url and not url.startswith(('http://', 'https://')):
                url = urljoin(base_url, url)
            
            parsed = urlparse(url)
            
            # Normalize scheme for internal URLs
            domain_to_check = parsed.netloc.lower().split(':')[0]
            if domain_to_check in {d.lower() for d in self.domain_variants}:
                parsed = parsed._replace(scheme=self.scheme)
            
            # Remove fragment
            parsed = parsed._replace(fragment='')
            
            # Normalize path
            path = parsed.path.rstrip('/') if parsed.path != '/' else '/'
            parsed = parsed._replace(path=path)
            
            # Remove default ports
            netloc = parsed.netloc.lower()
            if ':' in netloc:
                domain, port = netloc.rsplit(':', 1)
                try:
                    port_num = int(port)
                    if (parsed.scheme == 'http' and port_num == 80) or \
                       (parsed.scheme == 'https' and port_num == 443):
                        netloc = domain
                except ValueError:
                    pass
            
            parsed = parsed._replace(netloc=netloc)
            
            # Sort query parameters for consistency
            if parsed.query:
                query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                query_params.sort()
                normalized_query = urllib.parse.urlencode(query_params)
                parsed = parsed._replace(query=normalized_query)
            
            return urlunparse(parsed)
            
        except Exception as e:
            self.logger.debug(f"Error normalizing URL {url}: {str(e)}")
            return url

    def should_process_path(self, url):
        """Check if URL path should be processed based on filters."""
        try:
            parsed = urlparse(url)
            path = parsed.path
            
            # Check excludes first
            if self.path_excludes:
                for exclude_pattern in self.path_excludes:
                    if re.search(exclude_pattern, path):
                        self.logger.debug(f"URL excluded: {url}")
                        return False
            
            # Check includes
            if self.path_includes:
                for include_pattern in self.path_includes:
                    if re.search(include_pattern, path):
                        return True
                self.logger.debug(f"URL doesn't match include patterns: {url}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error checking path filters for {url}: {str(e)}")
            return True

    def fuzzy_url_similarity(self, url1, url2, threshold=0.8):
        """
        NEW: Calculate similarity between URLs for aggressive matching.
        
        Args:
            url1, url2 (str): URLs to compare
            threshold (float): Minimum similarity score (0-1)
            
        Returns:
            float: Similarity score (0-1)
        """
        try:
            # Normalize both URLs for comparison
            norm1 = self.normalize_url(url1).lower()
            norm2 = self.normalize_url(url2).lower()
            
            # Calculate similarity
            similarity = SequenceMatcher(None, norm1, norm2).ratio()
            return similarity
            
        except Exception as e:
            self.logger.debug(f"Error calculating URL similarity: {str(e)}")
            return 0.0

    def extract_all_potential_urls(self, html_content, base_url):
        """
        ENHANCED: Extract URLs using multiple methods for aggressive mode.
        
        Args:
            html_content (str): HTML content to parse
            base_url (str): Base URL for resolving relative URLs
            
        Returns:
            dict: Dictionary of URLs found with their contexts and patterns
        """
        url_findings = {}
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Method 1: Standard href extraction
            for anchor in soup.find_all('a', href=True):
                href = anchor['href'].strip()
                
                if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                    continue
                
                try:
                    absolute_url = urljoin(base_url, href)
                    normalized_url = self.normalize_url(absolute_url)
                    
                    if self.is_internal_url(normalized_url) and self.should_process_path(normalized_url):
                        # Get context around the link
                        context = str(anchor.parent) if anchor.parent else str(anchor)
                        
                        url_findings[normalized_url] = {
                            'original_href': href,
                            'method': 'href_attribute',
                            'element': str(anchor)[:200],
                            'context': context[:300],
                            'anchor_text': anchor.get_text(strip=True)[:100]
                        }
                except Exception as e:
                    self.logger.debug(f"Error processing href {href}: {str(e)}")
                    continue
            
            # Method 2: AGGRESSIVE - Text-based URL detection
            if self.aggressive_mode:
                # Find URLs in text content that might not be properly linked
                url_pattern = re.compile(
                    r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|/[^\s<>"\']*(?:/[^\s<>"\']*)*',
                    re.IGNORECASE
                )
                
                text_content = soup.get_text()
                for match in url_pattern.finditer(text_content):
                    potential_url = match.group(0)
                    
                    try:
                        # Convert to absolute URL
                        if potential_url.startswith('/'):
                            absolute_url = urljoin(base_url, potential_url)
                        elif potential_url.startswith('www.'):
                            absolute_url = f"{self.scheme}://{potential_url}"
                        else:
                            absolute_url = potential_url
                        
                        normalized_url = self.normalize_url(absolute_url)
                        
                        if (self.is_internal_url(normalized_url) and 
                            self.should_process_path(normalized_url) and
                            normalized_url not in url_findings):
                            
                            # Get context around the found URL
                            start = max(0, match.start() - 50)
                            end = min(len(text_content), match.end() + 50)
                            context = text_content[start:end]
                            
                            url_findings[normalized_url] = {
                                'original_href': potential_url,
                                'method': 'text_detection',
                                'element': f'Text: "{potential_url}"',
                                'context': context,
                                'anchor_text': 'Found in text content'
                            }
                            
                    except Exception as e:
                        self.logger.debug(f"Error processing text URL {potential_url}: {str(e)}")
                        continue
                
                # Method 3: AGGRESSIVE - Check for similar URLs in content
                content_lower = html_content.lower()
                for redirect_url in self.redirect_chains.keys():
                    parsed_redirect = urlparse(redirect_url)
                    
                    # Look for path-only references
                    path_pattern = re.escape(parsed_redirect.path)
                    if path_pattern and len(path_pattern) > 5:  # Only meaningful paths
                        path_matches = re.finditer(path_pattern, content_lower, re.IGNORECASE)
                        
                        for match in path_matches:
                            # Check if this path reference could be our redirect
                            start = max(0, match.start() - 100)
                            end = min(len(html_content), match.end() + 100)
                            context = html_content[start:end]
                            
                            # Avoid duplicates and ensure it's in a link context
                            if (redirect_url not in url_findings and 
                                ('href' in context or 'link' in context.lower())):
                                
                                url_findings[redirect_url] = {
                                    'original_href': parsed_redirect.path,
                                    'method': 'path_matching',
                                    'element': f'Path reference: "{parsed_redirect.path}"',
                                    'context': context,
                                    'anchor_text': 'Path-based detection'
                                }
        
        except Exception as e:
            self.logger.error(f"Error in aggressive URL extraction: {str(e)}")
        
        return url_findings

    def create_aggressive_replacement_patterns(self, old_url, new_url):
        """
        NEW: Create comprehensive replacement patterns for aggressive mode.
        
        Args:
            old_url (str): Original URL to replace
            new_url (str): New URL to replace with
            
        Returns:
            list: List of (old_pattern, new_pattern) tuples
        """
        patterns = []
        
        try:
            # Standard patterns (from original tool)
            standard_patterns = [
                (f'href="{old_url}"', f'href="{new_url}"'),
                (f"href='{old_url}'", f"href='{new_url}'"),
                (f'href={old_url}', f'href={new_url}'),
                (f'href = "{old_url}"', f'href = "{new_url}"'),
                (f"href = '{old_url}'", f"href = '{new_url}'"),
            ]
            patterns.extend(standard_patterns)
            
            # URL-encoded versions
            encoded_old = urllib.parse.quote(old_url, safe=':/?#[]@!$&\'()*+,;=')
            if encoded_old != old_url:
                patterns.extend([
                    (f'href="{encoded_old}"', f'href="{new_url}"'),
                    (f"href='{encoded_old}'", f"href='{new_url}'")
                ])
            
            # HTML entities
            html_escaped_old = old_url.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            if html_escaped_old != old_url:
                patterns.extend([
                    (f'href="{html_escaped_old}"', f'href="{new_url}"'),
                    (f"href='{html_escaped_old}'", f"href='{new_url}'")
                ])
            
            if self.aggressive_mode:
                # AGGRESSIVE: Path-only patterns
                old_parsed = urlparse(old_url)
                new_parsed = urlparse(new_url)
                
                if old_parsed.path and old_parsed.path != '/':
                    # Replace path-only references
                    patterns.extend([
                        (f'href="{old_parsed.path}"', f'href="{new_url}"'),
                        (f"href='{old_parsed.path}'", f"href='{new_url}'"),
                    ])
                    
                    # Replace in text content (very aggressive)
                    if len(old_parsed.path) > 8:  # Only for meaningful paths
                        patterns.append((old_parsed.path, new_parsed.path))
                
                # AGGRESSIVE: Domain variations
                old_without_www = old_url.replace('://www.', '://')
                old_with_www = old_url.replace('://', '://www.') if '://www.' not in old_url else old_url
                
                if old_without_www != old_url:
                    patterns.extend([
                        (f'href="{old_without_www}"', f'href="{new_url}"'),
                        (f"href='{old_without_www}'", f"href='{new_url}'")
                    ])
                
                if old_with_www != old_url:
                    patterns.extend([
                        (f'href="{old_with_www}"', f'href="{new_url}"'),
                        (f"href='{old_with_www}'", f"href='{new_url}'")
                    ])
        
        except Exception as e:
            self.logger.error(f"Error creating aggressive patterns: {str(e)}")
        
        return patterns

    def display_replacement_preview(self, post_data, replacement_plan):
        """
        NEW: Display a detailed preview of planned replacements for user review.
        
        Args:
            post_data (dict): Post information
            replacement_plan (list): List of planned replacements
        """
        print(f"\n" + "="*80)
        print(f"📋 REPLACEMENT PREVIEW")
        print(f"="*80)
        print(f"Post: {post_data['title']}")
        print(f"URL: {post_data['url']}")
        print(f"Total Replacements Planned: {len(replacement_plan)}")
        
        for i, replacement in enumerate(replacement_plan, 1):
            print(f"\n🔄 Replacement {i}:")
            print(f"   Old URL: {replacement['old_url']}")
            print(f"   New URL: {replacement['new_url']}")
            print(f"   Pattern: {replacement['pattern']}")
            print(f"   Method: {replacement.get('method', 'standard')}")
            
            # Show context if available
            if 'context' in replacement:
                context = replacement['context'][:200]
                print(f"   Context: ...{context}...")
            
            if 'element' in replacement:
                element = replacement['element'][:150]
                print(f"   Element: {element}...")

    def get_user_confirmation_for_replacements(self, post_data, replacement_plan):
        """
        NEW: Get user confirmation for replacements with different modes.
        
        Args:
            post_data (dict): Post information  
            replacement_plan (list): List of planned replacements
            
        Returns:
            dict: Dictionary of replacement confirmations
        """
        confirmations = {}
        
        if not replacement_plan:
            return confirmations
        
        self.display_replacement_preview(post_data, replacement_plan)
        
        print(f"\n🤔 CONFIRMATION OPTIONS:")
        print(f"1. Approve ALL replacements for this post")
        print(f"2. Review and approve each replacement individually")  
        print(f"3. Skip this post (no replacements)")
        
        while True:
            try:
                choice = input(f"\nChoose option (1/2/3): ").strip()
                
                if choice == '1':
                    # Approve all
                    for i, replacement in enumerate(replacement_plan):
                        confirmations[i] = True
                    self.stats['user_confirmations'] += len(replacement_plan)
                    print(f"✅ Approved ALL {len(replacement_plan)} replacements")
                    break
                
                elif choice == '2':
                    # Individual review
                    for i, replacement in enumerate(replacement_plan):
                        print(f"\n🔍 Review Replacement {i+1}/{len(replacement_plan)}:")
                        print(f"   {replacement['old_url']} → {replacement['new_url']}")
                        print(f"   Pattern: {replacement['pattern']}")
                        
                        while True:
                            approve = input(f"   Approve this replacement? (y/n/q to quit): ").strip().lower()
                            if approve in ['y', 'yes']:
                                confirmations[i] = True
                                self.stats['user_confirmations'] += 1
                                print(f"   ✅ Approved")
                                break
                            elif approve in ['n', 'no']:
                                confirmations[i] = False
                                self.stats['user_rejections'] += 1
                                print(f"   ❌ Rejected")
                                break
                            elif approve in ['q', 'quit']:
                                print(f"   ⏸️ Stopping review")
                                return confirmations
                            else:
                                print(f"   Please enter y, n, or q")
                    break
                
                elif choice == '3':
                    # Skip all
                    for i, replacement in enumerate(replacement_plan):
                        confirmations[i] = False
                    self.stats['user_rejections'] += len(replacement_plan)
                    print(f"❌ Skipped post - no replacements will be made")
                    break
                
                else:
                    print(f"Please enter 1, 2, or 3")
                    
            except KeyboardInterrupt:
                print(f"\n⏸️ User interrupted - stopping confirmation")
                break
        
        return confirmations

    def aggressive_replacement_analysis(self, content, post_id, redirects):
        """
        NEW: Enhanced replacement analysis for aggressive mode.
        
        Args:
            content (str): Post content
            post_id (int): Post ID
            redirects (list): List of redirect mappings
            
        Returns:
            list: Enhanced replacement plan with aggressive matches
        """
        replacement_plan = []
        
        try:
            # Extract all potential URLs from content
            url_findings = self.extract_all_potential_urls(content, self.base_url)
            
            for redirect in redirects:
                old_url = redirect['old_url']
                new_url = redirect['new_url']
                
                # Check for exact matches
                if old_url in url_findings:
                    finding = url_findings[old_url]
                    replacement_plan.append({
                        'old_url': old_url,
                        'new_url': new_url,
                        'pattern': f'href="{old_url}"',
                        'method': finding['method'],
                        'context': finding.get('context', ''),
                        'element': finding.get('element', ''),
                        'confidence': 1.0,
                        'match_type': 'exact'
                    })
                
                # AGGRESSIVE: Look for similar URLs
                elif self.aggressive_mode:
                    for found_url, finding in url_findings.items():
                        similarity = self.fuzzy_url_similarity(old_url, found_url)
                        
                        if similarity > 0.7:  # 70% similarity threshold
                            replacement_plan.append({
                                'old_url': found_url,
                                'new_url': new_url,
                                'pattern': f'href="{found_url}"',
                                'method': f"{finding['method']}_fuzzy",
                                'context': finding.get('context', ''),
                                'element': finding.get('element', ''),
                                'confidence': similarity,
                                'match_type': 'fuzzy',
                                'original_redirect': old_url
                            })
                            
                            self.stats['aggressive_matches_found'] += 1
                
                # Generate comprehensive replacement patterns
                patterns = self.create_aggressive_replacement_patterns(old_url, new_url)
                
                # Check if any patterns exist in content
                for old_pattern, new_pattern in patterns:
                    if old_pattern in content:
                        # Avoid duplicates
                        existing = any(p['pattern'] == old_pattern for p in replacement_plan)
                        if not existing:
                            replacement_plan.append({
                                'old_url': old_url,
                                'new_url': new_url,
                                'pattern': old_pattern,
                                'method': 'aggressive_pattern' if self.aggressive_mode else 'standard_pattern',
                                'context': self.extract_pattern_context(content, old_pattern),
                                'element': old_pattern,
                                'confidence': 0.9,
                                'match_type': 'pattern'
                            })
        
        except Exception as e:
            self.logger.error(f"Error in aggressive replacement analysis: {str(e)}")
        
        return replacement_plan

    def extract_pattern_context(self, content, pattern, context_length=100):
        """
        NEW: Extract context around a pattern match.
        
        Args:
            content (str): Content to search in
            pattern (str): Pattern to find
            context_length (int): Characters of context to extract
            
        Returns:
            str: Context around the pattern
        """
        try:
            pos = content.find(pattern)
            if pos == -1:
                return ""
            
            start = max(0, pos - context_length)
            end = min(len(content), pos + len(pattern) + context_length)
            
            return content[start:end].strip()
            
        except Exception as e:
            self.logger.debug(f"Error extracting pattern context: {str(e)}")
            return ""

    def execute_confirmed_replacements(self, content, replacement_plan, confirmations):
        """
        NEW: Execute only the user-confirmed replacements.
        
        Args:
            content (str): Original content
            replacement_plan (list): Full replacement plan
            confirmations (dict): User confirmations
            
        Returns:
            tuple: (updated_content, replacements_made, replacement_details)
        """
        updated_content = content
        replacements_made = 0
        replacement_details = []
        
        try:
            # Process confirmations in reverse order to avoid position shifts
            confirmed_replacements = [
                (i, plan) for i, plan in enumerate(replacement_plan)
                if confirmations.get(i, False)
            ]
            
            for i, replacement in confirmed_replacements:
                old_pattern = replacement['pattern']
                new_pattern = replacement['pattern'].replace(
                    replacement['old_url'], 
                    replacement['new_url']
                )
                
                if old_pattern in updated_content:
                    count = updated_content.count(old_pattern)
                    updated_content = updated_content.replace(old_pattern, new_pattern)
                    
                    replacements_made += count
                    replacement_details.append({
                        'old_url': replacement['old_url'],
                        'new_url': replacement['new_url'],
                        'pattern': old_pattern,
                        'count': count,
                        'method': replacement['method'],
                        'confidence': replacement.get('confidence', 1.0)
                    })
                    
                    self.logger.info(f"✅ Replaced {count}x: {replacement['old_url']} → {replacement['new_url']}")
        
        except Exception as e:
            self.logger.error(f"Error executing confirmed replacements: {str(e)}")
        
        return updated_content, replacements_made, replacement_details

    # [Previous methods remain the same - get_wp_nonce, login, is_internal_url, etc.]
    # I'll include the key ones here for completeness:

    def get_wp_nonce(self):
        """Enhanced nonce extraction for cookie-based authentication."""
        if self.use_app_password:
            return None
        
        try:
            nonce_sources = [
                (self.admin_url, [
                    r'"_wpnonce"\s*:\s*"([^"]+)"',
                    r'wpApiSettings\s*=\s*\{[^}]*"nonce"\s*:\s*"([^"]+)"',
                    r'name="_wpnonce"\s+value="([^"]+)"',
                    r'var wpApiSettings = \{"root":"[^"]+","nonce":"([^"]+)"',
                ]),
                (f"{self.base_url}/wp-json/", [
                    r'"X-WP-Nonce"\s*:\s*"([^"]+)"'
                ])
            ]
            
            for url, patterns in nonce_sources:
                try:
                    headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}
                    response = self.session.get(url, headers=headers, timeout=30)
                    
                    if response.status_code == 200:
                        for pattern in patterns:
                            match = re.search(pattern, response.text, re.IGNORECASE)
                            if match:
                                nonce = match.group(1)
                                self.logger.info(f"WordPress nonce extracted from {url}")
                                return nonce
                except Exception as e:
                    self.logger.debug(f"Error getting nonce from {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            self.logger.warning(f"Could not extract WordPress nonce: {str(e)}")
        
        return None

    def login(self):
        """Enhanced authentication with proper Content-Type handling."""
        try:
            if self.use_app_password:
                self.logger.info("Testing Application Password authentication...")
                headers = {'Accept': 'application/json'}
                response = self.session.get(f"{self.api_url}users/me", headers=headers, timeout=30)
                
                if response.status_code == 200:
                    user_data = response.json()
                    self.logger.info(f"✅ Application Password authentication successful for: {user_data.get('name', 'Unknown')}")
                    return True
                else:
                    self.logger.error(f"❌ Application Password authentication failed: {response.status_code}")
                    return False
            
            else:
                self.logger.info("Using cookie-based authentication...")
                
                login_headers = {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
                login_page = self.session.get(self.login_url, headers=login_headers, timeout=30)
                
                if login_page.status_code != 200:
                    self.logger.error(f"Cannot access login page: {login_page.status_code}")
                    return False
                
                soup = BeautifulSoup(login_page.text, 'html.parser')
                
                payload = {
                    'log': self.username,
                    'pwd': self.password,
                    'wp-submit': 'Log In',
                    'redirect_to': self.admin_url,
                    'testcookie': '1'
                }
                
                for hidden in soup.find_all('input', type='hidden'):
                    name = hidden.get('name')
                    value = hidden.get('value', '')
                    if name:
                        payload[name] = value
                
                form_headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Referer': self.login_url
                }
                
                login_response = self.session.post(
                    self.login_url, 
                    data=payload, 
                    headers=form_headers,
                    timeout=30
                )
                
                success_indicators = [
                    'wp-admin' in login_response.url,
                    login_response.status_code == 200,
                    'dashboard' in login_response.text.lower()
                ]
                
                failure_indicators = [
                    'ERROR' in login_response.text.upper(),
                    'incorrect' in login_response.text.lower()
                ]
                
                if any(success_indicators) and not any(failure_indicators):
                    self.logger.info("✅ Cookie-based authentication successful")
                    self.wp_nonce = self.get_wp_nonce()
                    return True
                else:
                    self.logger.error("❌ Cookie-based authentication failed")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            return False

    def is_internal_url(self, url):
        """Check if URL is internal to our domain."""
        try:
            if url.startswith('/') and not url.startswith('//'):
                return True
            
            parsed = urlparse(url)
            if parsed.scheme not in ['http', 'https']:
                return False
            
            url_domain = parsed.netloc.lower().split(':')[0]
            return url_domain in {d.lower() for d in self.domain_variants}
            
        except:
            return False

    def analyze_url_status(self, url, max_redirects=10):
        """Analyze URL status with comprehensive redirect chain following."""
        redirect_chain = []
        current_url = url
        visited_in_chain = set()
        
        try:
            for hop in range(max_redirects):
                if current_url in visited_in_chain:
                    self.logger.warning(f"Redirect loop detected: {current_url}")
                    break
                
                visited_in_chain.add(current_url)
                
                try:
                    response = self.session.head(current_url, allow_redirects=False, timeout=15)
                except:
                    try:
                        response = self.session.get(current_url, allow_redirects=False, timeout=15, stream=True)
                        response.close()
                    except Exception as e:
                        self.logger.debug(f"Network error for {current_url}: {str(e)}")
                        return 0, url, []
                
                status_code = response.status_code
                
                if status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '').strip()
                    if not location:
                        break
                    
                    next_url = urljoin(current_url, location)
                    next_url = self.normalize_url(next_url)
                    
                    redirect_chain.append((current_url, next_url, status_code))
                    current_url = next_url
                    continue
                else:
                    break
            
            return status_code, current_url, redirect_chain
            
        except Exception as e:
            self.logger.debug(f"Error analyzing {url}: {str(e)}")
            self.crawl_errors[url] = str(e)
            return 0, url, []

    def extract_links_from_content(self, html_content, base_url):
        """Extract internal anchor links with enhanced detection."""
        if self.aggressive_mode:
            # Use the enhanced extraction method
            url_findings = self.extract_all_potential_urls(html_content, base_url)
            return set(url_findings.keys())
        else:
            # Use standard extraction
            links = set()
            
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
                
                for anchor in soup.find_all('a', href=True):
                    href = anchor['href'].strip()
                    
                    if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                        continue
                    
                    try:
                        absolute_url = urljoin(base_url, href)
                        normalized_url = self.normalize_url(absolute_url)
                        
                        if self.is_internal_url(normalized_url) and self.should_process_path(normalized_url):
                            links.add(normalized_url)
                    except:
                        continue
                        
            except Exception as e:
                self.logger.error(f"Error extracting links: {str(e)}")
            
            return links

    # [Include all other necessary methods from the previous version...]
    # For brevity, I'll continue with the key new/modified methods:

    def crawl_site(self):
        """Enhanced site crawling with immediate cache persistence."""
        if self.load_cache():
            return
        
        self.logger.info(f"Starting comprehensive site crawl from {self.base_url}")
        start_time = time()
        
        while self.crawl_queue:
            current_url = self.crawl_queue.popleft()
            
            if current_url in self.visited_urls:
                continue
            
            if not self.should_process_path(current_url):
                continue
            
            self.visited_urls.add(current_url)
            normalized_url = self.normalize_url(current_url)
            
            status_code, final_url, redirect_chain = self.analyze_url_status(normalized_url)
            self.url_status[normalized_url] = status_code
            self.stats['urls_crawled'] += 1
            
            if redirect_chain:
                self.redirect_chains[normalized_url] = self.normalize_url(final_url)
                self.stats['redirects_found'] += 1
                
                final_normalized = self.normalize_url(final_url)
                if (self.is_internal_url(final_normalized) and 
                    final_normalized not in self.visited_urls and
                    self.should_process_path(final_normalized)):
                    self.crawl_queue.append(final_normalized)
            
            elif status_code == 200:
                try:
                    response = self.session.get(normalized_url, timeout=30)
                    if response.status_code == 200:
                        page_links = self.extract_links_from_content(response.text, normalized_url)
                        
                        for link in page_links:
                            self.internal_links.add(link)
                            if link not in self.visited_urls and self.should_process_path(link):
                                self.crawl_queue.append(link)
                                
                except Exception as e:
                    self.logger.error(f"Error fetching {normalized_url}: {str(e)}")
                    self.crawl_errors[normalized_url] = str(e)
            
            if self.stats['urls_crawled'] % 25 == 0:
                elapsed = time() - start_time
                rate = self.stats['urls_crawled'] / elapsed if elapsed > 0 else 0
                self.logger.info(f"Crawl progress: {self.stats['urls_crawled']} URLs, {self.stats['redirects_found']} redirects, {rate:.1f}/sec")
            
            sleep(self.delay)
        
        self.save_cache()
        elapsed = time() - start_time
        self.logger.info(f"Site crawl completed in {elapsed:.1f}s")

    def load_cache(self):
        """Load cached crawl results if available."""
        if not self.use_cache or not os.path.exists(self.cache_file):
            return False
        
        try:
            with open(self.cache_file, 'rb') as f:
                cache_data = pickle.load(f)
            
            required_keys = ['visited_urls', 'url_status', 'redirect_chains', 'timestamp']
            if not all(key in cache_data for key in required_keys):
                return False
            
            if time() - cache_data['timestamp'] > 86400:
                self.logger.info("Cache is too old, performing fresh crawl")
                return False
            
            self.visited_urls = cache_data['visited_urls']
            self.url_status = cache_data['url_status']
            self.redirect_chains = cache_data['redirect_chains']
            self.internal_links = cache_data.get('internal_links', set())
            self.crawl_errors = cache_data.get('crawl_errors', {})
            
            self.logger.info(f"Cache loaded: {len(self.visited_urls)} URLs, {len(self.redirect_chains)} redirects")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading cache: {str(e)}")
            return False

    def save_cache(self):
        """Save cache with enhanced metadata."""
        try:
            cache_data = {
                'visited_urls': self.visited_urls,
                'url_status': self.url_status,
                'redirect_chains': self.redirect_chains,
                'internal_links': self.internal_links,
                'crawl_errors': self.crawl_errors,
                'timestamp': time(),
                'base_url': self.base_url,
                'version': '3.1',
                'path_filters': {
                    'includes': self.path_includes,
                    'excludes': self.path_excludes
                },
                'aggressive_mode': self.aggressive_mode
            }
            
            temp_file = self.cache_file + '.tmp'
            with open(temp_file, 'wb') as f:
                pickle.dump(cache_data, f)
            
            os.rename(temp_file, self.cache_file)
            self.logger.debug(f"Cache saved: {len(self.redirect_chains)} redirects")
            
        except Exception as e:
            self.logger.error(f"Error saving cache: {str(e)}")

    def get_posts_via_api(self):
        """Fetch posts with proper authentication."""
        posts = []
        page = 1
        per_page = 50
        
        self.logger.info("Fetching WordPress posts via REST API...")
        
        try:
            while page <= 200:
                params = {
                    'per_page': per_page,
                    'page': page,
                    'status': 'publish',
                    'context': 'edit'
                }
                
                headers = {'Accept': 'application/json'}
                if not self.use_app_password and self.wp_nonce:
                    headers['X-WP-Nonce'] = self.wp_nonce
                
                response = self.session.get(
                    f"{self.api_url}posts", 
                    params=params, 
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 401:
                    self.logger.error("❌ API authentication failed")
                    break
                elif response.status_code == 403:
                    self.logger.error("❌ Insufficient permissions")
                    break
                elif response.status_code != 200:
                    if page == 1:
                        self.logger.error(f"API error: {response.status_code}")
                    break
                
                try:
                    page_posts = response.json()
                except json.JSONDecodeError:
                    break
                
                if not page_posts:
                    break
                
                posts.extend(page_posts)
                self.logger.info(f"Fetched page {page}: {len(page_posts)} posts")
                
                total_pages = int(response.headers.get('X-WP-TotalPages', 1))
                if page >= total_pages:
                    break
                
                page += 1
                
        except Exception as e:
            self.logger.error(f"Error fetching posts: {str(e)}")
        
        self.logger.info(f"Total posts retrieved: {len(posts)}")
        return posts

    def analyze_post_links_directly(self, post_content, post_id):
        """Enhanced post link analysis with aggressive matching."""
        post_redirects = []
        
        post_links = self.extract_links_from_content(post_content, self.base_url)
        
        for link in post_links:
            normalized_link = self.normalize_url(link)
            
            if normalized_link in self.redirect_chains:
                post_redirects.append({
                    'old_url': normalized_link,
                    'new_url': self.redirect_chains[normalized_link],
                    'status_code': self.url_status.get(normalized_link, 'unknown')
                })
            else:
                status_code, final_url, redirect_chain = self.analyze_url_status(normalized_link)
                
                if redirect_chain:
                    final_normalized = self.normalize_url(final_url)
                    
                    self.redirect_chains[normalized_link] = final_normalized
                    self.url_status[normalized_link] = status_code
                    
                    post_redirects.append({
                        'old_url': normalized_link,
                        'new_url': final_normalized,
                        'status_code': status_code
                    })
                    
                    self.logger.info(f"New redirect discovered in post {post_id}: {normalized_link} → {final_normalized}")
        
        return post_redirects

    def find_redirects_in_posts(self):
        """Enhanced post analysis with aggressive mode support."""
        mode_desc = "AGGRESSIVE" if self.aggressive_mode else "STANDARD"
        self.logger.info(f"Analyzing WordPress posts for redirect links - {mode_desc} MODE")
        
        posts = self.get_posts_via_api()
        if not posts:
            self.logger.warning("No posts retrieved for analysis")
            return
        
        total_redirect_links = 0
        initial_redirect_count = len(self.redirect_chains)
        
        for post in posts:
            post_id = post['id']
            post_title = post.get('title', {}).get('rendered', f'Post {post_id}')
            
            content = post.get('content', {}).get('raw')
            if not content:
                content = post.get('content', {}).get('rendered', '')
                if content:
                    self.logger.debug(f"Using rendered content for post {post_id}")
            
            if not content.strip():
                continue
            
            self.stats['posts_scanned'] += 1
            
            # Use enhanced analysis for aggressive mode
            post_redirects = self.analyze_post_links_directly(content, post_id)
            
            if post_redirects:
                self.posts_with_redirects[post_id] = {
                    'title': post_title,
                    'url': post.get('link', ''),
                    'redirects': post_redirects,
                    'redirect_count': len(post_redirects),
                    'has_raw_content': bool(post.get('content', {}).get('raw')),
                    'original_content': content
                }
                
                total_redirect_links += len(post_redirects)
                self.logger.info(f"Post '{post_title}': {len(post_redirects)} redirect links")
        
        new_redirects_found = len(self.redirect_chains) - initial_redirect_count
        if new_redirects_found > 0:
            self.logger.info(f"Found {new_redirects_found} new redirects during post analysis")
            self.save_cache()
        
        self.logger.info(f"Post analysis complete: {total_redirect_links} redirect links in {len(self.posts_with_redirects)} posts")

    def replace_redirects_in_posts_enhanced(self):
        """
        ENHANCED: Replace redirects with aggressive mode and user confirmation.
        """
        mode_desc = "AGGRESSIVE DRY RUN" if self.aggressive_mode and self.dry_run else \
                   "AGGRESSIVE LIVE" if self.aggressive_mode else \
                   "STANDARD DRY RUN" if self.dry_run else "STANDARD LIVE"
        
        self.logger.info(f"Starting enhanced redirect link replacement - {mode_desc} MODE")
        
        if not self.posts_with_redirects:
            self.logger.info("No posts with redirect links found")
            return
        
        successful_updates = 0
        failed_updates = 0
        user_skipped = 0
        
        for post_id, post_data in self.posts_with_redirects.items():
            try:
                # Fetch current post
                params = {'context': 'edit'}
                headers = {'Accept': 'application/json'}
                if not self.use_app_password and self.wp_nonce:
                    headers['X-WP-Nonce'] = self.wp_nonce
                
                response = self.session.get(
                    f"{self.api_url}posts/{post_id}", 
                    params=params,
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code != 200:
                    self.logger.error(f"Cannot fetch post {post_id}: HTTP {response.status_code}")
                    failed_updates += 1
                    continue
                
                post = response.json()
                
                content = post.get('content', {}).get('raw')
                if not content:
                    content = post.get('content', {}).get('rendered', '')
                
                if not content:
                    self.logger.warning(f"No content available for post {post_id}")
                    continue
                
                # Create enhanced replacement plan
                replacement_plan = self.aggressive_replacement_analysis(
                    content, post_id, post_data['redirects']
                )
                
                if not replacement_plan:
                    self.logger.debug(f"No replacement patterns found for post {post_id}")
                    continue
                
                if self.dry_run:
                    # DRY RUN MODE
                    if self.aggressive_mode:
                        # Interactive confirmation in dry run
                        confirmations = self.get_user_confirmation_for_replacements(
                            post_data, replacement_plan
                        )
                        
                        confirmed_count = sum(1 for c in confirmations.values() if c)
                        if confirmed_count > 0:
                            self.logger.info(f"📋 DRY RUN - Would update '{post_data['title']}': {confirmed_count} confirmed links")
                        else:
                            self.logger.info(f"📋 DRY RUN - Skipping '{post_data['title']}': No links confirmed")
                            user_skipped += 1
                    else:
                        self.logger.info(f"📋 DRY RUN - Would update '{post_data['title']}': {len(replacement_plan)} links")
                
                else:
                    # LIVE MODE
                    confirmations = {}
                    
                    if self.aggressive_mode:
                        # Get user confirmation for aggressive mode
                        confirmations = self.get_user_confirmation_for_replacements(
                            post_data, replacement_plan
                        )
                        
                        # Check if any replacements were confirmed
                        confirmed_count = sum(1 for c in confirmations.values() if c)
                        if confirmed_count == 0:
                            self.logger.info(f"Skipping '{post_data['title']}': No replacements confirmed by user")
                            user_skipped += 1
                            continue
                    else:
                        # Standard mode - approve all
                        for i in range(len(replacement_plan)):
                            confirmations[i] = True
                    
                    # Execute confirmed replacements
                    updated_content, links_replaced, replacement_details = self.execute_confirmed_replacements(
                        content, replacement_plan, confirmations
                    )
                    
                    if links_replaced > 0:
                        update_data = {'content': updated_content}
                        
                        update_headers = {'Content-Type': 'application/json'}
                        if not self.use_app_password and self.wp_nonce:
                            update_headers['X-WP-Nonce'] = self.wp_nonce
                        
                        update_response = self.session.post(
                            f"{self.api_url}posts/{post_id}",
                            json=update_data,
                            headers=update_headers,
                            timeout=30
                        )
                        
                        if update_response.status_code == 200:
                            successful_updates += 1
                            self.stats['links_replaced'] += links_replaced
                            self.logger.info(f"✅ Updated '{post_data['title']}': {links_replaced} links replaced")
                        else:
                            failed_updates += 1
                            self.logger.error(f"❌ Failed to update post {post_id}: HTTP {update_response.status_code}")
                    else:
                        self.logger.debug(f"No confirmed replacements for post {post_id}")
                
            except Exception as e:
                failed_updates += 1
                self.logger.error(f"Error processing post {post_id}: {str(e)}")
        
        # Report results
        if self.dry_run:
            self.logger.info(f"📋 Enhanced DRY RUN completed: {len(self.posts_with_redirects)} posts analyzed")
            if user_skipped > 0:
                self.logger.info(f"📋 User skipped: {user_skipped} posts")
        else:
            self.logger.info(f"🔄 Enhanced replacement completed: {successful_updates} posts updated, {failed_updates} failed")
            if user_skipped > 0:
                self.logger.info(f"⏭️ User skipped: {user_skipped} posts")

    def generate_enhanced_report(self):
        """Generate comprehensive analysis report with aggressive mode stats."""
        self.logger.info("Generating enhanced analysis report...")
        
        status_breakdown = {}
        for status in self.url_status.values():
            status_names = {
                200: 'OK',
                301: 'Moved Permanently', 
                302: 'Found (Temporary)',
                404: 'Not Found',
                403: 'Forbidden',
                500: 'Internal Server Error',
                0: 'Network Error'
            }
            status_name = status_names.get(status, f'HTTP {status}')
            status_breakdown[status] = status_breakdown.get(status, 0) + 1
        
        report_data = {
            'metadata': {
                'site_url': self.base_url,
                'analysis_date': datetime.now().isoformat(),
                'tool_version': '3.1 (Enhanced Aggressive Mode)',
                'authentication_method': 'Application Password' if self.use_app_password else 'Cookie-based',
                'replacement_mode': 'Aggressive' if self.aggressive_mode else 'Conservative',
                'dry_run_mode': self.dry_run,
                'gutenberg_safe_replacement': True,
                'cache_used': self.use_cache and os.path.exists(self.cache_file),
                'path_filters': {
                    'includes': self.path_includes,
                    'excludes': self.path_excludes
                }
            },
            'statistics': {
                'total_urls_crawled': len(self.visited_urls),
                'internal_links_found': len(self.internal_links),
                'redirect_chains_found': len(self.redirect_chains),
                'posts_scanned': self.stats['posts_scanned'],
                'posts_with_redirects': len(self.posts_with_redirects),
                'total_redirect_links': sum(post['redirect_count'] for post in self.posts_with_redirects.values()),
                'links_replaced': self.stats['links_replaced'],
                'errors_encountered': len(self.crawl_errors),
                'aggressive_matches_found': self.stats['aggressive_matches_found'],
                'user_confirmations': self.stats['user_confirmations'],
                'user_rejections': self.stats['user_rejections']
            },
            'status_breakdown': status_breakdown,
            'redirect_chains': [
                {
                    'original_url': old_url,
                    'final_url': new_url,
                    'status_code': self.url_status.get(old_url, 'unknown')
                }
                for old_url, new_url in self.redirect_chains.items()
            ],
            'posts_with_redirects': [
                {
                    'post_id': post_id,
                    'title': data['title'],
                    'url': data['url'],
                    'redirect_count': data['redirect_count'],
                    'has_raw_content': data.get('has_raw_content', False),
                    'redirects': data['redirects']
                }
                for post_id, data in self.posts_with_redirects.items()
            ],
            'errors': [
                {
                    'url': url,
                    'error': error
                }
                for url, error in self.crawl_errors.items()
            ]
        }
        
        # Save report
        try:
            temp_report = self.report_file + '.tmp'
            with open(temp_report, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            os.rename(temp_report, self.report_file)
            self.logger.info(f"📊 Enhanced report saved: {self.report_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving report: {str(e)}")
        
        # Display summary
        self.display_enhanced_summary(report_data)
        return self.report_file

    def display_enhanced_summary(self, report_data):
        """Display enhanced summary with aggressive mode statistics."""
        print("\n" + "="*80)
        print("🔥 WORDPRESS 301 REDIRECT ANALYSIS - ENHANCED AGGRESSIVE MODE REPORT")
        print("="*80)
        
        stats = report_data['statistics']
        meta = report_data['metadata']
        
        print(f"\n📊 ANALYSIS SUMMARY")
        print(f"   Site: {meta['site_url']}")
        print(f"   Version: {meta['tool_version']}")
        print(f"   Authentication: {meta['authentication_method']}")
        print(f"   Replacement Mode: {meta['replacement_mode']}")
        print(f"   Run Mode: {'DRY RUN' if meta['dry_run_mode'] else 'LIVE'}")
        print(f"   Date: {meta['analysis_date']}")
        
        print(f"\n📈 STATISTICS")
        print(f"   URLs Crawled: {stats['total_urls_crawled']:,}")
        print(f"   Posts Scanned: {stats['posts_scanned']:,}")
        print(f"   Redirects Found: {stats['redirect_chains_found']:,}")
        print(f"   Posts with Redirects: {stats['posts_with_redirects']:,}")
        print(f"   Total Redirect Links: {stats['total_redirect_links']:,}")
        
        if stats['links_replaced'] > 0:
            print(f"   ✅ Links Replaced: {stats['links_replaced']:,}")
        
        if stats['aggressive_matches_found'] > 0:
            print(f"\n🔥 AGGRESSIVE MODE RESULTS")
            print(f"   Aggressive Matches Found: {stats['aggressive_matches_found']:,}")
            print(f"   User Confirmations: {stats['user_confirmations']:,}")
            print(f"   User Rejections: {stats['user_rejections']:,}")
        
        print(f"\n📋 HTTP STATUS BREAKDOWN")
        for status, count in report_data['status_breakdown'].items():
            status_names = {200: 'OK', 301: 'Moved Permanently', 404: 'Not Found', 0: 'Network Error'}
            name = status_names.get(status, f'HTTP {status}')
            print(f"   {status} ({name}): {count:,}")

    def run_full_analysis_enhanced(self, replace_links=False):
        """
        ENHANCED: Execute complete analysis with aggressive mode support.
        
        Returns:
            tuple: (success: bool, report_file: str)
        """
        mode_desc = f"{'AGGRESSIVE' if self.aggressive_mode else 'CONSERVATIVE'} {'DRY RUN' if self.dry_run else 'LIVE'}"
        self.logger.info(f"🔥 Starting Enhanced WordPress 301 redirect analysis - {mode_desc} MODE")
        
        try:
            # Step 1: Authentication
            if not self.login():
                self.logger.error("❌ Authentication failed - cannot proceed")
                return False, None
            
            # Step 2: Site crawling
            self.logger.info("Step 2: Comprehensive site crawling...")
            self.crawl_site()
            
            # Step 3: Post analysis
            self.logger.info("Step 3: Enhanced post analysis...")
            self.find_redirects_in_posts()
            
            # Always save cache after analysis
            self.save_cache()
            
            # Step 4: Enhanced replacement
            if replace_links and self.posts_with_redirects:
                replacement_mode = f"{'aggressive' if self.aggressive_mode else 'standard'} {'dry-run' if self.dry_run else 'live'}"
                self.logger.info(f"Step 4: Starting {replacement_mode} replacement...")
                self.replace_redirects_in_posts_enhanced()
            elif replace_links:
                self.logger.info("Step 4: No redirect links found to replace")
            else:
                self.logger.info("Step 4: Link replacement skipped (analysis only)")
            
            # Step 5: Enhanced reporting
            self.logger.info("Step 5: Generating enhanced report...")
            report_file = self.generate_enhanced_report()
            
            self.logger.info("✅ Enhanced analysis completed successfully!")
            return True, report_file
            
        except Exception as e:
            self.logger.error(f"❌ Analysis failed: {str(e)}")
            return False, None


def main():
    """Enhanced main function with aggressive mode support."""
    parser = argparse.ArgumentParser(
        description="WordPress 301 Redirect Cleaner - ENHANCED WITH AGGRESSIVE MODE v3.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Conservative mode (default)
  python wp301_cleaner.py --site https://site.com --user admin --password APP_PASSWORD
  
  # Aggressive mode with dry run
  python wp301_cleaner.py --site https://site.com --user admin --password APP_PASSWORD --aggressive --replace --dry-run
  
  # Aggressive mode with live replacement (interactive confirmation)
  python wp301_cleaner.py --site https://site.com --user admin --password APP_PASSWORD --aggressive --replace
        """
    )
    
    parser.add_argument('--site', help='WordPress site URL')
    parser.add_argument('--user', help='WordPress username')  
    parser.add_argument('--password', help='WordPress Application Password or regular password')
    parser.add_argument('--report-dir', default='reports', help='Directory for reports and cache')
    parser.add_argument('--replace', action='store_true', help='Replace redirect links')
    parser.add_argument('--dry-run', action='store_true', help='Simulate replacements without making changes')
    parser.add_argument('--aggressive', action='store_true', help='Enable aggressive URL matching and replacement')
    parser.add_argument('--delay', type=float, default=1.0, help='Request delay in seconds')
    parser.add_argument('--no-cache', action='store_true', help='Skip cached results')
    parser.add_argument('--cookie-auth', action='store_true', help='Use cookie authentication')
    parser.add_argument('--include-paths', help='Comma-separated regex patterns for paths to include')
    parser.add_argument('--exclude-paths', help='Comma-separated regex patterns for paths to exclude')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Parse path filters
    path_includes = []
    path_excludes = []
    
    if args.include_paths:
        path_includes = [p.strip() for p in args.include_paths.split(',') if p.strip()]
    
    if args.exclude_paths:
        path_excludes = [p.strip() for p in args.exclude_paths.split(',') if p.strip()]
    
    # Configuration
    if args.site and args.user and args.password:
        config = {
            'site_url': args.site,
            'username': args.user,
            'password': args.password,
            'report_dir': args.report_dir,
            'replace_links': args.replace,
            'dry_run': args.dry_run,
            'aggressive_mode': args.aggressive,
            'delay': args.delay,
            'use_cache': not args.no_cache,
            'use_app_password': not args.cookie_auth,
            'path_includes': path_includes,
            'path_excludes': path_excludes
        }
    else:
        # Enhanced interactive mode
        print("🔥 WordPress 301 Redirect Cleaner - Enhanced Aggressive Mode v3.1")
        print("="*70)
        
        site_url = input("WordPress site URL: ").strip()
        while not site_url or not site_url.startswith(('http://', 'https://')):
            site_url = input("Please enter a valid URL (http:// or https://): ").strip()
        
        username = input("WordPress username: ").strip()
        while not username:
            username = input("Username required: ").strip()
        
        print("\nAuthentication method:")
        print("1. Application Password (recommended)")
        print("2. Regular password (cookie-based)")
        auth_choice = input("Choose (1/2): ").strip()
        use_app_password = auth_choice != '2'
        
        password = input("Application Password: " if use_app_password else "WordPress password: ").strip()
        while not password:
            password = input("Password required: ").strip()
        
        print("\nReplacement mode:")
        print("1. Conservative (standard pattern matching)")
        print("2. Aggressive (enhanced detection with user confirmation)")
        mode_choice = input("Choose (1/2): ").strip()
        aggressive_mode = mode_choice == '2'
        
        print("\nOperation mode:")
        print("1. Analysis only (safe)")
        print("2. Analysis + Dry run replacement")
        print("3. Analysis + Live replacement")
        operation_choice = input("Choose (1/2/3): ").strip()
        
        replace_links = operation_choice in ['2', '3']
        dry_run = operation_choice == '2'
        
        config = {
            'site_url': site_url,
            'username': username,
            'password': password,
            'report_dir': 'reports',
            'replace_links': replace_links,
            'dry_run': dry_run,
            'aggressive_mode': aggressive_mode,
            'delay': 1.0,
            'use_cache': True,
            'use_app_password': use_app_password,
            'path_includes': [],
            'path_excludes': []
        }
    
    try:
        # Initialize enhanced tool
        cleaner = WP301CleanerAggressive(
            base_url=config['site_url'],
            username=config['username'], 
            password=config['password'],
            report_dir=config['report_dir'],
            delay=config['delay'],
            use_cache=config['use_cache'],
            use_app_password=config['use_app_password'],
            dry_run=config['dry_run'],
            aggressive_mode=config['aggressive_mode'],
            path_includes=config['path_includes'],
            path_excludes=config['path_excludes']
        )
        
        # Setup logging
        log_level = logging.DEBUG if args.verbose else logging.INFO
        cleaner.setup_logging(log_level)
        
        # Display configuration
        print(f"\n🎯 ENHANCED CONFIGURATION")
        print(f"   Site: {config['site_url']}")
        print(f"   Authentication: {'Application Password' if config['use_app_password'] else 'Cookie-based'}")
        print(f"   Replacement Mode: {'🔥 AGGRESSIVE' if config['aggressive_mode'] else '🛡️ CONSERVATIVE'}")
        print(f"   Run Mode: {'DRY RUN' if config['dry_run'] else ('LIVE REPLACEMENT' if config['replace_links'] else 'ANALYSIS ONLY')}")
        
        if config['aggressive_mode']:
            print(f"\n🔥 AGGRESSIVE MODE FEATURES:")
            print(f"   • Enhanced URL detection in text content")
            print(f"   • Fuzzy URL matching for similar links") 
            print(f"   • Path-based link detection")
            print(f"   • Interactive user confirmation")
            print(f"   • Individual link review option")
        
        # Warnings and confirmations
        if config['replace_links'] and not config['dry_run']:
            print(f"\n⚠️ WARNING: Live replacement will modify your WordPress posts!")
            if config['aggressive_mode']:
                print(f"🔥 AGGRESSIVE MODE: Enhanced detection with interactive confirmation")
            confirm = input("Proceed with live replacement? (type 'YES' to confirm): ")
            if confirm != 'YES':
                print("Live replacement cancelled - switching to dry run mode")
                config['replace_links'] = True
                config['dry_run'] = True
                cleaner.dry_run = True
        
        print(f"\n🔥 Starting enhanced analysis...")
        
        # Execute enhanced analysis
        success, report_file = cleaner.run_full_analysis_enhanced(config['replace_links'])
        
        if success:
            mode_desc = f"{'AGGRESSIVE' if config['aggressive_mode'] else 'CONSERVATIVE'} {'DRY RUN' if config['dry_run'] else ('LIVE' if config['replace_links'] else 'ANALYSIS')}"
            print(f"\n✅ Enhanced analysis completed successfully! - {mode_desc} MODE")
            
            if report_file:
                print(f"📊 Detailed report: {report_file}")
                
            # Enhanced post-analysis options
            if cleaner.posts_with_redirects and not config['replace_links']:
                print(f"\n💡 Found {len(cleaner.posts_with_redirects)} posts with redirect links")
                
                print("Enhanced options:")
                print("1. Run conservative dry-run replacement")
                print("2. Run aggressive dry-run replacement (with preview)")
                print("3. Run conservative live replacement")
                print("4. Run aggressive live replacement (interactive)")
                print("5. Exit")
                
                choice = input("Choose (1/2/3/4/5): ").strip()
                
                if choice in ['1', '2', '3', '4']:
                    is_aggressive = choice in ['2', '4']
                    is_live = choice in ['3', '4']
                    
                    if is_live:
                        mode_desc = "AGGRESSIVE LIVE" if is_aggressive else "CONSERVATIVE LIVE"
                        print(f"⚠️ FINAL WARNING: {mode_desc} replacement will modify your posts!")
                        final_confirm = input("Type 'REPLACE' to confirm: ").strip()
                        
                        if final_confirm != 'REPLACE':
                            print("Live replacement cancelled")
                        else:
                            cleaner.dry_run = False
                            cleaner.aggressive_mode = is_aggressive
                            cleaner.replace_redirects_in_posts_enhanced()
                            cleaner.generate_enhanced_report()
                            print("✅ Live replacement completed!")
                    else:
                        cleaner.dry_run = True
                        cleaner.aggressive_mode = is_aggressive
                        cleaner.replace_redirects_in_posts_enhanced()
                        print("✅ Dry run completed!")
        else:
            print(f"\n❌ Analysis failed - check logs for details")
            return 1
            
    except KeyboardInterrupt:
        print(f"\n⏸️ Analysis interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
