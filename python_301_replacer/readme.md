<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# WordPress 301 Redirect Cleaner Tool

A comprehensive, production-ready Python tool that automatically discovers and fixes internal 301 redirect links in WordPress sites. This tool crawls your entire WordPress site, identifies internal links that result in redirects, and can automatically replace them with their final destination URLs to improve site performance and SEO.

## 🎯 Features

- **Comprehensive Site Crawling**: Automatically discovers all internal URLs
- **Redirect Chain Analysis**: Follows complex redirect chains to find final destinations
- **WordPress Integration**: Uses WordPress REST API for secure post content access
- **Gutenberg-Safe Replacement**: Preserves block editor content integrity
- **Multiple Authentication Methods**: Supports both Application Passwords and cookie-based auth
- **Intelligent Caching**: Avoids re-crawling with smart cache management
- **Dry Run Mode**: Preview changes before making them live
- **Path Filtering**: Include/exclude specific URL patterns
- **Comprehensive Reporting**: Detailed JSON reports and console summaries
- **Production-Ready**: Robust error handling, retry logic, and atomic operations


## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- WordPress site with REST API enabled
- WordPress user account with `edit_posts` capability


### Installation

```bash
# Clone or download the script
wget https://example.com/wp301_cleaner.py

# Install required dependencies
pip install requests beautifulsoup4
```


### Basic Usage

```bash
# Analysis only (safe)
python wp301_cleaner.py --site https://yoursite.com --user admin --password YOUR_APP_PASSWORD

# Preview changes with dry run
python wp301_cleaner.py --site https://yoursite.com --user admin --password YOUR_APP_PASSWORD --replace --dry-run

# Make actual changes
python wp301_cleaner.py --site https://yoursite.com --user admin --password YOUR_APP_PASSWORD --replace
```


## 🔐 Authentication Setup

### Application Passwords (Recommended)

1. In WordPress admin, go to **Users → Profile**
2. Scroll to **Application Passwords** section
3. Add a new password with name "301 Cleaner"
4. Copy the generated password
5. Use this password in the tool (not your regular WordPress password)

### Cookie-Based Authentication

```bash
python wp301_cleaner.py --site https://yoursite.com --user admin --password regular_password --cookie-auth
```


## 📋 Command Line Options

| Option | Description | Example |
| :-- | :-- | :-- |
| `--site` | WordPress site URL | `https://yoursite.com` |
| `--user` | WordPress username | `admin` |
| `--password` | Application Password or regular password | `abcd 1234 efgh 5678` |
| `--replace` | Enable link replacement | `--replace` |
| `--dry-run` | Preview changes without making them | `--dry-run` |
| `--cookie-auth` | Use cookie authentication instead of App Password | `--cookie-auth` |
| `--include-paths` | Comma-separated regex patterns for paths to include | `"/blog/,/products/"` |
| `--exclude-paths` | Comma-separated regex patterns for paths to exclude | `"/admin/,/wp-"` |
| `--report-dir` | Directory for reports and cache | `reports` |
| `--delay` | Request delay in seconds | `1.0` |
| `--no-cache` | Skip cached results | `--no-cache` |
| `--verbose` | Enable verbose logging | `--verbose` |

## 💡 Usage Examples

### Safe Analysis

```bash
# Analyze site without making changes
python wp301_cleaner.py --site https://example.com --user admin --password "abcd 1234 efgh 5678"
```


### Dry Run Preview

```bash
# See what would be changed without making actual changes
python wp301_cleaner.py \
  --site https://example.com \
  --user admin \
  --password "abcd 1234 efgh 5678" \
  --replace --dry-run
```


### Live Replacement

```bash
# Make actual changes to fix redirect links
python wp301_cleaner.py \
  --site https://example.com \
  --user admin \
  --password "abcd 1234 efgh 5678" \
  --replace
```


### Filter Specific Paths

```bash
# Only process blog and product pages, exclude admin areas
python wp301_cleaner.py \
  --site https://example.com \
  --user admin \
  --password "abcd 1234 efgh 5678" \
  --include-paths "/blog/,/products/" \
  --exclude-paths "/admin/,/wp-" \
  --replace --dry-run
```


### Cookie Authentication

```bash
# Use regular WordPress password with cookie authentication
python wp301_cleaner.py \
  --site https://example.com \
  --user admin \
  --password "regular_password" \
  --cookie-auth \
  --replace --dry-run
```


## 📊 Output Files

### Reports Directory Structure

```
reports/
├── logs/
│   └── wp301_cleaner_[hash]_[timestamp].log
├── cache_[hash].pkl
├── report_[hash]_[timestamp].json
└── dry_run_plan_[hash]_[timestamp].json (if using --dry-run)
```


### Report Contents

- **Site Statistics**: URLs crawled, redirects found, posts analyzed
- **Redirect Chains**: Complete mapping of old → new URLs
- **Post Analysis**: Which posts contain redirect links
- **HTTP Status Breakdown**: Distribution of response codes
- **Error Log**: Any issues encountered during processing


## 🛡️ Safety Features

### Gutenberg Block Editor Safe

- Uses targeted string replacement instead of DOM re-serialization
- Preserves block comments and structure
- Won't break block editor content


### Multiple Confirmation Steps

- Interactive confirmation for destructive operations
- Dry run mode to preview changes
- Comprehensive backup recommendations


### Robust Error Handling

- Automatic retry logic for network issues
- Graceful degradation on individual failures
- Detailed error logging and reporting


## 🎯 What It Fixes

### Before

```html
<a href="https://yoursite.com/old-product">Check out our product!</a>
```

*This link causes a 301 redirect: old-product → new-amazing-product*

### After

```html
<a href="https://yoursite.com/new-amazing-product">Check out our product!</a>
```

*Direct link, no redirect needed*

## 📈 Benefits

- **Improved Performance**: Eliminates redirect hops for faster page loads
- **Better SEO**: More efficient crawl budget usage
- **Enhanced UX**: Faster navigation for users
- **Cleaner Analytics**: More accurate tracking without redirect chains
- **Reduced Server Load**: Fewer redirect requests to process


## ⚠️ Important Notes

### Before Running

1. **Create a full backup** of your WordPress site
2. **Test on a staging site** if possible
3. **Run in dry-run mode first** to preview changes
4. **Ensure you have edit_posts capability** in WordPress

### Requirements

- WordPress REST API must be enabled (default in modern WordPress)
- User account must have sufficient permissions to edit posts
- Site must be accessible and responsive


### Limitations

- Only processes internal links (same domain)
- Requires WordPress REST API access
- Cannot fix redirects in widgets, menus, or theme files (only post content)


## 🔧 Troubleshooting

### Common Issues

**Authentication Failed**

```bash
# Ensure Application Passwords are enabled
# Try cookie authentication as fallback
python wp301_cleaner.py --cookie-auth [other options]
```

**API Access Denied**

- Verify user has `edit_posts` capability
- Check if security plugins are blocking REST API
- Ensure WordPress REST API is enabled

**No Redirects Found**

- Check if crawling was limited by path filters
- Verify site actually has redirect chains
- Look for crawl errors in the logs

**Slow Performance**

```bash
# Increase delay between requests
python wp301_cleaner.py --delay 2.0 [other options]

# Use cache to avoid re-crawling
# Cache is automatically used unless --no-cache is specified
```


## 📚 Advanced Usage

### Interactive Mode

Run without arguments for guided setup:

```bash
python wp301_cleaner.py
```


### Custom Report Directory

```bash
python wp301_cleaner.py --report-dir /path/to/custom/reports [other options]
```


### Verbose Logging

```bash
python wp301_cleaner.py --verbose [other options]
```


## 🤝 Contributing

This tool is designed to be production-ready and handles edge cases comprehensively. If you encounter issues:

1. Check the detailed logs in the `reports/logs/` directory
2. Run with `--verbose` for more detailed output
3. Try `--dry-run` mode first to identify potential issues
4. Ensure your WordPress setup meets the requirements

## 📄 License

This tool is provided as-is for WordPress SEO optimization purposes. Use at your own risk and always maintain backups.

## 🔍 Version Information

**Current Version**: 3.0 (Final Bulletproof)

**Key Improvements**:

- Gutenberg-safe link replacement
- Enhanced authentication handling
- Comprehensive URL normalization
- Immediate cache persistence
- Production-grade error handling
- Dry-run capability
- Path filtering options

***

**⚡ Pro Tip**: Always start with `--dry-run` to see what changes would be made before running live replacement!

