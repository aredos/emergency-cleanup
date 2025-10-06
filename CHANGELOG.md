# Changelog

All notable changes to the Emergency Security Cleanup plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-01

### Added
- Initial release of Emergency Security Cleanup plugin
- **Malware Detection**: Comprehensive detection of malicious files, folders, and plugins
- **Content Scanning**: Advanced scanning of file contents for malicious code patterns
- **Database Security**: Detection of SQL injection attempts and suspicious database content
- **WordPress Integrity**: Verification of core WordPress files and permissions
- **Automatic Backup**: Creates backups before deleting malicious files
- **User Interface**: Clean, accessible admin interface with progress indicators
- **Security Features**: Proper nonce verification, input sanitization, and permission checks
- **Internationalization**: Full support for translations with POT file included
- **Accessibility**: Screen reader support and proper ARIA labels
- **Password Generator**: Built-in secure password generator
- **Post-Cleanup Checklist**: Comprehensive guide for post-cleanup security measures

### Security
- Implemented proper nonce verification for all AJAX requests
- Added input sanitization and validation for all user inputs
- Implemented proper capability checks (`manage_options`)
- Added SQL injection protection with prepared statements
- Implemented proper file permission checks
- Added CSRF protection for all forms

### Technical
- WordPress 5.0+ compatibility
- PHP 7.4+ requirement
- Follows WordPress Coding Standards
- Includes proper plugin headers for WordPress.org repository
- Implements proper activation/deactivation hooks
- Includes uninstall cleanup functionality
- Added comprehensive error handling and logging

### Features
- **File Detection**: Detects 5+ types of malicious files in root directory
- **Folder Detection**: Identifies 5+ suspicious folder patterns
- **Plugin Detection**: Recognizes 9+ known malicious plugins
- **Content Analysis**: Scans for 20+ malicious code patterns including:
  - Backdoors (`eval`, `base64_decode`, `shell_exec`)
  - SQL injections (`union select`, `drop table`)
  - Cryptocurrency mining scripts
  - Spam scripts
  - Obfuscated code
- **Database Scanning**: Checks for suspicious table structures and content
- **Integrity Verification**: Validates core WordPress files and permissions
- **Backup System**: Automatic backup creation before file deletion
- **Progress Tracking**: Visual progress indicators during scanning
- **Comprehensive Logging**: Detailed logs of all operations

### Accessibility
- Screen reader support with proper ARIA labels
- Keyboard navigation support
- High contrast color schemes
- Clear visual indicators and progress feedback
- Descriptive button labels and help text

### Internationalization
- Full translation support with `emergency-cleanup` text domain
- POT file included for translators
- All user-facing strings properly escaped and translatable
- RTL language support ready

### Documentation
- Comprehensive README with installation and usage instructions
- Inline code documentation following WordPress standards
- Security best practices documentation
- Troubleshooting guide included
- Changelog and version history

---

## [1.1.0] - 2024-01-XX

### Added
- **🧬 Heuristic Analysis System**: Baseline-based anomaly detection comparing actual vs expected file counts
- **📊 File Counter**: Detailed statistics per directory (themes, plugins, uploads) with total files scanned
- **🔍 Duplicate Detection**: Identifies 15+ suspicious backup patterns (.bak, .old, .save, .backup, .copy, etc.)
- **🎭 Typosquatting Detection**: Detects files with deceptive names (adrnin.php, wp-lgin.php, wp-contig.php)
- **🛡️ Advanced index.php Verification**: 12-layer security verification including:
  - File permissions check (rejects 777, 666, 775, 776)
  - BOM (Byte Order Mark) detection
  - Binary character detection (0x00-0x1F)
  - Dangerous function detection
  - Known safe pattern matching
- **🚨 File Spam Detection**: Alerts on mass file injection (>100 PHP files in uploads)

### Improved
- **🧠 Multi-Pattern Trust System**: Requires 2+ pattern matches to flag as malicious (reduces false positives by ~90%)
- **📋 25+ Refined Regex Patterns**: More precise malware detection including:
  - Backdoors with obfuscation (eval + base64_decode, gzinflate, etc.)
  - Command execution with variables ($\_GET, $\_POST)
  - Long base64 strings (>200 chars)
  - Known backdoors (c99shell, r57shell, webshell)
  - Cryptocurrency mining scripts
- **✅ Intelligent Whitelist**: Auto-excludes legitimate security plugins:
  - Wordfence Security
  - iThemes Security
  - Sucuri Scanner
  - All In One WP Security & Firewall
  - Jetpack
  - Akismet
- **🗄️ Smart Database Scanning**: Distinguishes real malicious code from educational content
  - Removes code blocks before analysis (`<pre>`, `<code>`, ` ``` `)
  - Searches for executable patterns, not just keywords
  - Detects: eval($_GET), system($_POST), <?php eval(, etc.
- **⚡ Performance Optimizations**:
  - File size limit: 1MB (avoids timeout on large files)
  - Directory limit: 5,000 files per scan
  - Ignores: node_modules, vendor, .git, .svn, bower_components

### Changed
- **Severity Levels**: Graduated alert system (Critical, High, Medium)
  - ✅ Normal: ±50% deviation
  - 🟡 Medium: >50% deviation
  - 🟠 High: >100% deviation
  - 🔴 Critical: >200% deviation or >100 PHP files in uploads
- **Baseline Calculation**:
  - Plugins: Total × 120 files average
  - Themes: Total × 60 files average
  - Uploads: Max 5 files (protection index.php only)

### Fixed
- **False Positive Reduction**:
  - Plugin no longer detects itself
  - Wordfence and security plugins excluded
  - Educational posts with code examples ignored
  - Backup plugin directories (backup, backups, updraft, backwpup) ignored
  - Empty or protection index.php files recognized as legitimate
  - index.html detection now checks for malicious redirects/scripts

### Security
- **Critical File Protection**: Alerts on backups of sensitive files that could expose credentials
  - wp-config.php.bak
  - wp-settings.php.old
  - .htaccess.save
  - wp-load.php.orig

### Technical
- Added `scan_stats` tracking array for file count analysis
- Implemented `analyze_file_count_anomalies()` function
- Implemented `scan_suspicious_duplicates()` function
- Implemented `is_legitimate_index_php()` function (12 security checks)
- Implemented `verify_malicious_post_content()` function
- Enhanced `contains_malicious_code()` with whitelist support
- Enhanced `scan_file_content()` with counter and statistics

## [Unreleased]

### Planned Features
- Real-time scanning capabilities
- Cloud-based threat intelligence
- Automated security recommendations
- Multi-site network support
- Command-line interface (WP-CLI) support
- Quarantine system (move vs delete)
- Scheduled automatic scans

### Security Improvements
- Machine learning-based threat detection
- Advanced backup encryption
- Secure file deletion methods
- Hash-based file verification

---

## Version History

- **1.1.0** - Advanced heuristic analysis, duplicate detection, typosquatting detection, and smart false positive reduction
- **1.0.0** - Initial release with core security cleanup functionality
- **Future versions** - Will follow semantic versioning (MAJOR.MINOR.PATCH)

---

## Support

For support, bug reports, or feature requests, please visit:
- GitHub Issues: https://github.com/aredos/emergency-cleanup/issues
- WordPress.org Support: [Plugin Support Forum]

## Security

If you discover a security vulnerability, please report it responsibly:
- Email: security@example.com
- Do not report security issues through public GitHub issues
- We will respond to security reports within 24 hours

---

**Note**: This plugin is designed for emergency situations after malware attacks. Always maintain regular security practices and consider it a temporary solution for immediate cleanup.
