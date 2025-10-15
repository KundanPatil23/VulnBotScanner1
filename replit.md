# VulnBot - Automated Vulnerability Scanner

## Overview
VulnBot is a web-based automated vulnerability scanner built with Python and Flask. It performs comprehensive asset discovery, port scanning, service enumeration, and CVE mapping using Nmap and the Shodan API. The tool features a modern web interface for easy scan management and generates detailed vulnerability reports with remediation guidance in both JSON and HTML formats.

## Recent Changes
- **2025-10-13**: Complete web-based GUI implementation with security hardening
  - **Web Interface**: Built Flask-based web application with modern, responsive UI
  - **Frontend**: Created purple gradient design with real-time scan progress updates
  - **Backend API**: Implemented RESTful endpoints for scanning, results, and report downloads
  - **Security**: Added comprehensive input validation, path traversal prevention, and thread safety
  - **Scan History**: Track all scans with persistent history and report management
  - **Interactive Results**: Dynamic vulnerability display with severity-based color coding
  
- **2025-10-13**: Initial CLI project setup
  - Installed Python 3.11, Nmap, Flask, and all required dependencies
  - Created modular project structure with separate modules for scanning, Shodan API, CVE mapping, and reporting
  - Implemented Nmap scanner with port scanning and service enumeration
  - Built Shodan API integration for vulnerability lookups and asset fingerprinting
  - Created CVE mapping logic with CVSS scoring and severity classification
  - Implemented JSON and HTML report generation with remediation guidance
  - Added environment-based configuration management

## Project Architecture

### Core Modules
- **scanner.py**: Nmap integration for port scanning and service detection
- **shodan_api.py**: Shodan API client for vulnerability enrichment
- **cve_mapper.py**: CVE mapping and CVSS-based risk scoring
- **reporter.py**: Multi-format report generation (JSON/HTML)
- **cli.py**: Command-line interface and argument parsing
- **config.py**: Centralized configuration management

### Key Features
1. **Network Reconnaissance**: Automated port/service discovery with Nmap
2. **Vulnerability Assessment**: CVE correlation with discovered services
3. **Shodan Integration**: Enhanced asset fingerprinting and vuln lookups
4. **Risk Analysis**: CVSS-based severity scoring (Critical/High/Medium/Low)
5. **Report Generation**: JSON (machine-readable) and HTML (visual) reports
6. **Remediation Guidance**: Actionable recommendations per vulnerability

### Technology Stack
- **Language**: Python 3.11
- **Scanning**: Nmap (python-nmap wrapper)
- **API**: Shodan API for vulnerability data
- **Reporting**: Jinja2 templates for HTML reports
- **CLI**: argparse for command-line interface
- **Config**: python-dotenv for environment variables

## Configuration

### Environment Variables
- `SHODAN_API_KEY`: Required for Shodan API integration (get free key at https://account.shodan.io/)
- `SESSION_SECRET`: Auto-generated session secret (do not modify)

### Default Settings
- Default port range: 1-1000
- Nmap arguments: `-sV -sC -O --version-intensity 5`
- Report directory: `./reports`
- CVSS thresholds: Critical (9.0+), High (7.0+), Medium (4.0+), Low (0.0+)

## User Preferences
- No specific preferences recorded yet
- Standard Python coding conventions followed
- Modular architecture for extensibility

## Usage Examples

### Basic Scan
```bash
python main.py -t 192.168.1.1
```

### Advanced Scans
```bash
# Scan CIDR range with full port sweep
python main.py -t 192.168.1.0/24 -p 1-65535

# Scan without Shodan enrichment
python main.py -t scanme.nmap.org --no-shodan

# Custom output directory
python main.py -t 10.0.0.1 -o /custom/reports

# Custom Nmap arguments
python main.py -t 192.168.1.1 --nmap-args "-sV -sC --script vuln"
```

## Security Notes
- Shodan API key stored securely in environment variables (never in code)
- .env file excluded from version control via .gitignore
- Unauthorized scanning is illegal - always obtain proper authorization
- Free Shodan tier has rate limits (1 query/second)

## Future Enhancements
- Persistent database storage (SQLite/PostgreSQL) for scan history
- Scheduled scanning with cron-like functionality  
- Web dashboard for scan management and visualization
- Email/Slack notifications for critical vulnerabilities
- Integration with additional vulnerability databases (NVD, Exploit-DB)
- Automated penetration testing capabilities
- Network topology mapping

## Project Status
✅ **Full Web Application Complete** - Production-ready with security hardening
- ✅ Web-based GUI with modern, responsive design
- ✅ Real-time scan progress tracking
- ✅ Interactive results display
- ✅ Scan history management
- ✅ Nmap scanning operational
- ✅ Shodan API integration configured
- ✅ CVE mapping and scoring implemented
- ✅ Report generation (JSON/HTML) working
- ✅ Security hardening (input validation, path traversal prevention, thread safety)
- ✅ Comprehensive documentation

## Access
- **Web Interface**: Click the webview button or visit the Replit URL
- **CLI Mode**: Run `python main.py -t <target>` in the shell

## Security Model
**Workspace-Level Access Control:**
- This tool relies on Replit's private workspace security
- No application-level authentication implemented
- Intended for single-user use in private Replit workspaces
- **Warning**: Do NOT share your Replit workspace URL publicly

**Security Hardening Implemented:**
1. **Input Validation**: Strict validation of targets (IP/CIDR/domain) and ports
2. **Input Sanitization**: Shell metacharacter removal to prevent command injection
3. **Path Traversal Prevention**: Canonical path checks for report downloads
4. **Thread Safety**: Locks protect all shared data structures
5. **No CORS**: Same-origin policy enforced

See SECURITY.md for complete security documentation.

## Optional Enhancements
1. Implement database storage for persistent scan history across sessions
2. Add scheduled scanning capabilities (cron-like functionality)
3. Create email/Slack notifications for critical vulnerabilities
4. Add application-level authentication for multi-user deployments outside Replit
5. Integration with additional vulnerability databases (NVD, Exploit-DB)
