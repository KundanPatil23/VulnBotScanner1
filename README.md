# 🛡️ VulnBot - Automated Vulnerability Scanner

A production-quality, automated vulnerability scanner built with Python that performs comprehensive asset discovery, port scanning, service enumeration, and CVE mapping using Nmap and the Shodan API.

## 🚀 Features

- **Network Reconnaissance**: Automated port scanning and service detection using Nmap
- **Vulnerability Assessment**: CVE mapping and correlation with discovered services
- **Shodan Integration**: Enhanced asset fingerprinting and vulnerability lookups
- **Risk Analysis**: CVSS-based severity scoring and risk classification
- **Comprehensive Reporting**: Generate both JSON and HTML reports with detailed findings
- **Remediation Guidance**: Actionable recommendations for identified vulnerabilities
- **Flexible CLI**: Support for IP addresses, CIDR ranges, and custom scan parameters

## 📋 Prerequisites

- Python 3.8 or higher
- Nmap (command-line tool)
- Shodan API key (free tier available at https://account.shodan.io/)

## 🔧 Installation

1. **Clone or download this repository**

2. **Install system dependencies**:
   ```bash
   # Nmap is already installed in this Replit environment
   ```

3. **Install Python dependencies**:
   ```bash
   # Dependencies are already installed via UV package manager
   ```

4. **Configure your Shodan API key**:
   ```bash
   # Create a .env file from the example
   cp .env.example .env
   
   # Edit .env and add your Shodan API key
   # Get a free API key at: https://account.shodan.io/
   ```

## 🎯 Usage

### Basic Scan

Scan a single IP address:
```bash
python main.py -t 192.168.1.1
```

### Advanced Scans

Scan a CIDR range:
```bash
python main.py -t 192.168.1.0/24
```

Scan specific port range:
```bash
python main.py -t scanme.nmap.org -p 1-65535
```

Scan without Shodan enrichment:
```bash
python main.py -t 10.0.0.1 --no-shodan
```

Custom output directory:
```bash
python main.py -t 192.168.1.1 -o /custom/reports
```

Custom Nmap arguments:
```bash
python main.py -t 192.168.1.1 --nmap-args "-sV -sC --script vuln"
```

### Command-Line Options

```
-t, --target        Target IP address, hostname, or CIDR range (required)
-p, --ports         Port range to scan (default: 1-1000)
--nmap-args         Custom Nmap arguments (overrides defaults)
--no-shodan         Skip Shodan API lookups
-o, --output        Output directory for reports (default: ./reports)
--json-only         Generate only JSON report (skip HTML)
-v, --verbose       Verbose output
```

## 📊 Report Formats

VulnBot generates two types of reports:

### 1. JSON Report
- Machine-readable format
- Complete scan metadata
- Structured vulnerability data
- Easy integration with other tools

### 2. HTML Report
- Human-friendly web interface
- Visual severity indicators
- Organized by host and vulnerability
- Includes remediation guidance

Reports are saved in the `reports/` directory with timestamps.

## 🔍 Vulnerability Severity Levels

VulnBot classifies vulnerabilities based on CVSS scores:

- **CRITICAL** (9.0-10.0): Immediate patching required
- **HIGH** (7.0-8.9): Patch within 24-48 hours
- **MEDIUM** (4.0-6.9): Schedule patching within 1 week
- **LOW** (0.0-3.9): Apply during next maintenance window

## 🏗️ Project Structure

```
vulnbot/
├── src/vulnbot/
│   ├── __init__.py          # Package initialization
│   ├── config.py            # Configuration management
│   ├── scanner.py           # Nmap scanning module
│   ├── shodan_api.py        # Shodan API integration
│   ├── cve_mapper.py        # CVE mapping and scoring
│   ├── reporter.py          # Report generation
│   ├── cli.py               # Command-line interface
│   └── templates/
│       └── report_template.html  # HTML report template
├── main.py                  # Application entry point
├── .env                     # Environment configuration
├── reports/                 # Generated scan reports
└── README.md               # This file
```

## 🔐 Security Considerations

- **API Keys**: Never commit your `.env` file to version control
- **Permissions**: Ensure you have authorization to scan target systems
- **Legal**: Unauthorized scanning may be illegal in your jurisdiction
- **Rate Limits**: Be mindful of Shodan API rate limits (free tier: 1 query/second)

## 🛠️ Configuration

Edit `src/vulnbot/config.py` to customize:

- Default Nmap scan arguments
- Scan timeout values
- Report output directory
- CVSS severity thresholds

## 📝 Example Workflow

1. **Initial Scan**: Run a basic scan to discover assets
   ```bash
   python main.py -t 192.168.1.0/24
   ```

2. **Review Reports**: Check the HTML report in `reports/` directory

3. **Deep Dive**: Re-scan specific hosts with full port range
   ```bash
   python main.py -t 192.168.1.100 -p 1-65535
   ```

4. **Export Data**: Use JSON reports for further analysis or integration

## 🚧 Troubleshooting

### Nmap Permission Errors
Some Nmap features require root privileges. Run with `sudo` if needed:
```bash
sudo python main.py -t 192.168.1.1
```

### Shodan API Errors
- Verify your API key is correctly set in `.env`
- Check rate limits on your account
- Use `--no-shodan` flag to skip Shodan lookups

### No Vulnerabilities Found
- Some systems may not have known vulnerabilities
- Ensure Shodan has data for the target IP
- Try scanning with version detection: `--nmap-args "-sV"`

## 🔮 Future Enhancements

- [ ] Persistent database storage (SQLite/PostgreSQL)
- [ ] Scheduled scanning with cron-like functionality
- [ ] Web dashboard for scan management
- [ ] Email/Slack notifications
- [ ] Integration with additional vulnerability databases (NVD, Exploit-DB)
- [ ] Automated penetration testing capabilities
- [ ] Network topology mapping

## 📄 License

This tool is provided for educational and authorized security testing purposes only.

## 🤝 Contributing

Contributions are welcome! Please ensure all security tools are used ethically and legally.

## ⚠️ Disclaimer

**USE THIS TOOL RESPONSIBLY AND LEGALLY**

This tool is designed for authorized security assessments only. Unauthorized scanning, hacking, or penetration testing is illegal. Always obtain proper written permission before scanning any network or system you do not own.

The authors and contributors are not responsible for any misuse or damage caused by this tool.

---

**VulnBot v1.0.0** - Built with ❤️ for the security community
