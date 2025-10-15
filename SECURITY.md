# Security Documentation

## Security Model

VulnBot is designed as a **single-user development tool** for authorized security testing. It runs in a Replit workspace accessible only to the workspace owner.

## Implemented Security Measures

### 1. Input Validation & Sanitization
- **Target Validation**: Only allows IP addresses, CIDR ranges, and valid domain names
- **Port Validation**: Strictly validates port specifications (numbers, ranges, comma-separated)
- **Input Sanitization**: Removes shell metacharacters (`;`, `|`, `&`, `$`, etc.) to prevent command injection
- **Implementation**: `src/vulnbot/validator.py`

### 2. Path Traversal Prevention
- **Canonical Path Resolution**: Uses `os.path.realpath()` for secure path handling
- **Directory Containment**: Ensures all file access stays within the `reports/` directory
- **Early Rejection**: Blocks `..` and absolute paths immediately
- **Implementation**: `app.py` download_report endpoint

### 3. Thread Safety
- **Lock-Based Synchronization**: Uses threading.Lock() for shared data structures
- **Daemon Threads**: Worker threads properly marked as daemon for clean shutdown
- **Race Condition Prevention**: Protected scan_status and scan_history with locks

### 4. Network Security
- **Same-Origin Policy**: No CORS enabled - only same-origin requests allowed
- **Replit Workspace Access Control**: Relies on Replit's workspace-level security
- **Private URLs**: Replit URLs are private by default unless explicitly shared

## Security Limitations

### Important Notes for Users

1. **Single-User Tool**: VulnBot is NOT designed for multi-user or public deployment
2. **Workspace-Level Security**: Relies on Replit's private workspace access control
3. **Keep URLs Private**: Do NOT share your Replit workspace URL publicly
4. **Development Use**: Intended for security research and authorized testing only
5. **Legal Compliance**: Users MUST obtain authorization before scanning any systems

## Deployment Recommendations

### ⚠️ DO NOT Deploy to Production

This tool is designed for:
- Personal security research
- Authorized penetration testing
- Educational purposes
- Private Replit workspaces

### If You Must Deploy Externally

Add these security measures:
1. **Authentication**: Implement OAuth, API keys, or session-based auth
2. **Authorization**: Role-based access control for scan permissions
3. **Rate Limiting**: Prevent abuse and resource exhaustion
4. **CSRF Protection**: Add CSRF tokens if enabling cross-origin requests
5. **Audit Logging**: Log all scan activities with timestamps and user IDs
6. **IP Allowlisting**: Restrict which targets can be scanned

## Vulnerability Reporting

If you discover a security vulnerability:
1. Do NOT create a public GitHub issue
2. Contact the maintainer privately
3. Provide detailed reproduction steps
4. Allow time for a fix before disclosure

## Security Best Practices for Users

1. **Always Obtain Authorization**: Unauthorized scanning is illegal
2. **Protect API Keys**: Keep your Shodan API key confidential
3. **Secure Your Workspace**: Use Replit's privacy settings
4. **Review Reports**: Sanitize reports before sharing (may contain sensitive data)
5. **Update Dependencies**: Regularly update Python packages for security patches

## Known Security Considerations

- **Nmap Privileges**: Some Nmap scans require root/sudo (OS detection, SYN scans)
- **Shodan Rate Limits**: Free tier limited to prevent abuse
- **Network Exposure**: Scanning generates network traffic that may be logged
- **Report Storage**: Reports stored unencrypted in `reports/` directory

## Compliance

Users are responsible for ensuring compliance with:
- Computer Fraud and Abuse Act (CFAA)
- Local and international hacking laws
- Organizational security policies
- Penetration testing agreements

---

**Remember**: With great power comes great responsibility. Use VulnBot ethically and legally.
