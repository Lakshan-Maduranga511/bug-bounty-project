# Bug Bounty Project: DVWA Security Assessment

A comprehensive security assessment of Damn Vulnerable Web Application (DVWA) demonstrating professional penetration testing methodology, vulnerability discovery, exploitation, and reporting.

---

## 🎯 Project Overview

This project represents a complete bug bounty workflow from reconnaissance to professional reporting, conducted in a safe, legal laboratory environment using intentionally vulnerable software designed for security training.

**Purpose**: Educational demonstration of cybersecurity skills including:

- Professional penetration testing methodology
- Vulnerability discovery and exploitation
- Security tool usage and proficiency
- Professional technical documentation
- Risk assessment and remediation planning

---

## 🔍 Vulnerabilities Discovered

### Summary of Findings:

| #   | Vulnerability        | Severity     | CVSS | Status       |
| --- | -------------------- | ------------ | ---- | ------------ |
| 1   | SQL Injection        | **Critical** | 9.8  | ✅ Confirmed |
| 2   | Stored XSS           | **High**     | 7.1  | ✅ Confirmed |
| 3   | Local File Inclusion | **High**     | 7.5  | ✅ Confirmed |
| 4   | Reflected XSS        | **Medium**   | 6.1  | ✅ Confirmed |

**Overall Risk Rating**: CRITICAL

---

## 📂 Project Structure

```
bug-bounty-project/
│
├── README.md                          # Project overview (this file)
│
├── recon/                             # Reconnaissance Phase
│   ├── nmap-scans/                   # Network scanning results
│   │   ├── basic-scan.txt            # Basic port scan
│   │   ├── service-scan.txt          # Service version detection
│   │   └── full-scan.txt             # Comprehensive scan
│   ├── http-headers.txt              # HTTP header analysis
│   ├── application-structure.txt     # Manual application mapping
│   └── technology-stack.txt          # Technology identification
│
├── exploitation/                      # Exploitation Phase
│   ├── xss/                          # XSS Testing
│   │   ├── reflected-xss-poc.html    # Proof of concept file
│   │   └── xss-findings.txt          # Detailed XSS findings
│   ├── sqli/                         # SQL Injection Testing
│   │   ├── sqlmap-results/           # SQLMap output directory
│   │   └── sqlmap-findings.txt       # SQL injection documentation
│   └── idor/                         # File Inclusion Testing
│       └── lfi-findings.txt          # LFI documentation
│
├── screenshots/                       # Visual Evidence
│   ├── xss/                          # XSS Screenshots
│   │   ├── reflected-xss-input.png
│   │   ├── reflected-xss-alert.png
│   │   ├── reflected-xss-source.png
│   │   ├── stored-xss-form.png
│   │   ├── stored-xss-alert.png
│   │   └── stored-xss-persistence.png
│   ├── sqli/                         # SQL Injection Screenshots
│   │   ├── sqlmap-databases.png
│   │   ├── sqlmap-tables.png
│   │   └── sqlmap-users-dump.png
│   └── idor/                         # LFI Screenshots
│       ├── lfi-passwd-success.png
│       └── burp-lfi-success.png
│
└── reports/                           # Professional Documentation
    ├── 01-reflected-xss-vulnerability.md
    ├── 02-sql-injection-vulnerability.md
    ├── 03-stored-xss-vulnerability.md
    ├── 04-file-inclusion-vulnerability.md
    └── FINAL-BUG-BOUNTY-REPORT.md    # Comprehensive final report
```

---

## 🔬 Methodology

This assessment followed industry-standard penetration testing methodology:

### Phase 1: Reconnaissance (4 hours)

- **Network Scanning**: Nmap port enumeration and service detection
- **HTTP Analysis**: Header inspection and fingerprinting
- **Application Mapping**: Manual exploration of functionality
- **Technology Identification**: Stack analysis and version detection

### Phase 2: Vulnerability Discovery (8 hours)

- **SQL Injection Testing**: Manual and automated (SQLMap)
- **XSS Testing**: Reflected and Stored variants
- **File Inclusion Testing**: LFI/Path traversal
- **OWASP Top 10 Methodology**: Systematic vulnerability testing

### Phase 3: Exploitation (4 hours)

- **Proof-of-Concept Development**: Working exploit code
- **Impact Validation**: Confirming exploitability
- **Evidence Collection**: Screenshots and outputs
- **Tool Usage**: Burp Suite, SQLMap, browser tools

### Phase 4: Documentation (3 hours)

- **Individual Reports**: Detailed vulnerability documentation
- **Comprehensive Report**: Executive and technical findings
- **Remediation Guidance**: Actionable fix recommendations
- **Professional Formatting**: Industry-standard reporting

**Total Time**: Approximately 19 hours over 5 days

---

## 🛠️ Tools Used

### Reconnaissance Tools:

- **Nmap** - Network scanning and port enumeration
- **cURL** - HTTP header analysis
- **Browser DevTools** - Request/response inspection

### Exploitation Tools:

- **Burp Suite Community Edition** - Web application security testing
- **SQLMap** - Automated SQL injection exploitation
- **Firefox Browser** - Manual testing and PoC validation

### Documentation Tools:

- **Markdown** - Professional report formatting
- **Git** - Version control and project management
- **Windows Snipping Tool** - Evidence capture

### Development Environment:

- **Docker** - DVWA container deployment
- **PowerShell** - Command-line operations
- **Notepad/VS Code** - Text editing and documentation

---

## 🎓 Key Findings Summary

### 1. SQL Injection (CRITICAL - CVSS 9.8)

**Location**: `/vulnerabilities/sqli/` (parameter: `id`)

**Impact**:

- Complete database compromise
- All user credentials extracted
- 5 accounts compromised (admin, gordonb, 1337, pablo, smithy)
- Passwords cracked: password, abc123, charley, letmein

**Evidence**:

- Manual authentication bypass: `' OR '1'='1`
- SQLMap automation successful
- Database: `dvwa`, Tables: `users`, `guestbook`
- Full data exfiltration achieved

**Remediation**: Implement prepared statements/parameterized queries

---

### 2. Stored XSS (HIGH - CVSS 7.1)

**Location**: `/vulnerabilities/xss_s/` (parameters: `txtName`, `mtxMessage`)

**Impact**:

- Persistent JavaScript execution
- Affects ALL application users
- No user interaction required
- Potential for session hijacking and account takeover

**Evidence**:

- Payload: `<script>alert('Stored XSS')</script>`
- Confirmed persistence after page refresh
- Stored in database permanently

**Remediation**: HTML entity encoding with `htmlspecialchars()`

---

### 3. Local File Inclusion (HIGH - CVSS 7.5)

**Location**: `/vulnerabilities/fi/` (parameter: `page`)

**Impact**:

- Arbitrary file reading from server
- System file access (`/etc/passwd`)
- Configuration file exposure risk
- Source code disclosure

**Evidence**:

- Payload: `?page=../../../../etc/passwd`
- Successfully read system users
- PHP filter wrapper exploitation

**Remediation**: File path whitelist and input validation

---

### 4. Reflected XSS (MEDIUM - CVSS 6.1)

**Location**: `/vulnerabilities/xss_r/` (parameter: `name`)

**Impact**:

- JavaScript injection in victim browsers
- Session cookie theft possible
- Phishing attack vector
- Requires social engineering

**Evidence**:

- Payload: `<script>alert('XSS')</script>`
- Multiple injection vectors confirmed
- Proof-of-concept HTML file created

**Remediation**: Output encoding and Content Security Policy

---

## 💡 Proof of Concept

All vulnerabilities have been verified with working exploits:

### SQL Injection PoC:

```sql
-- Authentication bypass
URL: http://localhost/vulnerabilities/sqli/?id=' OR '1'='1

-- Database extraction
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1" \
  --cookie="PHPSESSID=xxx; security=low" \
  -D dvwa -T users --dump --batch
```

### Stored XSS PoC:

```html
<!-- Guestbook injection -->
Name: Attacker Message:
<script>
  alert("Stored XSS - affects all users");
</script>
```

### LFI PoC:

```
# System file access
http://localhost/vulnerabilities/fi/?page=../../../../etc/passwd

# Source code exposure
http://localhost/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=include.php
```

### Reflected XSS PoC:

```html
<!-- URL-based injection -->
http://localhost/vulnerabilities/xss_r/?name=
<script>
  alert("XSS");
</script>
```

**Note**: Interactive PoC file available: `exploitation/xss/reflected-xss-poc.html`

---

## 🛡️ Remediation Summary

### Immediate Priorities :

**SQL Injection**:

```php
// SECURE: Use prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = :id");
$stmt->bindParam(':id', $id, PDO::PARAM_INT);
$stmt->execute();
```

**XSS (Both types)**:

```php
// SECURE: HTML entity encoding
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```

**File Inclusion**:

```php
// SECURE: Whitelist approach
$allowed = ['file1.php', 'file2.php', 'file3.php'];
if (in_array($_GET['page'], $allowed)) {
    include($_GET['page']);
} else {
    die("Access Denied");
}
```

### Additional Security Controls:

- Deploy Web Application Firewall (WAF)
- Implement Content Security Policy (CSP)
- Add security headers (X-XSS-Protection, X-Frame-Options)
- Enable HTTPOnly cookies
- Implement rate limiting
- Add comprehensive logging

---

## 📚 Learning Outcomes

Through this project, I demonstrated proficiency in:

### Technical Skills:

- ✅ Network reconnaissance and enumeration
- ✅ Web application security testing
- ✅ SQL injection (manual and automated)
- ✅ Cross-site scripting (XSS) exploitation
- ✅ Local file inclusion (LFI) attacks
- ✅ Burp Suite usage and HTTP manipulation
- ✅ SQLMap usage and database extraction
- ✅ Security tool selection and usage

### Analytical Skills:

- ✅ Vulnerability identification and classification
- ✅ Risk assessment using CVSS scoring
- ✅ Impact analysis and business risk evaluation
- ✅ Attack scenario development
- ✅ Root cause analysis

### Communication Skills:

- ✅ Professional technical report writing
- ✅ Clear vulnerability documentation
- ✅ Step-by-step reproduction instructions
- ✅ Actionable remediation recommendations
- ✅ Executive-level summaries

### Methodology:

- ✅ Systematic testing approach
- ✅ Evidence collection and organization
- ✅ Professional documentation standards
- ✅ OWASP and CWE framework adherence
- ✅ Industry best practices

---

## 🔧 Environment Details

### Target Application:

- **Name**: DVWA (Damn Vulnerable Web Application)
- **Version**: 1.10 Development
- **Container**: Docker (vulnerables/web-dvwa)
- **URL**: http://localhost
- **Security Level**: Low (for educational purposes)

### Infrastructure:

- **Web Server**: Apache 2.4.25 (Debian)
- **Backend**: PHP 5.6.40
- **Database**: MySQL (MariaDB fork)
- **OS**: Linux Debian 9 (stretch)
- **Host**: Windows 11

### Testing Period:

- **Start Date**: January 12, 2026
- **End Date**: January 16, 2026
- **Duration**: 5 days
- **Total Hours**: ~19 hours

---

## ⚠️ Important Disclaimer

### Legal and Ethical Considerations:

**THIS PROJECT WAS CONDUCTED LEGALLY AND ETHICALLY:**

✅ **Authorized Testing**: All testing performed on local Docker container under my control

✅ **Intentionally Vulnerable**: DVWA is designed specifically for security training

✅ **Educational Purpose**: Project completed as part of academic coursework

✅ **No Unauthorized Access**: No real production systems or third-party systems were tested

❌ **NEVER** perform security testing on systems without explicit written authorization

❌ **NEVER** exploit vulnerabilities for malicious purposes

❌ **NEVER** access unauthorized data or systems

### Responsible Disclosure:

In real-world scenarios:

- Always obtain written permission before testing
- Follow responsible disclosure practices
- Report vulnerabilities to appropriate parties
- Respect bug bounty program rules
- Never publicly disclose before remediation
- Comply with all applicable laws and regulations

**Unauthorized hacking is illegal and can result in criminal prosecution.**

---

## 📖 References and Resources

### OWASP Resources:

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **XSS Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- **SQL Injection Prevention**: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Security Standards:

- **CWE Database**: https://cwe.mitre.org/
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
- **PCI DSS**: https://www.pcisecuritystandards.org/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework

### Learning Platforms:

- **PortSwigger Web Security Academy**: https://portswigger.net/web-security
- **DVWA GitHub**: https://github.com/digininja/DVWA
- **HackTheBox**: https://www.hackthebox.com/
- **TryHackMe**: https://tryhackme.com/

### Tool Documentation:

- **SQLMap**: https://github.com/sqlmapproject/sqlmap/wiki
- **Burp Suite**: https://portswigger.net/burp/documentation
- **Nmap**: https://nmap.org/book/man.html

---

## 👤 Author

**Student**: Lakshan  
**Project**: Cyber Security Bug Bounty Project  
**Submission Date**: January 17, 2026

---

## 📊 Project Statistics

- **Lines of Documentation**: 5,000+
- **Screenshots Captured**: 15+
- **Tools Used**: 8
- **Vulnerabilities Found**: 4
- **Reports Written**: 5 (4 individual + 1 comprehensive)
- **Code Samples**: 20+
- **Commands Documented**: 50+
- **Time Investment**: 19 hours

---

## 🎯 Submission Information

**Deadline**: January 17, 2026, 11:59 PM (IST)

**Submission Format**: GitHub Repository

**Repository URL**: https://github.com/Lakshan-Maduranga511/bug-bounty-project

**Submission Contents**:

- ✅ Complete project structure
- ✅ All reconnaissance outputs
- ✅ Exploitation evidence
- ✅ Screenshots (15+)
- ✅ Individual vulnerability reports (4)
- ✅ Comprehensive final report
- ✅ README documentation
- ✅ Proof-of-concept code

---

## 🏆 Project Achievements

This project successfully demonstrates:

✅ **Professional Methodology** - Industry-standard penetration testing approach

✅ **Technical Proficiency** - Effective use of security tools and techniques

✅ **Complete Coverage** - Comprehensive testing of OWASP Top 10 vulnerabilities

✅ **Quality Documentation** - Professional-grade security reports

✅ **Practical Skills** - Real-world exploitation capabilities

✅ **Ethical Conduct** - Responsible and legal security testing

✅ **Portfolio Ready** - Professional work suitable for career portfolio

---

## 📝 Notes

### For Instructors/Reviewers:

This project demonstrates competency in:

- Cybersecurity fundamentals
- Vulnerability assessment
- Penetration testing methodology
- Security tool usage
- Professional documentation
- Risk assessment
- Remediation planning

All work is original and completed individually as part of the Bug Bounty 101 course requirements.

### For Future Reference:

This project serves as:

- Portfolio piece for job applications
- Reference for security methodology
- Example of professional reporting
- Template for future assessments
- Demonstration of technical skills

---

## 🙏 Acknowledgments

- **DVWA Development Team** - For creating excellent training software
- **OWASP Community** - For security resources and guidelines
- **Course Instructors** - For guidance and support
- **Security Community** - For tools and knowledge sharing

---

_This project demonstrates ethical hacking practices and professional security reporting in a controlled educational environment. All testing was conducted legally and responsibly on authorized systems._

**⭐ If you found this project helpful for learning, please star the repository!**

---

**END OF README**
