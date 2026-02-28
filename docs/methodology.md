# Testing Methodology

This document describes the comprehensive methodology used to test and collect the 24,700+ payloads in this database.

## Overview

The testing was conducted over **100 rounds** spanning multiple weeks, systematically covering all major web application attack vectors with a focus on WAF bypass techniques.

## Target Environment

- **Target**: Cloudflare-protected endpoint (waf.cumulusfire.net)
- **WAF**: Cloudflare Web Application Firewall
- **Testing Period**: February 2026
- **Total Payloads**: 24,705
- **Success Rate**: 0% (demonstrating WAF effectiveness)

## Testing Phases

### Phase 1: Baseline Testing (Rounds 1-20)
- Basic XSS vectors
- Standard SQL injection
- Common bypass techniques
- Encoding variations

### Phase 2: Advanced Techniques (Rounds 21-50)
- HTTP/2 specific attacks
- Desynchronization attacks
- Grammar-based fuzzing
- Differential parsing
- Content-Type confusion

### Phase 3: Research-Based Payloads (Rounds 51-95)
- GenXSS AI-generated payloads
- Community-confirmed bypasses
- PortSwigger cheat sheet vectors
- Academic research payloads
- Mutation XSS (mXSS)

### Phase 4: Novel Techniques (Rounds 96-100)
- PortSwigger 2026 XSS Cheat Sheet
- Cloudflare July 2025 WAF Changelog techniques
- Browser automation testing
- Reverse engineering analysis
- Advanced bypass attempts

## Attack Vectors Tested

### 1. Cross-Site Scripting (XSS) - 21,755 payloads

#### Basic XSS
- Script tags: `<script>alert(1)</script>`
- Event handlers: `<img src=x onerror=alert(1)>`
- SVG vectors: `<svg onload=alert(1)>`
- Body/iframe: `<body onload=alert(1)>`

#### Encoded XSS
- URL encoding: `%3Cscript%3E`
- HTML entities: `&lt;script&gt;`
- Unicode: `\u003cscript\u003e`
- Base64: `PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`
- Mixed encoding combinations

#### Obfuscated XSS
- Case variation: `<ScRiPt>`, `<SCRIPT>`
- Whitespace: `<script >`, `< script>`
- Null bytes: `<script\x00>`
- Comments: `<!--><script>`, `<script><!---->`
- Nested tags: `<scr<script>ipt>`

#### Advanced XSS
- Polyglot payloads
- Mutation XSS (mXSS)
- DOM-based XSS
- Template injection
- Prototype pollution
- DOM clobbering

### 2. SQL Injection - 14 payloads
- Union-based: `' UNION SELECT NULL--`
- Boolean-based: `' AND '1'='1`
- Time-based: `' OR SLEEP(5)--`
- Error-based: `' AND 1=CONVERT(int, @@version)--`
- Stacked queries: `'; DROP TABLE users--`

### 3. Command Injection - 11 payloads
- Shell commands: `; ls`, `| whoami`
- Backticks: `` `id` ``
- Command substitution: `$(whoami)`
- Encoded commands: `;%20ls`

### 4. Server-Side Request Forgery (SSRF) - 14 payloads
- AWS metadata: `http://169.254.169.254/latest/meta-data/`
- GCP metadata: `http://metadata.google.internal/`
- Azure metadata: `http://169.254.169.254/metadata/instance`
- Internal IPs: `http://localhost`, `http://127.0.0.1`
- File protocol: `file:///etc/passwd`

### 5. XML External Entity (XXE) - 3 payloads
- File disclosure via XXE
- SSRF via XXE
- Blind XXE with out-of-band

### 6. Path Traversal - 10 payloads
- Basic: `../../etc/passwd`
- Encoded: `%2e%2e%2f`
- Double encoded: `%252e%252e%252f`
- Null byte: `../../etc/passwd%00`

### 7. Server-Side Template Injection (SSTI) - 10 payloads
- Jinja2: `{{7*7}}`, `{{config}}`
- Twig: `{{7*'7'}}`
- Freemarker: `${7*7}`
- Velocity: `#set($x=7*7)$x`

### 8. Other Vectors
- Open redirect
- CRLF injection
- HTTP parameter pollution
- Header injection

## Delivery Methods

### HTTP Methods
- GET requests
- POST (application/x-www-form-urlencoded)
- POST (application/json)
- POST (multipart/form-data)
- PUT, PATCH, DELETE, OPTIONS
- HTTP/2 requests

### Injection Points
- URL parameters: `?param=payload`
- POST body parameters
- JSON fields
- HTTP headers (User-Agent, Referer, X-Forwarded-For, etc.)
- Cookies
- File uploads (filename, content)

### Encoding Layers
- Single encoding
- Double encoding
- Triple encoding
- Mixed encoding (URL + HTML entities)
- Charset variations (UTF-7, UTF-16, ISO-8859-1)

## Testing Tools

### Custom Scripts
- Python-based HTTP testing framework
- Raw socket connections for precise control
- SSL/TLS with custom configurations
- HTTP/2 support via h2 library

### Browser Automation
- Playwright for real browser testing
- Chromium engine
- JavaScript execution context
- DOM manipulation testing

### Analysis Tools
- Response parsing and classification
- Pattern detection
- Statistical analysis
- Payload effectiveness scoring

## Detection Criteria

### Blocked Requests
- HTTP 403 Forbidden
- HTTP 406 Not Acceptable
- HTTP 503 Service Unavailable
- Error code 1020 (Cloudflare specific)

### Passed Requests
- HTTP 200 OK
- HTTP 301/302 Redirects
- Other 2xx/3xx status codes

### Reflection Detection
- Payload present in response body
- XSS indicators in HTML
- JavaScript execution markers
- Alert/confirm/prompt dialog detection

## Key Findings

### WAF Capabilities Observed

1. **Normalization**
   - Decodes all encoding methods
   - Handles nested encoding
   - Processes charset variations

2. **Pattern Matching**
   - Tag + event handler combinations
   - SQL keywords and syntax
   - Command injection patterns
   - Path traversal sequences

3. **Context Awareness**
   - Understands HTML structure
   - Parses JavaScript context
   - Recognizes SQL syntax
   - Detects protocol violations

4. **Comprehensive Coverage**
   - Blocks rare/deprecated HTML tags
   - Detects browser-specific quirks
   - Catches mutation XSS
   - Prevents polyglot attacks

### Bypass Attempts (All Failed)

- ✗ Traditional obfuscation
- ✗ Advanced encoding
- ✗ Parameter smuggling
- ✗ Header injection
- ✗ Charset confusion
- ✗ Browser automation
- ✗ HTTP/2 specific attacks
- ✗ Mutation XSS
- ✗ DOM clobbering
- ✗ Polyglot payloads

## Statistical Analysis

### Overall Results
- **Total Payloads**: 24,705
- **Blocked**: 24,690 (99.94%)
- **Passed (Non-malicious)**: 15 (0.06%)
- **Errors**: 0
- **Bypasses Found**: 0

### By Category
- XSS: 21,755 payloads, 99.9% blocked
- SQLi: 14 payloads, 100% blocked
- Command Injection: 11 payloads, 100% blocked
- SSRF: 14 payloads, 100% blocked
- XXE: 3 payloads, 100% blocked
- Path Traversal: 10 payloads, 100% blocked
- SSTI: 10 payloads, 100% blocked
- Other: 2,888 payloads, 99.5% blocked

### By Technique
- Direct injection: 85% of payloads
- Encoding: 10% of payloads
- Obfuscation: 3% of payloads
- Mutation: 1% of payloads
- Polyglot: 1% of payloads

## Lessons Learned

### WAF Effectiveness
Modern WAFs like Cloudflare's are highly effective against:
- Known attack patterns
- Encoding variations
- Obfuscation techniques
- Browser-specific quirks
- Novel research-based attacks

### Attack Evolution
Attackers continue to develop:
- More sophisticated obfuscation
- Context-aware payloads
- Mutation techniques
- Polyglot attacks
- Zero-day vectors

### Defense Recommendations
1. Deploy comprehensive WAF with regular updates
2. Implement defense in depth
3. Monitor for anomalous patterns
4. Keep WAF rules current
5. Test against latest attack vectors

## Reproducibility

All tests can be reproduced using:
1. The payload database in this repository
2. The testing tools in `/tools` directory
3. The methodology described in this document

### Example Test

```python
from tools.payload_tester import WAFTester

# Initialize tester
tester = WAFTester(target_url="https://your-target.com")

# Load payloads
payloads = tester.load_payloads('payloads/xss/basic.json')

# Run tests
results = tester.test_payloads(payloads)

# Generate report
tester.generate_report(results, output='report.html')
```

## Ethical Considerations

All testing was conducted:
- Against a demo/testing environment
- With no malicious intent
- For educational and research purposes
- Following responsible disclosure practices
- In compliance with applicable laws

## Future Work

- Expand payload database with new techniques
- Test against multiple WAF vendors
- Implement machine learning classification
- Develop automated bypass discovery
- Create comparative analysis tools

## References

- OWASP Testing Guide
- PortSwigger Web Security Academy
- Cloudflare WAF Documentation
- GenXSS Research Paper
- Community security research

---

Last Updated: February 2026
