#!/usr/bin/env python3
"""
Cleanup 'other' category - Recategorize and remove junk payloads
"""

import json
import re
import base64

def is_valid_payload(payload_str):
    """Check if payload is valid (not test metadata or script fragment)"""
    if not payload_str or len(payload_str) < 3:
        return False
    
    # Filter out test script fragments
    junk_patterns = [
        r'^print\(',
        r'^test\(',
        r'^\s*#',
        r'^===',
        r'^---',
        r'^\s*$',
        r'^def\s+',
        r'^for\s+',
        r'^if\s+',
        r'^\s*\n',
        r'^raw_req\(',
        r'^charset_tests',
        r'Accept-Charset$',
        r'^utf-8$',
        r'^replace$',
        r'^globalHtml$',
    ]
    
    for pattern in junk_patterns:
        if re.search(pattern, payload_str, re.MULTILINE):
            return False
    
    return True

def categorize_payload(payload_str):
    """Determine proper category for payload"""
    payload_lower = payload_str.lower()
    
    # XSS patterns
    if any(x in payload_lower for x in ['<script', 'alert(', 'onerror=', 'onload=', '<svg', '<img', 'javascript:', 'eval(', 'prompt(', 'confirm(']):
        return 'xss'
    
    # SQL injection
    if any(x in payload_lower for x in ['union select', 'or 1=1', 'and 1=1', "' or '", 'sleep(', 'waitfor delay']):
        return 'sqli'
    
    # Command injection
    if any(x in payload_lower for x in ['$(', '`', '|', ';whoami', ';id', '&&', '||']):
        return 'command_injection'
    
    # Path traversal
    if any(x in payload_lower for x in ['../', '..\\', '%2e%2e', 'etc/passwd']):
        return 'path_traversal'
    
    # SSRF
    if any(x in payload_lower for x in ['http://', 'https://', 'file://', 'gopher://', 'localhost', '127.0.0.1']):
        return 'ssrf'
    
    # SSTI
    if any(x in payload_lower for x in ['{{', '}}', '{%', '%}', '__class__', '__mro__']):
        return 'ssti'
    
    # XXE
    if any(x in payload_lower for x in ['<!entity', '<!doctype', 'system "', 'public "']):
        return 'xxe'
    
    # CRLF injection
    if any(x in payload_lower for x in ['%0d%0a', '\\r\\n', '\r\n']):
        return 'crlf_injection'
    
    # Base64 encoded (might be XSS)
    try:
        decoded = base64.b64decode(payload_str).decode('utf-8', errors='ignore')
        if any(x in decoded.lower() for x in ['alert', 'script', 'svg']):
            return 'xss'
    except:
        pass
    
    return 'other'

def cleanup_other_category():
    """Clean up the 'other' category"""
    print("🧹 Cleaning up 'other' category...")
    
    # Load other/general.json
    with open('payloads/other/general.json', 'r') as f:
        data = json.load(f)
    
    original_count = len(data['payloads'])
    print(f"📊 Original count: {original_count} payloads")
    
    # Categorize payloads
    categorized = {
        'xss': [],
        'sqli': [],
        'command_injection': [],
        'path_traversal': [],
        'ssrf': [],
        'ssti': [],
        'xxe': [],
        'crlf_injection': [],
        'other': [],
        'junk': []
    }
    
    for payload in data['payloads']:
        payload_str = payload.get('payload', '')
        
        if not is_valid_payload(payload_str):
            categorized['junk'].append(payload)
            continue
        
        category = categorize_payload(payload_str)
        categorized[category].append(payload)
    
    # Print statistics
    print("\n📊 Categorization Results:")
    for cat, items in categorized.items():
        if items:
            print(f"  - {cat}: {len(items)} payloads")
    
    # Keep only valid 'other' payloads
    valid_other = categorized['other']
    
    # Update the file
    data['payloads'] = valid_other
    data['count'] = len(valid_other)
    
    with open('payloads/other/general.json', 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n✅ Cleaned up 'other' category:")
    print(f"  - Kept: {len(valid_other)} valid payloads")
    print(f"  - Removed: {original_count - len(valid_other)} junk/test fragments")
    print(f"  - Recategorizable: {sum(len(v) for k, v in categorized.items() if k not in ['other', 'junk'])} payloads")
    
    # Save categorized payloads for manual review
    with open('categorized_payloads.json', 'w') as f:
        json.dump({k: v for k, v in categorized.items() if k not in ['other', 'junk']}, f, indent=2)
    
    print(f"\n💾 Saved recategorizable payloads to categorized_payloads.json")
    print("📝 Review and manually add these to proper categories if needed")

if __name__ == '__main__':
    cleanup_other_category()
