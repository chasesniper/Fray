#!/usr/bin/env python3
"""
Recategorize 'other' payloads into proper categories
Most are XSS variants that should be in xss/obfuscated.json
"""

import json

def main():
    print("🔄 Recategorizing 'other' payloads...")
    
    # Load other/general.json
    with open('payloads/other/general.json', 'r') as f:
        other_data = json.load(f)
    
    print(f"📊 Found {len(other_data['payloads'])} payloads in 'other' category")
    
    # Most of these are XSS obfuscation/encoding variants
    # Let's move them to xss/obfuscated.json
    
    # Load xss/obfuscated.json
    with open('payloads/xss/obfuscated.json', 'r') as f:
        xss_obf_data = json.load(f)
    
    original_xss_count = len(xss_obf_data['payloads'])
    
    # Categorize payloads
    xss_payloads = []
    truly_other = []
    
    for payload in other_data['payloads']:
        payload_str = payload.get('payload', '').lower()
        
        # Check if it's XSS-related
        xss_indicators = [
            'alert', 'script', 'svg', 'img', 'onerror', 'onload', 
            'onfocus', 'onclick', 'onmouseover', 'eval', 'prompt',
            'confirm', 'javascript:', '</script>', '</style>',
            'ale', 'rt', '\\x', 'window[', 'self[', 'top[',
            'globalthis', 'autofocus', 'ontoggle', 'onwheel'
        ]
        
        if any(indicator in payload_str for indicator in xss_indicators):
            # Update category
            payload['category'] = 'xss'
            payload['subcategory'] = 'obfuscated'
            xss_payloads.append(payload)
        else:
            truly_other.append(payload)
    
    print(f"\n📊 Categorization:")
    print(f"  - XSS payloads: {len(xss_payloads)}")
    print(f"  - Truly 'other': {len(truly_other)}")
    
    # Add XSS payloads to xss/obfuscated.json
    # Renumber IDs to avoid conflicts
    next_id = original_xss_count + 1
    for payload in xss_payloads:
        payload['id'] = f"xss-obf-{next_id:04d}"
        next_id += 1
        xss_obf_data['payloads'].append(payload)
    
    xss_obf_data['count'] = len(xss_obf_data['payloads'])
    
    # Save updated xss/obfuscated.json
    with open('payloads/xss/obfuscated.json', 'w') as f:
        json.dump(xss_obf_data, f, indent=2)
    
    print(f"\n✅ Updated xss/obfuscated.json:")
    print(f"  - Before: {original_xss_count} payloads")
    print(f"  - After: {xss_obf_data['count']} payloads")
    print(f"  - Added: {len(xss_payloads)} payloads")
    
    # Update other/general.json with only truly 'other' payloads
    other_data['payloads'] = truly_other
    other_data['count'] = len(truly_other)
    other_data['description'] = "HTTP protocol attacks, encoding experiments, and hybrid techniques that don't fit standard categories"
    
    with open('payloads/other/general.json', 'w') as f:
        json.dump(other_data, f, indent=2)
    
    print(f"\n✅ Updated other/general.json:")
    print(f"  - Kept: {len(truly_other)} truly 'other' payloads")
    print(f"  - Moved to XSS: {len(xss_payloads)} payloads")
    
    # Calculate new total
    old_total = 2325
    new_total = old_total - 313  # Removed junk
    
    print(f"\n📊 Repository totals:")
    print(f"  - Old total: {old_total} payloads")
    print(f"  - Removed junk: 313 payloads")
    print(f"  - New total: {new_total} payloads")
    print(f"\n✅ Cleanup complete!")

if __name__ == '__main__':
    main()
