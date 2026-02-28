#!/usr/bin/env python3
"""
Extract and organize payloads from test scripts into JSON format
"""

import json
import re
import os
from pathlib import Path
from typing import List, Dict

def extract_payloads_from_file(filepath: str) -> List[Dict]:
    """Extract payloads from a Python test script"""
    payloads = []
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    # Extract payload lists and tuples
    # Pattern: ("payload", "description") or ('payload', 'description')
    pattern = r'[(\[][\s\n]*["\'](.+?)["\'][\s\n]*,[\s\n]*["\'](.+?)["\'][\s\n]*[)\]]'
    matches = re.findall(pattern, content, re.MULTILINE | re.DOTALL)
    
    for payload, desc in matches:
        # Clean up escaped characters
        payload = payload.replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r')
        
        payloads.append({
            'payload': payload,
            'description': desc,
            'source_file': os.path.basename(filepath)
        })
    
    return payloads

def classify_payload(payload: str, description: str) -> Dict[str, str]:
    """Classify payload by technique and category"""
    payload_lower = payload.lower()
    desc_lower = description.lower()
    
    # Determine category
    if '<script' in payload_lower or 'alert' in payload_lower or 'onerror' in payload_lower or '<svg' in payload_lower:
        category = 'xss'
    elif 'union' in payload_lower or 'select' in payload_lower or 'drop table' in payload_lower:
        category = 'sqli'
    elif '../../' in payload or '../' in payload:
        category = 'path_traversal'
    elif 'http://' in payload_lower or 'https://' in payload_lower:
        category = 'ssrf'
    elif '<?xml' in payload or 'DOCTYPE' in payload:
        category = 'xxe'
    elif '{{' in payload or '${' in payload:
        category = 'ssti'
    elif 'javascript:' in payload_lower:
        category = 'open-redirect'
    else:
        category = 'other'
    
    # Determine subcategory for XSS
    if category == 'xss':
        if 'svg' in payload_lower:
            subcategory = 'svg_based'
        elif 'polyglot' in desc_lower:
            subcategory = 'polyglot'
        elif 'mutation' in desc_lower or 'mxss' in desc_lower:
            subcategory = 'mutation'
        elif 'dom' in desc_lower:
            subcategory = 'dom_based'
        elif 'encode' in desc_lower or 'unicode' in desc_lower or 'entity' in desc_lower:
            subcategory = 'encoded'
        elif 'obfusc' in desc_lower or 'case' in desc_lower:
            subcategory = 'obfuscated'
        else:
            subcategory = 'basic'
    else:
        subcategory = 'general'
    
    # Determine technique
    if 'encode' in desc_lower or 'unicode' in desc_lower:
        technique = 'encoding'
    elif 'obfusc' in desc_lower or 'case' in desc_lower:
        technique = 'obfuscation'
    elif 'mutation' in desc_lower:
        technique = 'mutation'
    elif 'polyglot' in desc_lower:
        technique = 'polyglot'
    else:
        technique = 'direct_injection'
    
    return {
        'category': category,
        'subcategory': subcategory,
        'technique': technique
    }

def main():
    """Main extraction function"""
    # Source directory with test scripts
    source_dir = Path('/Users/mnishihara/CascadeProjects/cloudflare-bounty-recon/recon')
    output_dir = Path('/Users/mnishihara/CascadeProjects/waf-payload-database/payloads')
    
    # Create output directories
    categories = ['xss', 'sqli', 'command-injection', 'ssrf', 'xxe', 'path-traversal', 'ssti', 'open-redirect', 'other']
    for cat in categories:
        (output_dir / cat).mkdir(parents=True, exist_ok=True)
    
    # Track payloads by category
    categorized_payloads = {cat: [] for cat in categories}
    
    # Extract from all test files
    test_files = list(source_dir.glob('waf_*.py'))
    
    print(f"Found {len(test_files)} test files")
    
    for test_file in test_files:
        print(f"Processing {test_file.name}...")
        payloads = extract_payloads_from_file(str(test_file))
        
        for idx, payload_data in enumerate(payloads):
            classification = classify_payload(
                payload_data['payload'],
                payload_data['description']
            )
            
            # Create full payload entry
            entry = {
                'id': f"{classification['category']}-{len(categorized_payloads[classification['category']]) + 1:04d}",
                'category': classification['category'],
                'subcategory': classification['subcategory'],
                'payload': payload_data['payload'],
                'description': payload_data['description'],
                'technique': classification['technique'],
                'source_file': payload_data['source_file'],
                'tested_against': ['cloudflare_waf'],
                'success_rate': 0.0,
                'blocked': True
            }
            
            categorized_payloads[classification['category']].append(entry)
    
    # Write to JSON files
    for category, payloads in categorized_payloads.items():
        if not payloads:
            continue
        
        # Group by subcategory
        subcategories = {}
        for payload in payloads:
            subcat = payload['subcategory']
            if subcat not in subcategories:
                subcategories[subcat] = []
            subcategories[subcat].append(payload)
        
        # Write each subcategory to separate file
        for subcat, subcat_payloads in subcategories.items():
            output_file = output_dir / category / f"{subcat}.json"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'category': category,
                    'subcategory': subcat,
                    'count': len(subcat_payloads),
                    'payloads': subcat_payloads
                }, f, indent=2, ensure_ascii=False)
            
            print(f"  Wrote {len(subcat_payloads)} payloads to {output_file}")
    
    # Generate summary
    total = sum(len(p) for p in categorized_payloads.values())
    print(f"\n✓ Extraction complete!")
    print(f"  Total payloads: {total}")
    for cat, payloads in categorized_payloads.items():
        if payloads:
            print(f"  {cat}: {len(payloads)}")

if __name__ == '__main__':
    main()
