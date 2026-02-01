#!/usr/bin/env python3

 
import re
import json


class DataExtractor:
    """Simple data extractor with security validation"""
    
    def __init__(self):
        self.email_pattern = re.compile(
            r'\b[a-zA-Z0-9][a-zA-Z0-9._+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b'
        )
        
        self.url_pattern = re.compile(
            r'https?://(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?'
        )
        
        self.phone_pattern = re.compile(
            r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        )
        
        self.card_pattern = re.compile(
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
        )
        
        self.dangerous = [
            r'<script',
            r'javascript:',
            r'UNION\s+SELECT',
            r'DROP\s+TABLE',
        ]
    
    def is_safe(self, text):
        """Check if input contains malicious patterns"""
        for pattern in self.dangerous:
            if re.search(pattern, text, re.IGNORECASE):
                return False
        return True
    
    def validate_luhn(self, card_number):
        """Validate credit card using Luhn algorithm"""
        digits = re.sub(r'[-\s]', '', card_number)
        if not digits.isdigit() or len(digits) != 16:
            return False
        
        total = 0
        for i, digit in enumerate(reversed(digits)):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        
        return total % 10 == 0
    
    def mask_email(self, email):
        """Mask email for security: user@domain.com -> u***r@domain.com"""
        local, domain = email.rsplit('@', 1)
        if len(local) > 2:
            return f"{local[0]}***{local[-1]}@{domain}"
        return f"***@{domain}"
    
    def mask_card(self, card):
        """Mask card number: 1234-5678-9012-3456 -> ****-****-****-3456"""
        digits = re.sub(r'[-\s]', '', card)
        return f"****-****-****-{digits[-4:]}"
    
    def extract(self, text):
        """Extract all data types from text"""
        
        if not self.is_safe(text):
            return {
                'status': 'REJECTED',
                'reason': 'Malicious patterns detected',
                'emails': [],
                'urls': [],
                'phones': [],
                'cards': []
            }
        
        emails = list(set(self.email_pattern.findall(text)))
        urls = list(set(self.url_pattern.findall(text)))
        phones = list(set(self.phone_pattern.findall(text)))
        cards_raw = list(set(self.card_pattern.findall(text)))
        
        cards = [c for c in cards_raw if self.validate_luhn(c)]
        
        return {
            'status': 'SUCCESS',
            'emails': [self.mask_email(e) for e in emails],
            'urls': urls,
            'phones': phones,
            'cards': [self.mask_card(c) for c in cards]
        }


def main():
    """Run the data extraction program"""
    
    try:
        with open('sample_input.txt', 'r') as f:
            text = f.read()
    except FileNotFoundError:
        print("Error: sample_input.txt not found!")
        return
    
    extractor = DataExtractor()
    results = extractor.extract(text)
    
    print("\n" + "="*60)
    print("DATA EXTRACTION RESULTS")
    print("="*60)
    
    if results['status'] == 'REJECTED':
        print(f"\nWARNING: {results['reason']}")
    else:
        print(f"\nEmails found: {len(results['emails'])}")
        for email in results['emails']:
            print(f"   - {email}")
        
        print(f"\nURLs found: {len(results['urls'])}")
        for url in results['urls']:
            print(f"   - {url}")
        
        print(f"\nPhones found: {len(results['phones'])}")
        for phone in results['phones']:
            print(f"   - {phone}")
        
        print(f"\nValid cards found: {len(results['cards'])}")
        for card in results['cards']:
            print(f"   - {card}")
    
    print("\n" + "="*60)
    
    with open('output.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\nResults saved to output.json\n")


if __name__ == "__main__":
    main()