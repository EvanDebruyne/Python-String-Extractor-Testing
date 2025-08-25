#!/usr/bin/env python3
"""
String Extractor - Binary File Analysis Tool
A comprehensive tool for extracting and analyzing strings from binary files.
Perfect for malware analysis, forensics, and security research.

Author: [Your Name]
License: MIT
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Set, Tuple
import json
from datetime import datetime
import hashlib


class StringExtractor:
    """Main class for extracting and analyzing strings from binary files."""
    
    def __init__(self, min_length: int = 4, encoding: str = 'utf-8'):
        self.min_length = min_length
        self.encoding = encoding
        self.extracted_strings = []
        self.analysis_results = {}
        
    def extract_strings(self, file_path: str, methods: List[str] = None) -> Dict[str, List[str]]:
        """
        Extract strings using multiple methods.
        
        Args:
            file_path: Path to the binary file
            methods: List of extraction methods to use
            
        Returns:
            Dictionary with method names as keys and extracted strings as lists
        """
        if methods is None:
            methods = ['ascii', 'unicode', 'wide', 'regex']
            
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        results = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            for method in methods:
                if method == 'ascii':
                    results['ascii'] = self._extract_ascii_strings(data)
                elif method == 'unicode':
                    results['unicode'] = self._extract_unicode_strings(data)
                elif method == 'wide':
                    results['wide'] = self._extract_wide_strings(data)
                elif method == 'regex':
                    results['regex'] = self._extract_regex_strings(data)
                    
        except Exception as e:
            print(f"Error reading file: {e}")
            return {}
            
        return results
    
    def _extract_ascii_strings(self, data: bytes) -> List[str]:
        """Extract ASCII strings from binary data."""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII range
                current_string += chr(byte)
            else:
                if len(current_string) >= self.min_length:
                    strings.append(current_string)
                current_string = ""
                
        # Don't forget the last string
        if len(current_string) >= self.min_length:
            strings.append(current_string)
            
        return list(set(strings))  # Remove duplicates
    
    def _extract_unicode_strings(self, data: bytes) -> List[str]:
        """Extract Unicode strings from binary data."""
        strings = []
        
        try:
            # Try different encodings
            for encoding in ['utf-8', 'utf-16', 'utf-32', 'latin-1']:
                try:
                    text = data.decode(encoding, errors='ignore')
                    # Extract strings that match our criteria
                    words = re.findall(r'[a-zA-Z0-9_\-\.]{' + str(self.min_length) + r',}', text)
                    strings.extend(words)
                except:
                    continue
        except:
            pass
            
        return list(set(strings))
    
    def _extract_wide_strings(self, data: bytes) -> List[str]:
        """Extract wide (UTF-16) strings from binary data."""
        strings = []
        
        if len(data) < 2:
            return strings
            
        # Look for UTF-16 strings (every other byte should be readable)
        for i in range(0, len(data) - 1, 2):
            if i + 1 < len(data):
                # Check if this could be a readable wide character
                if (32 <= data[i] <= 126) and (data[i+1] == 0):
                    # Found potential wide string start
                    wide_string = ""
                    j = i
                    while j < len(data) - 1:
                        if (32 <= data[j] <= 126) and (data[j+1] == 0):
                            wide_string += chr(data[j])
                            j += 2
                        else:
                            break
                    
                    if len(wide_string) >= self.min_length:
                        strings.append(wide_string)
                        
        return list(set(strings))
    
    def _extract_regex_strings(self, data: bytes) -> List[str]:
        """Extract strings using regex patterns for common formats."""
        strings = []
        
        # Common patterns to look for
        patterns = [
            rb'[A-Za-z0-9_\-\.]{' + str(self.min_length).encode() + rb',}',  # Alphanumeric
            rb'https?://[^\s\x00]{' + str(self.min_length).encode() + rb',}',  # URLs
            rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',  # Email addresses
            rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            rb'[A-Za-z]:\\[^\x00]{' + str(self.min_length).encode() + rb',}',  # Windows paths
            rb'/[^\x00]{' + str(self.min_length).encode() + rb',}',  # Unix paths
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, data)
            for match in matches:
                try:
                    string = match.decode('utf-8', errors='ignore')
                    if len(string) >= self.min_length:
                        strings.append(string)
                except:
                    continue
                    
        return list(set(strings))
    
    def analyze_strings(self, strings: List[str]) -> Dict:
        """Analyze extracted strings for security-relevant patterns."""
        analysis = {
            'total_strings': len(strings),
            'avg_length': 0,
            'suspicious_patterns': [],
            'urls': [],
            'emails': [],
            'ip_addresses': [],
            'file_paths': [],
            'registry_keys': [],
            'api_calls': [],
            'suspicious_keywords': [],
            'encoding_stats': {}
        }
        
        if not strings:
            return analysis
            
        # Calculate average length
        total_length = sum(len(s) for s in strings)
        analysis['avg_length'] = total_length / len(strings)
        
        # Pattern analysis
        for string in strings:
            # URLs
            if re.match(r'https?://', string):
                analysis['urls'].append(string)
                
            # Email addresses
            if re.match(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', string):
                analysis['emails'].append(string)
                
            # IP addresses
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', string):
                analysis['ip_addresses'].append(string)
                
            # File paths
            if re.match(r'[A-Za-z]:\\', string) or string.startswith('/'):
                analysis['file_paths'].append(string)
                
            # Registry keys
            if string.startswith('HKEY_') or string.startswith('HKLM\\') or string.startswith('HKCU\\'):
                analysis['registry_keys'].append(string)
                
            # API calls
            if re.match(r'[A-Za-z]+[A-Za-z0-9_]*\(', string):
                analysis['api_calls'].append(string)
                
            # Suspicious keywords
            suspicious_keywords = [
                'admin', 'password', 'key', 'secret', 'token', 'auth', 'login',
                'shell', 'cmd', 'exec', 'system', 'process', 'inject', 'hook',
                'bypass', 'exploit', 'vulnerability', 'overflow', 'buffer',
                'malware', 'trojan', 'virus', 'backdoor', 'rootkit'
            ]
            
            for keyword in suspicious_keywords:
                if keyword.lower() in string.lower():
                    analysis['suspicious_keywords'].append(string)
                    break
                    
        # Remove duplicates
        for key in ['urls', 'emails', 'ip_addresses', 'file_paths', 'registry_keys', 'api_calls', 'suspicious_keywords']:
            analysis[key] = list(set(analysis[key]))
            
        return analysis
    
    def save_results(self, file_path: str, output_file: str = None):
        """Save extraction results to a file."""
        if output_file is None:
            base_name = Path(file_path).stem
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{base_name}_strings_{timestamp}.json"
            
        results = {
            'file_analyzed': file_path,
            'analysis_timestamp': datetime.now().isoformat(),
            'file_hash': self._calculate_file_hash(file_path),
            'extraction_settings': {
                'min_length': self.min_length,
                'encoding': self.encoding
            },
            'extracted_strings': self.extracted_strings,
            'analysis_results': self.analysis_results
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"Results saved to: {output_file}")
        except Exception as e:
            print(f"Error saving results: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of the analyzed file."""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            return file_hash
        except:
            return "ERROR"
    
    def print_summary(self, file_path: str):
        """Print a summary of the analysis results."""
        print("\n" + "="*60)
        print(f"STRING EXTRACTION ANALYSIS SUMMARY")
        print("="*60)
        print(f"File: {file_path}")
        print(f"File Hash: {self.analysis_results.get('file_hash', 'N/A')}")
        print(f"Total Strings Extracted: {self.analysis_results.get('total_strings', 0)}")
        print(f"Average String Length: {self.analysis_results.get('avg_length', 0):.2f}")
        
        print("\n" + "-"*40)
        print("SECURITY ANALYSIS FINDINGS")
        print("-"*40)
        
        findings = [
            ('URLs Found', 'urls'),
            ('Email Addresses', 'emails'),
            ('IP Addresses', 'ip_addresses'),
            ('File Paths', 'file_paths'),
            ('Registry Keys', 'registry_keys'),
            ('API Calls', 'api_calls'),
            ('Suspicious Keywords', 'suspicious_keywords')
        ]
        
        for label, key in findings:
            count = len(self.analysis_results.get(key, []))
            if count > 0:
                print(f"{label}: {count}")
                # Show first few examples
                examples = self.analysis_results.get(key, [])[:3]
                for example in examples:
                    print(f"  - {example}")
                if count > 3:
                    print(f"  ... and {count - 3} more")
                print()


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="String Extractor - Binary File Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python string_extractor.py malware.exe
  python string_extractor.py -m 8 -o results.json suspicious.bin
  python string_extractor.py --methods ascii,unicode,regex file.exe
        """
    )
    
    parser.add_argument('file', help='Binary file to analyze')
    parser.add_argument('-m', '--min-length', type=int, default=4,
                       help='Minimum string length (default: 4)')
    parser.add_argument('--methods', default='ascii,unicode,wide,regex',
                       help='Extraction methods to use (comma-separated)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--save-strings', action='store_true',
                       help='Save extracted strings to separate file')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate file exists
    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)
    
    # Parse methods
    methods = [m.strip() for m in args.methods.split(',')]
    valid_methods = ['ascii', 'unicode', 'wide', 'regex']
    for method in methods:
        if method not in valid_methods:
            print(f"Error: Invalid method '{method}'. Valid methods: {', '.join(valid_methods)}")
            sys.exit(1)
    
    print("🔍 String Extractor - Binary File Analysis Tool")
    print("=" * 50)
    print(f"Analyzing: {args.file}")
    print(f"Methods: {', '.join(methods)}")
    print(f"Min Length: {args.min_length}")
    print()
    
    try:
        # Initialize extractor
        extractor = StringExtractor(min_length=args.min_length)
        
        # Extract strings
        print("Extracting strings...")
        results = extractor.extract_strings(args.file, methods)
        
        # Combine all results
        all_strings = []
        for method, strings in results.items():
            all_strings.extend(strings)
            if args.verbose:
                print(f"{method.upper()}: {len(strings)} strings")
        
        # Remove duplicates and sort
        all_strings = sorted(list(set(all_strings)), key=len, reverse=True)
        extractor.extracted_strings = all_strings
        
        print(f"\nTotal unique strings extracted: {len(all_strings)}")
        
        # Analyze strings
        print("Analyzing strings for security patterns...")
        extractor.analysis_results = extractor.analyze_strings(all_strings)
        
        # Print summary
        extractor.print_summary(args.file)
        
        # Save results
        if args.output or args.save_strings:
            extractor.save_results(args.file, args.output)
        
        # Save strings to separate file if requested
        if args.save_strings:
            strings_file = f"{Path(args.file).stem}_strings_only.txt"
            try:
                with open(strings_file, 'w', encoding='utf-8') as f:
                    for string in all_strings:
                        f.write(string + '\n')
                print(f"Strings saved to: {strings_file}")
            except Exception as e:
                print(f"Error saving strings: {e}")
        
        print("\n✅ Analysis complete!")
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
