#!/usr/bin/env python3
"""
Batch String Analyzer
Processes multiple files and generates a comprehensive security report.
Useful for incident response and bulk malware analysis.
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from string_extractor import StringExtractor


class BatchAnalyzer:
    """Batch analysis of multiple files for security indicators."""
    
    def __init__(self, min_length: int = 4, methods: list = None):
        self.min_length = min_length
        self.methods = methods or ['ascii', 'unicode', 'wide', 'regex']
        self.extractor = StringExtractor(min_length=min_length)
        self.results = {}
        self.summary = {
            'total_files': 0,
            'processed_files': 0,
            'failed_files': 0,
            'total_strings': 0,
            'security_findings': {
                'urls': set(),
                'emails': set(),
                'ip_addresses': set(),
                'file_paths': set(),
                'registry_keys': set(),
                'api_calls': set(),
                'suspicious_keywords': set()
            },
            'high_risk_files': [],
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def analyze_file(self, file_path: str) -> dict:
        """Analyze a single file and return results."""
        try:
            print(f"Analyzing: {file_path}")
            
            # Extract strings
            results = self.extractor.extract_strings(file_path, self.methods)
            
            # Combine all strings
            all_strings = []
            for method, strings in results.items():
                all_strings.extend(strings)
            all_strings = list(set(all_strings))
            
            # Analyze strings
            analysis = self.extractor.analyze_strings(all_strings)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(analysis)
            
            # Store results
            file_result = {
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'file_hash': self.extractor._calculate_file_hash(file_path),
                'strings_count': len(all_strings),
                'risk_score': risk_score,
                'analysis': analysis,
                'extracted_strings': all_strings[:100]  # Store first 100 strings
            }
            
            # Update summary
            self._update_summary(file_result, analysis)
            
            # Check if high risk
            if risk_score >= 30:
                self.summary['high_risk_files'].append({
                    'file_path': file_path,
                    'risk_score': risk_score,
                    'indicators': list(analysis['suspicious_keywords'])[:5]
                })
            
            print(f"  ✓ Extracted {len(all_strings)} strings, Risk Score: {risk_score}/50")
            return file_result
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            self.summary['failed_files'] += 1
            return {'error': str(e), 'file_path': file_path}
    
    def _calculate_risk_score(self, analysis: dict) -> int:
        """Calculate a risk score based on security indicators."""
        score = 0
        
        # Network indicators (high risk)
        if analysis['urls']:
            score += 15
        if analysis['ip_addresses']:
            score += 10
        if analysis['emails']:
            score += 5
        
        # System artifacts (medium risk)
        if analysis['file_paths']:
            score += 8
        if analysis['registry_keys']:
            score += 5
        if analysis['api_calls']:
            score += 7
        
        # Suspicious keywords (high risk)
        if analysis['suspicious_keywords']:
            score += 20
        
        return min(score, 50)  # Cap at 50
    
    def _update_summary(self, file_result: dict, analysis: dict):
        """Update the overall summary with file results."""
        self.summary['total_strings'] += file_result['strings_count']
        
        # Aggregate security findings
        for key in self.summary['security_findings']:
            if key in analysis:
                self.summary['security_findings'][key].update(analysis[key])
    
    def analyze_directory(self, directory_path: str, file_extensions: list = None):
        """Analyze all files in a directory."""
        if file_extensions is None:
            file_extensions = ['.exe', '.dll', '.bin', '.dat', '.sys', '.drv']
        
        directory = Path(directory_path)
        if not directory.exists() or not directory.is_dir():
            print(f"Error: Directory '{directory_path}' not found or not a directory.")
            return
        
        # Find files to analyze
        files_to_analyze = []
        for ext in file_extensions:
            files_to_analyze.extend(directory.glob(f"*{ext}"))
            files_to_analyze.extend(directory.glob(f"*{ext.upper()}"))
        
        if not files_to_analyze:
            print(f"No files with extensions {file_extensions} found in {directory_path}")
            return
        
        print(f"Found {len(files_to_analyze)} files to analyze...")
        print("=" * 60)
        
        # Analyze each file
        for file_path in files_to_analyze:
            self.summary['total_files'] += 1
            result = self.analyze_file(str(file_path))
            self.results[str(file_path)] = result
            self.summary['processed_files'] += 1
        
        print("=" * 60)
        self._print_summary()
    
    def analyze_file_list(self, file_list: list):
        """Analyze a specific list of files."""
        print(f"Analyzing {len(file_list)} files...")
        print("=" * 60)
        
        for file_path in file_list:
            if os.path.exists(file_path):
                self.summary['total_files'] += 1
                result = self.analyze_file(file_path)
                self.results[file_path] = result
                self.summary['processed_files'] += 1
            else:
                print(f"File not found: {file_path}")
                self.summary['failed_files'] += 1
        
        print("=" * 60)
        self._print_summary()
    
    def _print_summary(self):
        """Print a comprehensive summary of the analysis."""
        print("\n" + "="*60)
        print("BATCH ANALYSIS SUMMARY")
        print("="*60)
        print(f"Total Files: {self.summary['total_files']}")
        print(f"Processed: {self.summary['processed_files']}")
        print(f"Failed: {self.summary['failed_files']}")
        print(f"Total Strings Extracted: {self.summary['total_strings']}")
        print(f"Analysis Time: {self.summary['analysis_timestamp']}")
        
        print("\n" + "-"*40)
        print("SECURITY FINDINGS ACROSS ALL FILES")
        print("-"*40)
        
        findings = [
            ('URLs', 'urls'),
            ('Email Addresses', 'emails'),
            ('IP Addresses', 'ip_addresses'),
            ('File Paths', 'file_paths'),
            ('Registry Keys', 'registry_keys'),
            ('API Calls', 'api_calls'),
            ('Suspicious Keywords', 'suspicious_keywords')
        ]
        
        for label, key in findings:
            count = len(self.summary['security_findings'][key])
            if count > 0:
                print(f"{label}: {count}")
                # Show first few examples
                examples = list(self.summary['security_findings'][key])[:3]
                for example in examples:
                    print(f"  - {example}")
                if count > 3:
                    print(f"  ... and {count - 3} more")
                print()
        
        if self.summary['high_risk_files']:
            print("-"*40)
            print("HIGH RISK FILES")
            print("-"*40)
            for file_info in self.summary['high_risk_files']:
                print(f"File: {file_info['file_path']}")
                print(f"Risk Score: {file_info['risk_score']}/50")
                print(f"Indicators: {', '.join(file_info['indicators'])}")
                print()
    
    def save_results(self, output_file: str = None):
        """Save all results to a JSON file."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"batch_analysis_{timestamp}.json"
        
        # Convert sets to lists for JSON serialization
        json_summary = self.summary.copy()
        for key in json_summary['security_findings']:
            json_summary['security_findings'][key] = list(json_summary['security_findings'][key])
        
        output_data = {
            'summary': json_summary,
            'file_results': self.results
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            print(f"Results saved to: {output_file}")
        except Exception as e:
            print(f"Error saving results: {e}")


def main():
    """Main CLI interface for batch analysis."""
    parser = argparse.ArgumentParser(
        description="Batch String Analyzer - Analyze multiple files for security indicators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python batch_analyzer.py -d /path/to/files
  python batch_analyzer.py -f file1.exe file2.dll file3.bin
  python batch_analyzer.py -d /path/to/files -e .exe,.dll,.bin
  python batch_analyzer.py -d /path/to/files -m 6 --methods ascii,regex
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--directory', help='Directory to analyze')
    group.add_argument('-f', '--files', nargs='+', help='Specific files to analyze')
    
    parser.add_argument('-e', '--extensions', default='.exe,.dll,.bin,.dat,.sys,.drv',
                       help='File extensions to analyze (comma-separated)')
    parser.add_argument('-m', '--min-length', type=int, default=4,
                       help='Minimum string length (default: 4)')
    parser.add_argument('--methods', default='ascii,unicode,wide,regex',
                       help='Extraction methods to use (comma-separated)')
    parser.add_argument('-o', '--output', help='Output JSON file for results')
    
    args = parser.parse_args()
    
    # Parse methods and extensions
    methods = [m.strip() for m in args.methods.split(',')]
    extensions = [e.strip() for e in args.extensions.split(',')]
    
    print("🔍 Batch String Analyzer - Security Analysis Tool")
    print("=" * 60)
    print(f"Min Length: {args.min_length}")
    print(f"Methods: {', '.join(methods)}")
    print(f"Extensions: {', '.join(extensions)}")
    print()
    
    # Initialize analyzer
    analyzer = BatchAnalyzer(min_length=args.min_length, methods=methods)
    
    try:
        if args.directory:
            # Analyze directory
            analyzer.analyze_directory(args.directory, extensions)
        else:
            # Analyze specific files
            analyzer.analyze_file_list(args.files)
        
        # Save results
        if args.output or analyzer.results:
            analyzer.save_results(args.output)
        
        print("\n✅ Batch analysis completed successfully!")
        
    except KeyboardInterrupt:
        print("\n⚠️ Analysis interrupted by user")
        if analyzer.results:
            analyzer.save_results("interrupted_analysis.json")
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
