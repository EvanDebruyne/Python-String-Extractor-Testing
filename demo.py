#!/usr/bin/env python3
"""
Demo script showing how to use String Extractor programmatically.
This demonstrates the API usage for integration into other tools.
"""

from string_extractor import StringExtractor
import os


def demo_programmatic_usage():
    """Demonstrate programmatic usage of String Extractor."""
    
    print("🚀 String Extractor - Programmatic Usage Demo")
    print("=" * 50)
    
    # Example 1: Basic usage
    print("\n1️⃣ Basic String Extraction")
    print("-" * 30)
    
    # Create a simple test file
    test_content = b"Hello World\x00This is a test\x00https://example.com\x00admin\x00"
    with open("demo_test.bin", "wb") as f:
        f.write(test_content)
    
    # Initialize extractor
    extractor = StringExtractor(min_length=4)
    
    # Extract strings
    results = extractor.extract_strings("demo_test.bin")
    
    print(f"ASCII strings: {len(results.get('ascii', []))}")
    print(f"Unicode strings: {len(results.get('unicode', []))}")
    print(f"Wide strings: {len(results.get('wide', []))}")
    print(f"Regex strings: {len(results.get('regex', []))}")
    
    # Example 2: Custom analysis
    print("\n2️⃣ Custom String Analysis")
    print("-" * 30)
    
    # Combine all strings
    all_strings = []
    for method, strings in results.items():
        all_strings.extend(strings)
    
    all_strings = list(set(all_strings))  # Remove duplicates
    
    # Analyze strings
    analysis = extractor.analyze_strings(all_strings)
    
    print(f"Total strings: {analysis['total_strings']}")
    print(f"Average length: {analysis['avg_length']:.2f}")
    print(f"URLs found: {len(analysis['urls'])}")
    print(f"Suspicious keywords: {len(analysis['suspicious_keywords'])}")
    
    # Example 3: Filtering and processing
    print("\n3️⃣ String Filtering and Processing")
    print("-" * 30)
    
    # Filter strings by length
    long_strings = [s for s in all_strings if len(s) > 10]
    short_strings = [s for s in all_strings if len(s) <= 10]
    
    print(f"Long strings (>10 chars): {len(long_strings)}")
    print(f"Short strings (≤10 chars): {len(short_strings)}")
    
    # Filter by suspicious patterns
    suspicious_strings = analysis['suspicious_keywords']
    if suspicious_strings:
        print(f"Suspicious strings found:")
        for s in suspicious_strings:
            print(f"  - {s}")
    
    # Example 4: Save results
    print("\n4️⃣ Saving Results")
    print("-" * 30)
    
    # Set the extracted strings and analysis results
    extractor.extracted_strings = all_strings
    extractor.analysis_results = analysis
    
    # Save to JSON
    extractor.save_results("demo_test.bin", "demo_results.json")
    
    # Save strings to text file
    with open("demo_strings.txt", "w", encoding="utf-8") as f:
        for string in all_strings:
            f.write(f"{string}\n")
    
    print("Results saved to demo_results.json")
    print("Strings saved to demo_strings.txt")
    
    # Example 5: Batch processing
    print("\n5️⃣ Batch Processing Example")
    print("-" * 30)
    
    # Create multiple test files
    test_files = [
        ("test1.bin", b"File one\x00https://site1.com\x00user1\x00"),
        ("test2.bin", b"File two\x00https://site2.com\x00user2\x00"),
        ("test3.bin", b"File three\x00https://site3.com\x00user3\x00")
    ]
    
    for filename, content in test_files:
        with open(filename, "wb") as f:
            f.write(content)
    
    # Process all files
    batch_results = {}
    for filename, _ in test_files:
        try:
            results = extractor.extract_strings(filename)
            all_strings = []
            for method, strings in results.items():
                all_strings.extend(strings)
            all_strings = list(set(all_strings))
            
            analysis = extractor.analyze_strings(all_strings)
            batch_results[filename] = {
                'strings': all_strings,
                'analysis': analysis
            }
            
            print(f"Processed {filename}: {len(all_strings)} strings")
            
        except Exception as e:
            print(f"Error processing {filename}: {e}")
    
    # Example 6: Integration example
    print("\n6️⃣ Integration Example")
    print("-" * 30)
    
    class SecurityAnalyzer:
        """Example class showing how to integrate String Extractor."""
        
        def __init__(self):
            self.string_extractor = StringExtractor(min_length=4)
        
        def analyze_file_security(self, file_path):
            """Analyze a file for security indicators."""
            try:
                # Extract strings
                results = self.string_extractor.extract_strings(file_path)
                
                # Combine all strings
                all_strings = []
                for method, strings in results.items():
                    all_strings.extend(strings)
                all_strings = list(set(all_strings))
                
                # Analyze for security patterns
                analysis = self.string_extractor.analyze_strings(all_strings)
                
                # Calculate risk score
                risk_score = 0
                if analysis['urls']:
                    risk_score += 10
                if analysis['suspicious_keywords']:
                    risk_score += 20
                if analysis['ip_addresses']:
                    risk_score += 15
                if analysis['registry_keys']:
                    risk_score += 5
                
                return {
                    'file_path': file_path,
                    'risk_score': risk_score,
                    'indicators': analysis,
                    'total_strings': len(all_strings)
                }
                
            except Exception as e:
                return {'error': str(e)}
    
    # Use the integration example
    analyzer = SecurityAnalyzer()
    security_report = analyzer.analyze_file_security("demo_test.bin")
    
    print(f"Security analysis for demo_test.bin:")
    print(f"  Risk Score: {security_report['risk_score']}/50")
    print(f"  Total Strings: {security_report['total_strings']}")
    print(f"  URLs Found: {len(security_report['indicators']['urls'])}")
    
    # Cleanup
    print("\n🧹 Cleaning up demo files...")
    demo_files = [
        "demo_test.bin", "demo_results.json", "demo_strings.txt",
        "test1.bin", "test2.bin", "test3.bin"
    ]
    
    for filename in demo_files:
        try:
            if os.path.exists(filename):
                os.unlink(filename)
                print(f"  Deleted: {filename}")
        except:
            pass
    
    print("\n✅ Demo completed successfully!")
    print("\n💡 This demonstrates how to integrate String Extractor into:")
    print("   - Security analysis tools")
    print("   - Incident response workflows")
    print("   - Malware analysis pipelines")
    print("   - Digital forensics tools")


if __name__ == "__main__":
    demo_programmatic_usage()
