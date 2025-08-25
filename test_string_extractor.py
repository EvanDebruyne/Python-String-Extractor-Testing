#!/usr/bin/env python3
"""
Test script for String Extractor
Creates a sample binary file and demonstrates the tool's capabilities.
"""

import os
import tempfile
from string_extractor import StringExtractor


def create_test_binary():
    """Create a test binary file with embedded strings for testing."""
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        # Add some binary data
        f.write(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F')
        
        # Add some ASCII strings
        f.write(b'Hello World\x00')
        f.write(b'This is a test file\x00')
        f.write(b'https://example.com/api\x00')
        f.write(b'admin\x00')
        f.write(b'password123\x00')
        f.write(b'192.168.1.100\x00')
        f.write(b'C:\\Windows\\System32\\kernel32.dll\x00')
        f.write(b'HKEY_LOCAL_MACHINE\\SOFTWARE\\Test\x00')
        f.write(b'CreateProcess\x00')
        f.write(b'VirtualAlloc\x00')
        f.write(b'user@example.com\x00')
        f.write(b'/usr/bin/bash\x00')
        
        # Add some wide strings (UTF-16)
        wide_strings = [
            b'W\x00i\x00d\x00e\x00 \x00S\x00t\x00r\x00i\x00n\x00g\x00\x00\x00',
            b'T\x00e\x00s\x00t\x00 \x00W\x00i\x00d\x00e\x00\x00\x00'
        ]
        for wide_string in wide_strings:
            f.write(wide_string)
        
        # Add some binary data at the end
        f.write(b'\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5\xF4\xF3\xF2\xF1\xF0')
        
        test_file = f.name
    
    return test_file


def test_string_extractor():
    """Test the String Extractor with the created test file."""
    
    print("🧪 Testing String Extractor Tool")
    print("=" * 40)
    
    # Create test file
    print("Creating test binary file...")
    test_file = create_test_binary()
    print(f"Test file created: {test_file}")
    
    try:
        # Initialize extractor
        extractor = StringExtractor(min_length=4)
        
        # Test all extraction methods
        print("\nTesting all extraction methods...")
        results = extractor.extract_strings(test_file, ['ascii', 'unicode', 'wide', 'regex'])
        
        # Combine results
        all_strings = []
        for method, strings in results.items():
            print(f"{method.upper()}: {len(strings)} strings")
            all_strings.extend(strings)
        
        # Remove duplicates and sort
        all_strings = sorted(list(set(all_strings)), key=len, reverse=True)
        extractor.extracted_strings = all_strings
        
        print(f"\nTotal unique strings: {len(all_strings)}")
        
        # Analyze strings
        print("Analyzing strings for security patterns...")
        extractor.analysis_results = extractor.analyze_strings(all_strings)
        
        # Print summary
        extractor.print_summary(test_file)
        
        # Test saving results
        print("Testing result saving...")
        extractor.save_results(test_file, "test_results.json")
        
        # Test saving strings only
        print("Testing string-only saving...")
        strings_file = f"{os.path.splitext(test_file)[0]}_strings_only.txt"
        try:
            with open(strings_file, 'w', encoding='utf-8') as f:
                for string in all_strings:
                    f.write(string + '\n')
            print(f"Strings saved to: {strings_file}")
        except Exception as e:
            print(f"Error saving strings: {e}")
        
        print("\n✅ All tests completed successfully!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        
    finally:
        # Clean up test files
        try:
            os.unlink(test_file)
            print(f"Cleaned up test file: {test_file}")
        except:
            pass


if __name__ == "__main__":
    test_string_extractor()
