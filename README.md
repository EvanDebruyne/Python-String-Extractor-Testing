# 🔍 String Extractor - Binary File Analysis Tool

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Cybersecurity-red.svg)](https://github.com/yourusername/string-extractor)

A comprehensive Python tool for extracting and analyzing strings from binary files, designed for malware analysis, digital forensics, and security research.

## 🚀 Features

- **Multiple Extraction Methods**: ASCII, Unicode, Wide (UTF-16), and Regex-based extraction
- **Security Pattern Analysis**: Automatically detects URLs, IP addresses, file paths, registry keys, and suspicious keywords
- **Comprehensive Reporting**: JSON output with detailed analysis and file hashing
- **Flexible Configuration**: Customizable minimum string length and extraction methods
- **Professional CLI Interface**: Clean, informative command-line interface
- **File Integrity**: SHA256 hash calculation for forensic documentation
- **Batch Processing**: Analyze multiple files simultaneously with risk scoring
- **Programmatic API**: Easy integration into other security tools and workflows

## 🎯 Use Cases

- **Malware Analysis**: Extract strings to identify command & control servers, file paths, and suspicious patterns
- **Digital Forensics**: Analyze binary files for evidence and artifacts
- **Security Research**: Study binary files for vulnerabilities and indicators of compromise
- **Reverse Engineering**: Understand binary file contents and functionality
- **Incident Response**: Quick analysis of suspicious files during security incidents
- **Batch Analysis**: Process multiple files for enterprise-wide security assessments

## 📋 Requirements

- Python 3.7+
- No external dependencies (uses only Python standard library)

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/string-extractor.git
cd string-extractor

# No installation required - just run the script
python string_extractor.py --help
```

## 📖 Usage

### Single File Analysis

```bash
# Analyze a binary file with default settings
python string_extractor.py suspicious_file.exe

# Specify minimum string length
python string_extractor.py -m 8 malware.bin

# Use specific extraction methods only
python string_extractor.py --methods ascii,unicode file.exe

# Save results to JSON file
python string_extractor.py -o analysis_results.json malware.exe

# Save extracted strings to separate text file
python string_extractor.py --save-strings suspicious.bin

# Verbose output with method-specific counts
python string_extractor.py -v file.exe
```

### Batch Analysis

```bash
# Analyze all files in a directory
python batch_analyzer.py -d /path/to/suspicious/files

# Analyze specific files
python batch_analyzer.py -f file1.exe file2.dll file3.bin

# Customize file extensions to analyze
python batch_analyzer.py -d /path/to/files -e .exe,.dll,.bin,.dat

# Adjust analysis parameters
python batch_analyzer.py -d /path/to/files -m 6 --methods ascii,regex

# Save batch results to specific file
python batch_analyzer.py -d /path/to/files -o batch_results.json
```

### Command Line Options

#### String Extractor
| Option | Description | Default |
|--------|-------------|---------|
| `file` | Binary file to analyze | Required |
| `-m, --min-length` | Minimum string length | 4 |
| `--methods` | Extraction methods (comma-separated) | ascii,unicode,wide,regex |
| `-o, --output` | Output JSON file | Auto-generated |
| `--save-strings` | Save strings to separate text file | False |
| `-v, --verbose` | Verbose output | False |

#### Batch Analyzer
| Option | Description | Default |
|--------|-------------|---------|
| `-d, --directory` | Directory to analyze | Required (or -f) |
| `-f, --files` | Specific files to analyze | Required (or -d) |
| `-e, --extensions` | File extensions to analyze | .exe,.dll,.bin,.dat,.sys,.drv |
| `-m, --min-length` | Minimum string length | 4 |
| `--methods` | Extraction methods | ascii,unicode,wide,regex |
| `-o, --output` | Output JSON file | Auto-generated |

### Extraction Methods

- **ASCII**: Standard printable ASCII character extraction
- **Unicode**: UTF-8, UTF-16, UTF-32, and Latin-1 encoding support
- **Wide**: UTF-16 wide string detection
- **Regex**: Pattern-based extraction for URLs, emails, IPs, paths, etc.

## 📊 Output Examples

### Single File Analysis
```
🔍 String Extractor - Binary File Analysis Tool
==================================================
Analyzing: suspicious_file.exe
Methods: ascii, unicode, wide, regex
Min Length: 4

Extracting strings...
Analyzing strings for security patterns...

Total unique strings extracted: 1,247

============================================================
STRING EXTRACTION ANALYSIS SUMMARY
============================================================
File: suspicious_file.exe
File Hash: a1b2c3d4e5f6...
Total Strings Extracted: 1,247
Average String Length: 12.34

----------------------------------------
SECURITY ANALYSIS FINDINGS
----------------------------------------
URLs Found: 3
  - https://malicious-domain.com/api
  - http://192.168.1.100:8080
  - ftp://files.example.com

IP Addresses: 2
  - 192.168.1.100
  - 10.0.0.1

File Paths: 15
  - C:\Windows\System32\kernel32.dll
  - C:\Users\Admin\AppData\Local\Temp
  - /usr/bin/bash

Suspicious Keywords: 8
  - admin
  - password
  - shell
  - exec
  - inject
  - hook
  - bypass
  - exploit

✅ Analysis complete!
```

### Batch Analysis
```
🔍 Batch String Analyzer - Security Analysis Tool
============================================================
Min Length: 4
Methods: ascii, unicode, wide, regex
Extensions: .exe, .dll, .bin, .dat, .sys, .drv

Found 5 files to analyze...
============================================================
Analyzing: C:\suspicious\file1.exe
  ✓ Extracted 1,247 strings, Risk Score: 35/50
Analyzing: C:\suspicious\file2.dll
  ✓ Extracted 892 strings, Risk Score: 22/50
Analyzing: C:\suspicious\file3.bin
  ✓ Extracted 567 strings, Risk Score: 18/50

============================================================

============================================================
BATCH ANALYSIS SUMMARY
============================================================
Total Files: 5
Processed: 5
Failed: 0
Total Strings Extracted: 2,706
Analysis Time: 2024-01-15T10:30:45.123456

----------------------------------------
SECURITY FINDINGS ACROSS ALL FILES
----------------------------------------
URLs: 5
  - https://malicious-domain.com/api
  - http://192.168.1.100:8080
  - ftp://files.example.com

IP Addresses: 3
  - 192.168.1.100
  - 10.0.0.1
  - 172.16.0.50

Suspicious Keywords: 12
  - admin
  - password
  - shell
  - exec
  - inject
  - hook
  - bypass
  - exploit
  - malware
  - trojan
  - virus
  - backdoor

----------------------------------------
HIGH RISK FILES
----------------------------------------
File: C:\suspicious\file1.exe
Risk Score: 35/50
Indicators: admin, password, shell, exec, inject

✅ Batch analysis completed successfully!
```

## 🔒 Security Features

### Pattern Detection
- **Network Indicators**: URLs, IP addresses, email addresses
- **System Artifacts**: File paths, registry keys, API calls
- **Suspicious Keywords**: Security-relevant terms and patterns
- **Encoding Analysis**: Multiple character encoding support

### Forensic Capabilities
- **File Integrity**: SHA256 hash calculation
- **Timestamp Recording**: Analysis timestamps for chain of custody
- **Comprehensive Logging**: Detailed extraction and analysis logs
- **Export Formats**: JSON and plain text output options

### Risk Assessment
- **Automated Scoring**: Risk scores based on security indicators
- **High-Risk Identification**: Flag files with suspicious patterns
- **Aggregate Analysis**: Cross-file pattern correlation
- **Enterprise Reporting**: Comprehensive security posture assessment

## 🧪 Testing & Examples

### Test the Tool
```bash
# Run the test suite
python test_string_extractor.py

# Run the demo
python demo.py

# Test batch processing
python batch_analyzer.py -f test_file1.bin test_file2.bin
```

### Programmatic Usage
```python
from string_extractor import StringExtractor

# Initialize extractor
extractor = StringExtractor(min_length=4)

# Extract strings
results = extractor.extract_strings("suspicious_file.exe")

# Analyze for security patterns
analysis = extractor.analyze_strings(all_strings)

# Save results
extractor.save_results("suspicious_file.exe", "results.json")
```

## 📁 Project Structure

```
string-extractor/
├── string_extractor.py      # Main tool - single file analysis
├── batch_analyzer.py        # Batch processing and enterprise analysis
├── test_string_extractor.py # Test suite and validation
├── demo.py                  # Programmatic usage examples
├── requirements.txt         # Python dependencies (none required)
├── README.md               # This file
├── LICENSE                 # MIT License
└── .gitignore             # Git ignore patterns
```

## 🧪 Testing

The tool has been tested with various file types:
- Windows executables (.exe, .dll)
- Linux binaries
- Document files (.pdf, .doc)
- Archive files (.zip, .rar)
- Memory dumps
- Network captures

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/string-extractor.git
cd string-extractor

# Create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Make your changes and test
python string_extractor.py --help
python test_string_extractor.py
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for **educational and legitimate security research purposes only**. Users are responsible for ensuring they have proper authorization to analyze any files. The authors are not responsible for any misuse of this tool.

## 🔗 Related Projects

- [PE File Analyzer](https://github.com/yourusername/pe-analyzer) - Windows executable analysis
- [Network Packet Analyzer](https://github.com/yourusername/packet-analyzer) - Network traffic analysis
- [Malware Sandbox](https://github.com/yourusername/malware-sandbox) - Safe malware analysis environment

## 📞 Contact

- **Author**: [Your Name]
- **Email**: your.email@example.com
- **GitHub**: [@yourusername](https://github.com/yourusername)
- **LinkedIn**: [Your LinkedIn](https://linkedin.com/in/yourprofile)

## 🙏 Acknowledgments

- Inspired by tools like `strings`, `binwalk`, and `pefile`
- Built for the cybersecurity community
- Special thanks to the open-source security tools community

---

**⭐ If you find this tool useful, please give it a star on GitHub!**

*Built with ❤️ for the cybersecurity community*
