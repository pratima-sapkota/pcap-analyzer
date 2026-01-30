# pcap-inspector

Automatic pcap/pcapng file analyzer designed for CTF (Capture The Flag) challenges. This tool automates the process of extracting and detecting flags from network traffic captures.

## Features

- **Flag Detection**: Automatically searches for common CTF flag patterns (`flag{...}`, `CTF{...}`, `picoCTF{...}`)
- **Multi-Encoding Support**: Detects flags encoded in:
  - Plain text (UTF-8)
  - Base64
  - ROT13
  - Hexadecimal
  - GZIP compressed data
- **TCP Stream Reassembly**: Reconstructs TCP sessions to find flags split across multiple packets
- **TLS Decryption**: Decrypt HTTPS traffic when provided with the server's private key
- **File Extraction**: Automatically extracts files from HTTP responses
- **Protocol Analysis**: Provides layer-by-layer breakdown of captured traffic

## Installation

### Prerequisites

- Python 3.10 or higher
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

```bash
# Clone the repository
git clone https://github.com/pratima-sapkota/pcap-inspector.git
cd pcap-inspector

# Install dependencies (creates venv automatically)
uv sync
```

## Usage

### Analyzing Any Pcap File

You can analyze pcap files from **anywhere on your filesystem**:

```bash
# Analyze a file with absolute path
uv run pcap-inspector /path/to/your/capture.pcap

# Analyze a file with relative path
uv run pcap-inspector ./downloads/network_dump.pcapng

# Analyze a file in the data directory
uv run pcap-inspector data/trace.pcap
```

### Using Custom Flag Patterns

Search for custom patterns using the `-p` flag (supports regex):

```bash
# Single custom pattern
uv run pcap-inspector capture.pcap -p "secret{.*?}"

# Multiple patterns
uv run pcap-inspector capture.pcap -p "KEY_[A-Z0-9]+" -p "token:[a-f0-9]{32}"
```

### TLS Decryption

For encrypted HTTPS traffic, place the RSA private key alongside the pcap file:

```bash
# Auto-detects matching key file (webnet0.pcap → webnet0.key)
uv run pcap-inspector data/webnet0.pcap

# Files must be named: <name>.pcap and <name>.key in the same directory
```

### Alternative: Run as Python Module

```bash
uv run python -m pcap_inspector.cli path/to/capture.pcap
```

### Example Output

```
Analyzing data/trace.pcap...
{
    "layers": {
        "Ethernet": 150,
        "IP": 150,
        "TCP": 140,
        "UDP": 10,
        "Raw": 120
    },
    "flags": [...],
    "stream_flags": [...],
    "extracted_files": [...]
}

[+] Possible Flags Found (Single Packet):
  Packet 42: flag{example_flag} (Encoding: plain)

[+] Possible Flags Found (reassembled streams):
  Stream TCP 192.168.1.1:443 > 192.168.1.2:54321: flag{stream_flag} (Encoding: gzip)

[+] Extracted Files:
  flag.png (Size: 1234 bytes) -> extracted_files/flag.png
```

## Data File Organization

Place your pcap files in the `data/` directory for easy access:

```
pcap-inspector/
├── data/
│   ├── capture.pcap          # Your pcap files
│   ├── capture.pcapng        # Also supports pcapng format
│   ├── webnet0.pcap          # Encrypted traffic
│   ├── webnet0.key           # Matching RSA key for decryption
│   └── ...
├── extracted_files/          # Auto-created for extracted files
├── src/
│   └── pcap_inspector/
└── tests/
```

### Supported File Formats

| Format   | Extension  | Description |
|----------|------------|-------------|
| PCAP     | `.pcap`    | Standard tcpdump capture format |
| PCAPNG   | `.pcapng`  | Next-generation pcap format |
| Key File | `.key`     | PEM-encoded RSA private key for TLS decryption |

## Running Tests

The test suite includes sample pcap generators and scanners:

```bash
# Run all tests
uv run pytest tests/

# Run the sample scanner (scans all files in data/)
uv run python tests/test_samples.py
```

The sample scanner will:
1. Generate synthetic test pcap files
2. Scan all `.pcap` and `.pcapng` files in `data/`
3. Report any flags found
4. Clean up generated test files

## Project Structure

```
pcap-inspector/
├── src/pcap_inspector/
│   ├── __init__.py
│   ├── cli.py              # Command line interface
│   ├── pcap_stats.py       # Main analyzer class (PcapInspector)
│   ├── stream_reassembly.py # TCP stream reconstruction (StreamAnalyzer)
│   ├── file_extractor.py   # HTTP file extraction (FileExtractor)
│   └── decode_pkts.py      # Encoding/decoding utilities
├── tests/
│   ├── generate_samples.py # Test pcap generators
│   ├── test_samples.py     # Sample file scanner
│   ├── test_phase1.py      # Basic functionality tests
│   ├── test_phase2.py      # Stream reassembly tests
│   └── test_phase3.py      # File extraction tests
├── data/                   # Place your pcap files here
├── extracted_files/        # Extracted files output directory
├── pyproject.toml          # Project configuration
└── README.md               # This file
```

## API Usage

You can also use pcap-inspector as a library:

```python
from pcap_inspector.pcap_stats import PcapInspector

# Basic analysis
analyzer = PcapInspector("capture.pcap")
stats = analyzer.read_stats()

# With TLS decryption
analyzer = PcapInspector("encrypted.pcap", key_file="server.key")
stats = analyzer.read_stats()

# Access results
print("Protocol layers:", stats['layers'])
print("Flags found:", stats['flags'])
print("Stream flags:", stats['stream_flags'])
print("Extracted files:", stats['extracted_files'])
```

## Dependencies

- [Scapy](https://scapy.net/) >= 2.6.1 - Packet manipulation library

## Capabilities & Limitations

### Supported Encodings for Flag Detection

| Encoding | Description |
|----------|-------------|
| Plain text | UTF-8 decoded payloads |
| Base64 | Standard base64 encoded flags |
| ROT13 | Caesar cipher with 13 shift |
| Hexadecimal | Hex-encoded strings |
| GZIP | Compressed stream data |

### Supported Flag Patterns

```regex
flag{...}, CTF{...}, picoCTF{...}
```

### Known Limitations

| Limitation | Impact |
|------------|--------|
| **TLS Key Exchange** | Only RSA key decryption supported; **Diffie-Hellman/ECDHE not supported** |
| **Steganography** | Cannot detect flags hidden in images/files |
| **Custom Encodings** | No support for XOR ciphers, custom base variants, or multi-layer encoding |
| **Non-TCP Protocols** | UDP stream reassembly not implemented |
| **Fragmented Files** | File carving from fragmented data not supported |
| **DNS Exfiltration** | No DNS payload analysis for subdomain-encoded flags |
| **Obfuscated Strings** | Flags with whitespace, newlines, or split strings may be missed |

## Tested picoCTF Problems

The following picoCTF challenges have been tested with this tool:

| Problem | Status | Notes |
|---------|--------|-------|
| **WebNet0** | ✅ Works | Simple TLS decryption with provided RSA key |
| **WebNet1** | ✅ Works | TLS decryption with key, flag in decrypted HTTPS content |
| **Wireshark doo dooo do doo....** | ✅ Works | Plain text flag visible in HTTP traffic |
| **PcapPoisoning** | ✅ Works | Flag in raw packet payloads, detectable via plain/stream search |
| **Wireshark twoo twooo two twoo** | ⚠️ Partial | Tool finds possible flag patterns; requires slight manual decoding to get accurate flag |

## License

This project is open source. See the repository for license details.
