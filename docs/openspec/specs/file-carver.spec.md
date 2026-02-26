# File Carver - Feature Specification

## Overview

**Feature Name:** File Carver
**Module:** fileCarver
**Status:** Planned
**Version:** 1.0.0
**Priority:** Medium
**Target Release:** Phase 4

## Purpose

Extract embedded files and artifacts from disk images, memory dumps, network captures, and binary files using file signature (magic bytes) detection. Helps recover deleted files, extract malware payloads, and analyze forensic images.

## Functional Requirements

### FR-1: File Signature Detection
- Detect files by magic bytes/signatures
- Support 100+ file types:
  - Images: JPEG, PNG, GIF, BMP, TIFF
  - Documents: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX
  - Archives: ZIP, RAR, 7Z, TAR, GZ
  - Executables: EXE, DLL, ELF, Mach-O
  - Scripts: PS1, JS, VBS, BAT, SH
  - Media: MP3, MP4, AVI, MKV
  - Email: EML, MSG, PST
  - Other: XML, JSON, SQLite, etc.

### FR-2: Data Source Support
- Raw disk images (dd, E01)
- Memory dumps (RAM dumps)
- PCAP files (extract HTTP payloads)
- Binary files
- Unallocated space
- Slack space

### FR-3: File Extraction
- Extract complete files
- Validate file integrity
- Calculate hashes (MD5, SHA1, SHA256)
- Preserve metadata
- Handle fragmented files

### FR-4: Carving Modes
- Quick scan (headers only)
- Deep scan (entire image)
- Smart carving (use file structure)
- Fragment carving (partial files)

### FR-5: Output Organization
- Organize by file type
- Unique naming (hash-based)
- Preserve directory structure (optional)
- Generate file inventory
- Export metadata

### FR-6: Filtering
- Filter by file type
- Filter by size range
- Filter by date/time (if available)
- Exclude known-good files

### FR-7: Hash Analysis
- Auto-hash all carved files
- Query VirusTotal for carved files
- Identify known malware
- Whitelist known-good hashes

### FR-8: Metadata Extraction
- EXIF data (images)
- Document properties
- PE headers (executables)
- File timestamps
- Embedded strings

### FR-9: Output Formats
- File inventory (JSON, CSV)
- Forensic timeline
- HTML report with previews
- Directory tree

### FR-10: Performance
- Multi-threaded carving
- Progress reporting
- Resume support
- Memory-efficient streaming

## Command-Line Interface

```bash
# Carve from disk image
python carver.py --image disk.dd --output /carved/

# Carve specific file types
python carver.py --image disk.dd --types exe,dll,pdf

# Deep scan mode
python carver.py --image disk.dd --mode deep

# Carve from memory dump
python carver.py --image memdump.raw --types exe,dll --hash-lookup

# Generate report
python carver.py --image disk.dd --report html --output report.html

# Unified CLI
vlair carve --image disk.dd --output /carved/
vlair carve --image memdump.raw --types exe,dll
```

## File Signatures Database

```python
SIGNATURES = {
    'jpg': {
        'header': b'\xFF\xD8\xFF',
        'footer': b'\xFF\xD9',
        'extension': 'jpg',
        'mime': 'image/jpeg'
    },
    'pdf': {
        'header': b'%PDF',
        'footer': b'%%EOF',
        'extension': 'pdf',
        'mime': 'application/pdf'
    },
    'exe': {
        'header': b'MZ',
        'extension': 'exe',
        'mime': 'application/x-msdownload'
    },
    # ... 100+ more signatures
}
```

## Dependencies

```
python-magic>=0.4.27              # File type detection
pytsk3>=20230125                  # Sleuth Kit bindings (forensics)
pillow>=10.0.0                    # Image processing
pefile>=2023.2.7                  # PE file parsing
requests>=2.31.0                  # API requests
tqdm>=4.66.0                      # Progress bars
```

## Output Schema

```json
{
  "metadata": {
    "tool": "file_carver",
    "version": "1.0.0",
    "source_image": "disk.dd",
    "carve_date": "2025-11-20T10:00:00Z",
    "files_carved": 156
  },
  "carved_files": [
    {
      "file_id": "file_001",
      "offset": 1024000,
      "size": 204800,
      "type": "image/jpeg",
      "extension": "jpg",
      "hash_md5": "abc123...",
      "hash_sha256": "def456...",
      "carved_path": "/carved/jpg/file_001.jpg",
      "vt_detections": 0,
      "metadata": {
        "exif": {
          "camera": "Canon EOS",
          "date": "2025:11:15 10:30:00"
        }
      }
    }
  ],
  "statistics": {
    "by_type": {
      "image/jpeg": 45,
      "application/pdf": 23,
      "application/x-msdownload": 12
    },
    "total_size": 524288000
  }
}
```

---

**Last Updated:** 2025-11-20
**Status:** Specification Complete - Ready for Implementation
