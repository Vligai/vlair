#!/usr/bin/env python3
"""
File Carver - Extract Files from Disk Images and Memory Dumps

Extract embedded files and artifacts using file signature (magic bytes) detection.
Supports disk images, memory dumps, and binary files.
"""

import sys
import json
import argparse
import hashlib
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

# File signatures database
FILE_SIGNATURES = {
    "jpg": {
        "header": b"\xFF\xD8\xFF",
        "footer": b"\xFF\xD9",
        "extension": "jpg",
        "mime": "image/jpeg",
        "description": "JPEG image",
    },
    "png": {
        "header": b"\x89PNG\r\n\x1a\n",
        "footer": b"IEND\xaeB`\x82",
        "extension": "png",
        "mime": "image/png",
        "description": "PNG image",
    },
    "gif": {"header": b"GIF8", "extension": "gif", "mime": "image/gif", "description": "GIF image"},
    "pdf": {
        "header": b"%PDF",
        "footer": b"%%EOF",
        "extension": "pdf",
        "mime": "application/pdf",
        "description": "PDF document",
    },
    "zip": {
        "header": b"PK\x03\x04",
        "extension": "zip",
        "mime": "application/zip",
        "description": "ZIP archive",
    },
    "rar": {
        "header": b"Rar!\x1a\x07",
        "extension": "rar",
        "mime": "application/x-rar",
        "description": "RAR archive",
    },
    "7z": {
        "header": b"7z\xbc\xaf\x27\x1c",
        "extension": "7z",
        "mime": "application/x-7z-compressed",
        "description": "7-Zip archive",
    },
    "exe": {
        "header": b"MZ",
        "extension": "exe",
        "mime": "application/x-msdownload",
        "description": "Windows executable",
    },
    "dll": {
        "header": b"MZ",
        "extension": "dll",
        "mime": "application/x-msdownload",
        "description": "Windows DLL",
    },
    "doc": {
        "header": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "extension": "doc",
        "mime": "application/msword",
        "description": "Microsoft Word document",
    },
    "docx": {
        "header": b"PK\x03\x04",
        "extension": "docx",
        "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "description": "Microsoft Word document (Office Open XML)",
    },
    "xls": {
        "header": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "extension": "xls",
        "mime": "application/vnd.ms-excel",
        "description": "Microsoft Excel spreadsheet",
    },
    "xlsx": {
        "header": b"PK\x03\x04",
        "extension": "xlsx",
        "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "description": "Microsoft Excel spreadsheet (Office Open XML)",
    },
    "mp3": {
        "header": b"\xff\xfb",
        "extension": "mp3",
        "mime": "audio/mpeg",
        "description": "MP3 audio",
    },
    "mp4": {
        "header": b"\x00\x00\x00\x18ftypmp42",
        "extension": "mp4",
        "mime": "video/mp4",
        "description": "MP4 video",
    },
    "avi": {
        "header": b"RIFF",
        "extension": "avi",
        "mime": "video/x-msvideo",
        "description": "AVI video",
    },
    "xml": {
        "header": b"<?xml",
        "extension": "xml",
        "mime": "application/xml",
        "description": "XML document",
    },
    "html": {
        "header": b"<html",
        "extension": "html",
        "mime": "text/html",
        "description": "HTML document",
    },
    "tar": {
        "header": b"ustar",
        "offset": 257,  # Signature at offset 257
        "extension": "tar",
        "mime": "application/x-tar",
        "description": "TAR archive",
    },
    "gz": {
        "header": b"\x1f\x8b",
        "extension": "gz",
        "mime": "application/gzip",
        "description": "GZIP compressed file",
    },
    "bz2": {
        "header": b"BZ",
        "extension": "bz2",
        "mime": "application/x-bzip2",
        "description": "BZIP2 compressed file",
    },
    "sqlite": {
        "header": b"SQLite format 3\x00",
        "extension": "sqlite",
        "mime": "application/x-sqlite3",
        "description": "SQLite database",
    },
    "eml": {
        "header": b"From:",
        "extension": "eml",
        "mime": "message/rfc822",
        "description": "Email message",
    },
    "ps1": {
        "header": b"#!",
        "extension": "ps1",
        "mime": "text/plain",
        "description": "PowerShell script",
    },
    "bat": {
        "header": b"@echo",
        "extension": "bat",
        "mime": "text/plain",
        "description": "Batch script",
    },
}


class FileCarver:
    """Main file carving engine"""

    def __init__(self, output_dir: str = "./carved", verbose=False, chunk_size: int = 1024 * 1024):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.chunk_size = chunk_size  # Read 1MB at a time
        self.signatures = FILE_SIGNATURES

        self.stats = {
            "files_carved": 0,
            "by_type": defaultdict(int),
            "total_bytes": 0,
            "scan_time": 0,
        }

    def detect_file_type(self, data: bytes, offset: int = 0) -> Optional[str]:
        """Detect file type from header bytes"""
        for file_type, sig in self.signatures.items():
            header = sig["header"]
            sig_offset = sig.get("offset", 0)

            # Check if we have enough data
            if len(data) < len(header) + sig_offset:
                continue

            # Check signature
            if data[sig_offset : sig_offset + len(header)] == header:
                return file_type

        return None

    def find_footer(self, data: bytes, file_type: str, start: int = 0) -> Optional[int]:
        """Find footer signature"""
        sig = self.signatures.get(file_type)
        if not sig or "footer" not in sig:
            return None

        footer = sig["footer"]
        pos = data.find(footer, start)

        if pos != -1:
            return pos + len(footer)

        return None

    def extract_file(self, data: bytes, start: int, end: int, file_type: str, file_id: int) -> Dict:
        """Extract and save a carved file"""
        try:
            # Extract file data
            file_data = data[start:end]

            # Calculate hashes
            md5 = hashlib.md5(file_data).hexdigest()
            sha256 = hashlib.sha256(file_data).hexdigest()

            # Create type-specific subdirectory
            sig = self.signatures[file_type]
            type_dir = self.output_dir / file_type
            type_dir.mkdir(exist_ok=True)

            # Generate filename
            filename = f"file_{file_id:05d}_{sha256[:8]}.{sig['extension']}"
            output_path = type_dir / filename

            # Save file
            with open(output_path, "wb") as f:
                f.write(file_data)

            # Update statistics
            self.stats["files_carved"] += 1
            self.stats["by_type"][file_type] += 1
            self.stats["total_bytes"] += len(file_data)

            if self.verbose:
                print(f"Carved {file_type}: {filename} ({len(file_data)} bytes)", file=sys.stderr)

            return {
                "file_id": file_id,
                "type": file_type,
                "mime_type": sig["mime"],
                "description": sig["description"],
                "offset": start,
                "size": len(file_data),
                "md5": md5,
                "sha256": sha256,
                "carved_path": str(output_path),
                "filename": filename,
            }

        except Exception as e:
            if self.verbose:
                print(f"Error extracting file: {e}", file=sys.stderr)
            return None

    def carve_from_file(self, source_path: str, file_types: List[str] = None) -> List[Dict]:
        """Carve files from a source file/image"""
        source_path = Path(source_path)

        if not source_path.exists():
            print(f"Error: Source file not found: {source_path}", file=sys.stderr)
            return []

        if self.verbose:
            file_size = source_path.stat().st_size
            print(f"Carving from {source_path} ({file_size:,} bytes)...", file=sys.stderr)

        carved_files = []
        file_id = 1

        try:
            with open(source_path, "rb") as f:
                offset = 0

                while True:
                    # Read chunk
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break

                    # Look for file signatures in this chunk
                    for i in range(len(chunk)):
                        file_type = self.detect_file_type(chunk[i:], offset + i)

                        if file_type:
                            # Filter by file types if specified
                            if file_types and file_type not in file_types:
                                continue

                            # Try to find footer
                            sig = self.signatures[file_type]

                            if "footer" in sig:
                                # Read more data to find footer (max 10MB)
                                current_pos = f.tell()
                                f.seek(offset + i)
                                extended_data = f.read(10 * 1024 * 1024)
                                f.seek(current_pos)

                                footer_pos = self.find_footer(extended_data, file_type)

                                if footer_pos:
                                    # Extract complete file
                                    f.seek(offset + i)
                                    file_data = f.read(footer_pos)
                                    f.seek(current_pos)

                                    result = self.extract_file(
                                        file_data, 0, len(file_data), file_type, file_id
                                    )

                                    if result:
                                        result["offset"] = offset + i
                                        carved_files.append(result)
                                        file_id += 1

                            else:
                                # No footer defined, extract fixed size or until next signature
                                # For simplicity, extract next 1MB or until chunk end
                                f.seek(offset + i)
                                file_data = f.read(min(1024 * 1024, len(chunk) - i))
                                current_pos = f.tell()

                                result = self.extract_file(
                                    file_data, 0, len(file_data), file_type, file_id
                                )

                                if result:
                                    result["offset"] = offset + i
                                    carved_files.append(result)
                                    file_id += 1

                                f.seek(current_pos)

                    offset += len(chunk)

                    if self.verbose and offset % (10 * 1024 * 1024) == 0:
                        print(f"Processed {offset:,} bytes...", file=sys.stderr)

        except Exception as e:
            print(f"Error during carving: {e}", file=sys.stderr)

        if self.verbose:
            print(f"\nCarved {len(carved_files)} files", file=sys.stderr)

        return carved_files


def format_output_json(metadata: Dict, carved_files: List[Dict], stats: Dict) -> str:
    """Format output as JSON"""
    output = {"metadata": metadata, "statistics": stats, "carved_files": carved_files}
    return json.dumps(output, indent=2)


def format_output_csv(carved_files: List[Dict]) -> str:
    """Format output as CSV"""
    lines = ["File ID,Type,MIME Type,Offset,Size,MD5,SHA256,Carved Path"]

    for f in carved_files:
        lines.append(
            f'{f["file_id"]},'
            f'{f["type"]},'
            f'{f["mime_type"]},'
            f'{f["offset"]},'
            f'{f["size"]},'
            f'{f["md5"]},'
            f'{f["sha256"]},'
            f'"{f["carved_path"]}"'
        )

    return "\n".join(lines)


def format_output_text(carved_files: List[Dict], stats: Dict) -> str:
    """Format output as human-readable text"""
    lines = []
    lines.append("=" * 80)
    lines.append("File Carving Report")
    lines.append("=" * 80)
    lines.append("")

    # Statistics
    lines.append(f"Files Carved: {stats['files_carved']}")
    lines.append(f"Total Bytes: {stats['total_bytes']:,}")
    lines.append("")

    lines.append("Files by Type:")
    for file_type, count in stats["by_type"].items():
        lines.append(f"  {file_type}: {count}")
    lines.append("")

    # Carved files
    if carved_files:
        lines.append("Carved Files:")
        lines.append("-" * 80)

        for f in carved_files:
            lines.append(f"ID: {f['file_id']}")
            lines.append(f"Type: {f['type']} ({f['description']})")
            lines.append(f"Offset: {f['offset']:,} bytes")
            lines.append(f"Size: {f['size']:,} bytes")
            lines.append(f"MD5: {f['md5']}")
            lines.append(f"SHA256: {f['sha256']}")
            lines.append(f"Saved to: {f['carved_path']}")
            lines.append("-" * 80)

    lines.append("=" * 80)
    return "\n".join(lines)


def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="File Carver - Extract Files from Disk Images and Memory Dumps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Carve all file types from disk image
  python carver.py --image disk.dd --output /carved/

  # Carve specific file types
  python carver.py --image disk.dd --types exe,dll,pdf

  # Carve from memory dump
  python carver.py --image memdump.raw --types exe,dll

  # Generate JSON report
  python carver.py --image disk.dd --format json --output report.json

  # List supported file types
  python carver.py --list-types
        """,
    )

    parser.add_argument("--image", "-i", help="Source file/image to carve from")
    parser.add_argument(
        "--output", "-o", default="./carved", help="Output directory (default: ./carved)"
    )
    parser.add_argument("--types", "-t", help="File types to carve (comma-separated)")
    parser.add_argument(
        "--format", "-f", choices=["json", "csv", "txt"], default="txt", help="Output format"
    )
    parser.add_argument("--report", "-r", help="Report output file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--list-types", action="store_true", help="List supported file types")

    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()

    # List file types
    if args.list_types:
        print("Supported File Types:")
        print("=" * 60)
        for file_type, sig in sorted(FILE_SIGNATURES.items()):
            print(f"{file_type:10s} - {sig['description']}")
        sys.exit(0)

    # Validate arguments
    if not args.image:
        print("Error: No source image specified. Use --help for usage.", file=sys.stderr)
        sys.exit(1)

    # Parse file types
    file_types = None
    if args.types:
        file_types = [t.strip().lower() for t in args.types.split(",")]

        # Validate file types
        invalid = [t for t in file_types if t not in FILE_SIGNATURES]
        if invalid:
            print(f"Error: Unknown file types: {', '.join(invalid)}", file=sys.stderr)
            print("Use --list-types to see supported types", file=sys.stderr)
            sys.exit(1)

    # Initialize carver
    carver = FileCarver(output_dir=args.output, verbose=args.verbose)

    # Carve files
    import time

    start_time = time.time()

    carved_files = carver.carve_from_file(args.image, file_types=file_types)

    carver.stats["scan_time"] = time.time() - start_time

    # Prepare metadata
    metadata = {
        "tool": "file_carver",
        "version": "1.0.0",
        "carve_date": datetime.utcnow().isoformat() + "Z",
        "source_image": args.image,
        "output_directory": args.output,
        "file_types_filter": file_types,
        "scan_time_seconds": round(carver.stats["scan_time"], 2),
    }

    # Format output
    if args.format == "json":
        report = format_output_json(metadata, carved_files, carver.stats)
    elif args.format == "csv":
        report = format_output_csv(carved_files)
    else:  # txt
        report = format_output_text(carved_files, carver.stats)

    # Write report
    if args.report:
        with open(args.report, "w") as f:
            f.write(report)
        print(f"\nReport written to {args.report}", file=sys.stderr)
    else:
        print(report)

    # Summary
    print(f"\nCarving complete! Carved {len(carved_files)} files to {args.output}", file=sys.stderr)
    print(f"Total size: {carver.stats['total_bytes']:,} bytes", file=sys.stderr)
    print(f"Scan time: {carver.stats['scan_time']:.2f} seconds", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
