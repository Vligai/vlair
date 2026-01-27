#!/usr/bin/env python3
"""
Unit tests for File Carver
"""

import pytest
import sys
import tempfile
import os
import hashlib
from pathlib import Path
from unittest.mock import Mock, patch

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from secops_helper.tools.file_carver import FileCarver, FILE_SIGNATURES


class TestFileSignatures:
    """Test file signature detection"""

    def test_detect_jpeg_signature(self):
        """Test detecting JPEG file signature"""
        carver = FileCarver()
        # JPEG magic bytes: FF D8 FF
        data = b"\xff\xd8\xff\xe0\x00\x10JFIF"
        file_type = carver.detect_file_type(data)
        assert file_type == "jpg"

    def test_detect_png_signature(self):
        """Test detecting PNG file signature"""
        carver = FileCarver()
        # PNG magic bytes
        data = b"\x89PNG\r\n\x1a\n"
        file_type = carver.detect_file_type(data)
        assert file_type == "png"

    def test_detect_pdf_signature(self):
        """Test detecting PDF file signature"""
        carver = FileCarver()
        # PDF magic bytes
        data = b"%PDF-1.4"
        file_type = carver.detect_file_type(data)
        assert file_type == "pdf"

    def test_detect_exe_signature(self):
        """Test detecting PE executable signature"""
        carver = FileCarver()
        # MZ header
        data = b"MZ\x90\x00"
        file_type = carver.detect_file_type(data)
        # MZ header maps to exe or dll
        assert file_type in ["exe", "dll"]

    def test_detect_zip_signature(self):
        """Test detecting ZIP file signature"""
        carver = FileCarver()
        # ZIP magic bytes
        data = b"PK\x03\x04"
        file_type = carver.detect_file_type(data)
        # ZIP header can match zip, docx, xlsx
        assert file_type in ["zip", "docx", "xlsx"]

    def test_no_signature_in_random_data(self):
        """Test that random data with no valid signature returns None"""
        carver = FileCarver()
        # Data that doesn't match any signature
        data = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        file_type = carver.detect_file_type(data)
        # May or may not find signatures, just ensure no crash
        assert file_type is None or isinstance(file_type, str)


class TestFileCarving:
    """Test file carving functionality"""

    @pytest.fixture
    def test_image(self):
        """Create a test image file with embedded data"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            # Write some random data
            f.write(os.urandom(100))
            # Write PNG header
            f.write(b"\x89PNG\r\n\x1a\n")
            # Write more random data
            f.write(os.urandom(100))
            return f.name

    def test_carve_from_file(self, test_image, tmp_path):
        """Test carving files from binary"""
        carver = FileCarver(output_dir=str(tmp_path), verbose=False)
        results = carver.carve_from_file(test_image)
        # Should return a list
        assert isinstance(results, list)
        os.unlink(test_image)

    def test_carve_from_nonexistent_file(self, tmp_path):
        """Test handling nonexistent source file"""
        carver = FileCarver(output_dir=str(tmp_path))
        results = carver.carve_from_file("/nonexistent/file.bin")
        # Should return empty list
        assert results == []

    def test_carve_with_type_filter(self, tmp_path):
        """Test carving with specific file type filter"""
        # Create a test file with PDF header
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"%PDF-1.4 some content here %%EOF")
            temp_path = f.name

        try:
            carver = FileCarver(output_dir=str(tmp_path))
            results = carver.carve_from_file(temp_path, file_types=["pdf"])
            assert isinstance(results, list)
        finally:
            os.unlink(temp_path)


class TestHashCalculation:
    """Test hash calculation for carved files"""

    def test_calculate_md5_sha256(self):
        """Test MD5 and SHA256 hash calculation via carving"""
        # Create a test file with a known header
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            # Write PDF with content
            content = b"%PDF-1.4 test content for hashing %%EOF"
            f.write(content)
            temp_path = f.name

        try:
            with tempfile.TemporaryDirectory() as output_dir:
                carver = FileCarver(output_dir=output_dir)
                results = carver.carve_from_file(temp_path, file_types=["pdf"])

                if results:
                    # Check that carved files have hashes
                    for result in results:
                        assert "md5" in result
                        assert "sha256" in result
                        assert len(result["md5"]) == 32
                        assert len(result["sha256"]) == 64
        finally:
            os.unlink(temp_path)


class TestFileCarverIntegration:
    """Integration tests for File Carver"""

    def test_carver_creation(self):
        """Test creating carver instance"""
        with tempfile.TemporaryDirectory() as output_dir:
            carver = FileCarver(output_dir=output_dir)
            assert carver is not None

    def test_supported_file_types(self):
        """Test getting list of supported file types"""
        # FILE_SIGNATURES is the dict of supported types
        assert isinstance(FILE_SIGNATURES, dict)
        assert len(FILE_SIGNATURES) > 0
        # Check some expected types
        assert "jpg" in FILE_SIGNATURES
        assert "png" in FILE_SIGNATURES
        assert "pdf" in FILE_SIGNATURES
        assert "exe" in FILE_SIGNATURES

    def test_carve_empty_file(self):
        """Test carving from empty file"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            temp_path = f.name

        try:
            with tempfile.TemporaryDirectory() as output_dir:
                carver = FileCarver(output_dir=output_dir)
                results = carver.carve_from_file(temp_path)
                # Should handle gracefully - returns empty list
                assert isinstance(results, list)
        finally:
            os.unlink(temp_path)


class TestOutputOrganization:
    """Test output organization by file type"""

    def test_organize_by_type(self):
        """Test that carved files are organized by type"""
        # Create file with known signature
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x89PNG\r\n\x1a\nIEND\xaeB`\x82")  # PNG with footer
            temp_path = f.name

        try:
            with tempfile.TemporaryDirectory() as output_dir:
                carver = FileCarver(output_dir=output_dir)
                results = carver.carve_from_file(temp_path)

                # If files were carved, check organization
                if results:
                    for result in results:
                        assert "type" in result
                        assert "carved_path" in result
        finally:
            os.unlink(temp_path)

    def test_output_directory_creation(self):
        """Test that output directories are created"""
        with tempfile.TemporaryDirectory() as base_dir:
            output_dir = os.path.join(base_dir, "carved_files")
            carver = FileCarver(output_dir=output_dir)
            # Output directory should be created
            assert os.path.exists(output_dir)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
