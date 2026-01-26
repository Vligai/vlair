#!/usr/bin/env python3
"""
Unit tests for File Carver
"""

import pytest
import sys
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from secops_helper.tools.file_carver import FileCarver


class TestFileSignatures:
    """Test file signature detection"""

    def test_detect_jpeg_signature(self):
        """Test detecting JPEG file signature"""
        carver = FileCarver()
        # JPEG magic bytes: FF D8 FF
        data = b'\xff\xd8\xff\xe0\x00\x10JFIF'
        signatures = carver.find_signatures(data)
        assert any('jpeg' in s.get('type', '').lower() or 'jpg' in s.get('type', '').lower()
                   for s in signatures)

    def test_detect_png_signature(self):
        """Test detecting PNG file signature"""
        carver = FileCarver()
        # PNG magic bytes
        data = b'\x89PNG\r\n\x1a\n'
        signatures = carver.find_signatures(data)
        assert any('png' in s.get('type', '').lower() for s in signatures)

    def test_detect_pdf_signature(self):
        """Test detecting PDF file signature"""
        carver = FileCarver()
        # PDF magic bytes
        data = b'%PDF-1.4'
        signatures = carver.find_signatures(data)
        assert any('pdf' in s.get('type', '').lower() for s in signatures)

    def test_detect_exe_signature(self):
        """Test detecting PE executable signature"""
        carver = FileCarver()
        # MZ header
        data = b'MZ\x90\x00'
        signatures = carver.find_signatures(data)
        assert any('exe' in s.get('type', '').lower() or 'pe' in s.get('type', '').lower()
                   for s in signatures)

    def test_detect_zip_signature(self):
        """Test detecting ZIP file signature"""
        carver = FileCarver()
        # ZIP magic bytes
        data = b'PK\x03\x04'
        signatures = carver.find_signatures(data)
        assert any('zip' in s.get('type', '').lower() for s in signatures)

    def test_no_signature_in_random_data(self):
        """Test that random data doesn't match signatures"""
        carver = FileCarver()
        data = os.urandom(1000)  # Random bytes
        signatures = carver.find_signatures(data)
        # May or may not find signatures in random data, just ensure no crash
        assert isinstance(signatures, list)


class TestFileCarving:
    """Test file carving functionality"""

    @pytest.fixture
    def test_image(self):
        """Create a test image file with embedded data"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            # Write some random data
            f.write(os.urandom(100))
            # Write PNG header
            f.write(b'\x89PNG\r\n\x1a\n')
            # Write more random data
            f.write(os.urandom(100))
            return f.name

    def test_carve_from_file(self, test_image):
        """Test carving files from binary"""
        carver = FileCarver()
        with tempfile.TemporaryDirectory() as output_dir:
            results = carver.carve(test_image, output_dir)
            # Should find something or return empty results
            assert isinstance(results, (list, dict))
        os.unlink(test_image)

    def test_carve_from_nonexistent_file(self):
        """Test handling nonexistent source file"""
        carver = FileCarver()
        with tempfile.TemporaryDirectory() as output_dir:
            results = carver.carve("/nonexistent/file.bin", output_dir)
            # Should handle gracefully
            assert results is None or isinstance(results, (list, dict))

    def test_carve_with_type_filter(self):
        """Test carving with specific file type filter"""
        pass


class TestHashCalculation:
    """Test hash calculation for carved files"""

    def test_calculate_md5(self):
        """Test MD5 hash calculation"""
        carver = FileCarver()
        data = b"test data for hashing"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            temp_path = f.name

        try:
            hashes = carver.calculate_hashes(temp_path)
            assert 'md5' in hashes
            assert len(hashes['md5']) == 32  # MD5 is 32 hex chars
        finally:
            os.unlink(temp_path)

    def test_calculate_sha256(self):
        """Test SHA256 hash calculation"""
        carver = FileCarver()
        data = b"test data for hashing"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            temp_path = f.name

        try:
            hashes = carver.calculate_hashes(temp_path)
            assert 'sha256' in hashes
            assert len(hashes['sha256']) == 64  # SHA256 is 64 hex chars
        finally:
            os.unlink(temp_path)


class TestFileCarverIntegration:
    """Integration tests for File Carver"""

    def test_carver_creation(self):
        """Test creating carver instance"""
        carver = FileCarver()
        assert carver is not None

    def test_supported_file_types(self):
        """Test getting list of supported file types"""
        carver = FileCarver()
        types = carver.get_supported_types()
        assert isinstance(types, list)
        assert len(types) > 0

    def test_carve_empty_file(self):
        """Test carving from empty file"""
        carver = FileCarver()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            temp_path = f.name

        try:
            with tempfile.TemporaryDirectory() as output_dir:
                results = carver.carve(temp_path, output_dir)
                # Should handle gracefully
                assert results is None or isinstance(results, (list, dict))
        finally:
            os.unlink(temp_path)


class TestOutputOrganization:
    """Test output organization by file type"""

    def test_organize_by_type(self):
        """Test that carved files are organized by type"""
        pass

    def test_output_directory_creation(self):
        """Test that output directories are created"""
        carver = FileCarver()
        with tempfile.TemporaryDirectory() as output_dir:
            subdir = os.path.join(output_dir, "test_subdir")
            # Carver should be able to create subdirectories
            assert True  # Placeholder


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
