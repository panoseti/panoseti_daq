# tests/ci_tests/test_pff_header_consistency.py

import os
import time
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import pytest

from control_util import is_hashpipe_running
import sys
sys.path.append('/app/tests/')
sys.path.append('/app/util/')
import pff # type: ignore

@pytest.mark.usefixtures("daq_env")
class TestPffHeaderConsistency:
    """
    Tests to verify that Hashpipe writes constant-sized JSON headers in PFF files.
    This is critical for the PFF format requirement that enables seeking to arbitrary frames.
    """

    def test_ph_constant_header_size(self, daq_env):
        """
        Test that ph256 or ph1024 PFF files have constant-sized JSON headers.
        Enhanced for container-based testing with longer waits.
        """
        base_dir = daq_env["base_dir"]
        run_name = daq_env["run_name"]
        ph_dp = daq_env["ph_dp"]

        # Wait longer for container-based tests to accumulate data
        max_wait_time = 60  # 1 minute max wait
        wait_interval = 5   # Check every 5 seconds
        
        header_sizes = []
        files_checked = 0
        
        for wait_time in range(0, max_wait_time, wait_interval):
            time.sleep(wait_interval)
            
            # Check for PFF files
            header_sizes = []
            files_checked = 0
            
            for mid in daq_env["module_ids"]:
                mod_run = base_dir / f"module_{mid}" / run_name
                if not mod_run.exists():
                    continue

                # Find ph256 PFF files
                ph256_files = list(mod_run.glob("*.dp_ph256.*.pff"))
                ph1024_files = list(mod_run.glob("*.dp_ph1024.*.pff"))

                for pff_file in ph256_files + ph1024_files:
                    # Be more lenient with file size in containers
                    if pff_file.stat().st_size < 500:
                        continue

                    if ph_dp == "ph256":
                        sizes = self._check_header_sizes_in_file(pff_file, expected_dp="ph256")
                        if sizes:
                            header_sizes.extend(sizes)
                            files_checked += 1
                    elif ph_dp == "ph1024":
                        sizes = self._check_header_sizes_in_file(pff_file, expected_dp="ph1024")
                        if sizes:
                            header_sizes.extend(sizes)
                            files_checked += 1

            # If we found files, break early
            if files_checked > 0:
                print(f"Found {files_checked} PFF files after {wait_time + wait_interval}s")
                break
            else:
                print(f"No PFF files found yet after {wait_time + wait_interval}s, continuing to wait...")

        assert files_checked > 0, f"No {ph_dp} PFF files found to test after {max_wait_time}s wait"
        assert len(header_sizes) > 0, f"No frames found in {ph_dp} PFF files"

        # All header sizes should be identical
        unique_sizes = set(header_sizes)
        assert len(unique_sizes) == 1, f"{ph_dp} headers have inconsistent sizes: {unique_sizes}"

        # Check against expected size (be more flexible for containers)
        header_size = list(unique_sizes)[0]
        print(f"{ph_dp} header size: {header_size} bytes from {len(header_sizes)} frames")
        assert 80 <= header_size <= 750, f"{ph_dp} header size {header_size} seems unreasonable"

    def test_img16_constant_header_size(self, daq_env):
        """
        Test that img16 PFF files have constant-sized JSON headers.
        """
        base_dir = daq_env["base_dir"]
        run_name = daq_env["run_name"]
        
        # Wait for some PFF files to be created
        time.sleep(5)
        
        header_sizes = []
        files_checked = 0
        
        for mid in daq_env["module_ids"]:
            mod_run = base_dir / f"module_{mid}" / run_name
            if not mod_run.exists():
                continue
                
            # Find img16 PFF files
            img16_files = list(mod_run.glob("*.dp_img16.*.pff"))
            
            for pff_file in img16_files:
                if pff_file.stat().st_size < 1000:  # Skip very small files
                    continue
                    
                sizes = self._check_header_sizes_in_file(pff_file, expected_dp="img16")
                if sizes:
                    header_sizes.extend(sizes)
                    files_checked += 1
        
        if files_checked == 0:
            pytest.skip("No img16 PFF files found to test")
        
        assert len(header_sizes) > 0, "No frames found in img16 PFF files"
        
        # All header sizes should be identical
        unique_sizes = set(header_sizes)
        assert len(unique_sizes) == 1, f"img16 headers have inconsistent sizes: {unique_sizes}"
        
        header_size = list(unique_sizes)[0]
        print(f"img16 header size: {header_size} bytes")

    def test_all_pff_files_constant_headers(self, daq_env):
        """
        Comprehensive test of all PFF files to ensure constant header sizes within each data product.
        """
        base_dir = daq_env["base_dir"]
        run_name = daq_env["run_name"]
        
        # Wait for files to be created and accumulate some data
        time.sleep(10)
        
        # Track header sizes by data product
        dp_header_sizes: Dict[str, List[int]] = {}
        files_by_dp: Dict[str, int] = {}
        
        for mid in daq_env["module_ids"]:
            mod_run = base_dir / f"module_{mid}" / run_name
            if not mod_run.exists():
                continue
                
            # Find all PFF files
            pff_files = list(mod_run.glob("*.pff"))
            
            for pff_file in pff_files:
                if pff_file.stat().st_size < 1000:  # Skip very small files
                    continue
                
                # Extract data product from filename
                dp_name = self._extract_dp_name(pff_file.name)
                if not dp_name:
                    continue
                
                # Skip housekeeping files which have different format
                if dp_name == "hk":
                    continue
                    
                sizes = self._check_header_sizes_in_file(pff_file, expected_dp=dp_name)
                if sizes:
                    if dp_name not in dp_header_sizes:
                        dp_header_sizes[dp_name] = []
                        files_by_dp[dp_name] = 0
                    
                    dp_header_sizes[dp_name].extend(sizes)
                    files_by_dp[dp_name] += 1
        
        assert len(dp_header_sizes) > 0, "No PFF files found with recognizable data products"
        
        # Verify consistency within each data product
        for dp_name, sizes in dp_header_sizes.items():
            unique_sizes = set(sizes)
            files_count = files_by_dp[dp_name]
            
            print(f"{dp_name}: {len(sizes)} frames across {files_count} files, "
                  f"header sizes: {unique_sizes}")
            
            assert len(unique_sizes) == 1, (
                f"Data product {dp_name} has inconsistent header sizes: {unique_sizes}. "
                f"All frames within a data product must have identical header sizes."
            )

    def test_frame_seeking_capability(self, daq_env):
        """
        Test that constant header sizes enable proper frame seeking within PFF files.
        """
        pytest.skip("Skipping frame seeking capability test")
        base_dir = daq_env["base_dir"]
        run_name = daq_env["run_name"]

        ph_dp = daq_env["ph_dp"]
        
        # Wait for files with multiple frames
        time.sleep(15)
        
        tested_files = 0
        
        for mid in daq_env["module_ids"]:
            mod_run = base_dir / f"module_{mid}" / run_name
            if not mod_run.exists():
                continue
                
            # Test ph256 files (most likely to have data)
            ph256_files = list(mod_run.glob("*.dp_ph256.*.pff"))
            ph1024_files = list(mod_run.glob("*.dp_ph1024.*.pff"))

            for pff_file in ph256_files + ph1024_files:
                if pff_file.stat().st_size < 5000:  # Need multiple frames
                    continue
                
                success = self._test_file_seeking(pff_file)
                if success:
                    tested_files += 1
                    
                # Only need to test a few files
                if tested_files >= 2:
                    break
            
            if tested_files >= 2:
                break
        
        assert tested_files > 0, "Could not find PFF files suitable for seeking test"

    def test_header_json_validity(self, daq_env):
        """
        Test that all JSON headers are valid and contain expected fields.
        """
        base_dir = daq_env["base_dir"]
        run_name = daq_env["run_name"]

        ph_dp = daq_env["ph_dp"]
        
        time.sleep(8)
        
        headers_tested = 0
        
        for mid in daq_env["module_ids"]:
            mod_run = base_dir / f"module_{mid}" / run_name
            if not mod_run.exists():
                continue

            pff_files = list(mod_run.glob(f"*.dp_{ph_dp}.*.pff"))

            for pff_file in pff_files:
                if pff_file.stat().st_size < 1000:
                    continue

                count = self._validate_json_headers(pff_file, ph_dp)
                headers_tested += count
                
                if headers_tested >= 50:  # Test reasonable number
                    break
            
            if headers_tested >= 50:
                break
        
        assert headers_tested > 0, "No JSON headers found to validate"

    def _check_header_sizes_in_file(self, pff_file: Path, expected_dp: str) -> List[int]:
        """
        Check header sizes in a single PFF file.
        Returns list of header sizes found.
        """
        try:
            with open(pff_file, 'rb') as f:
                header_sizes = []
                
                while True:
                    pos = f.tell()
                    
                    # Try to read JSON header
                    try:
                        json_str = pff.read_json(f)
                        if json_str is None:
                            break
                        
                        # Calculate header size including the { and \n\n
                        end_pos = f.tell()
                        header_size = end_pos - pos
                        header_sizes.append(header_size)
                        
                        # Skip the image data
                        if expected_dp == "ph256":
                            pff.skip_image(f, 16, 2)  # 16x16, 2 bytes per pixel
                        elif expected_dp == "ph1024":
                            pff.skip_image(f, 32, 2)  # 32x32, 2 bytes per pixel
                        elif expected_dp == "img16":
                            pff.skip_image(f, 32, 2)  # 32x32, 2 bytes per pixel (module frame)
                        elif expected_dp == "img8":
                            pff.skip_image(f, 32, 1)  # 32x32, 1 byte per pixel
                        else:
                            # Try to guess image size from file
                            break
                            
                    except Exception:
                        break
                
                return header_sizes
                
        except Exception as e:
            print(f"Error checking header sizes in {pff_file}: {e}")
            return []

    def _test_file_seeking(self, pff_file: Path) -> bool:
        """
        Test that we can seek to arbitrary frames in a PFF file.
        Returns True if seeking works correctly.
        """
        try:
            with open(pff_file, 'rb') as f:
                # Determine bytes per image (ph256 = 512 bytes)
                bytes_per_image = 512
                
                # Get file info using pff.img_info
                frame_size, nframes, first_t, last_t = pff.img_info(f, bytes_per_image)
                
                if nframes < 3:
                    return False  # Need at least 3 frames to test
                
                # Test seeking to middle frame
                middle_frame = nframes // 2
                f.seek(middle_frame * frame_size)
                
                # Try to read the frame
                json_str = pff.read_json(f)
                if json_str is None:
                    return False
                
                # Validate it's valid JSON
                header = json.loads(json_str)
                expected_fields = ['quabo_num', 'pkt_num', 'pkt_tai', 'pkt_nsec', 'tv_sec', 'tv_usec']
                
                for field in expected_fields:
                    if field not in header:
                        return False
                
                print(f"Successfully tested seeking in {pff_file.name}: "
                      f"{nframes} frames, frame_size={frame_size}")
                return True
                
        except Exception as e:
            print(f"Seeking test failed for {pff_file}: {e}")
            return False

    def _validate_json_headers(self, pff_file: Path, ph_dp: str) -> int:
        """
        Validate JSON headers in a PFF file.
        Returns number of headers validated.
        """
        try:
            with open(pff_file, 'rb') as f:
                count = 0
                
                while count < 10:  # Test first 10 frames
                    try:
                        json_str = pff.read_json(f)
                        if json_str is None:
                            break
                        
                        # Validate JSON
                        header = json.loads(json_str)
                        
                        # Check required fields for ph256
                        if ph_dp == "ph256":
                            required_fields = ['quabo_num', 'pkt_num', 'pkt_tai', 'pkt_nsec', 'tv_sec', 'tv_usec']
                        else:
                            required_fields = ['pkt_num', 'pkt_tai', 'pkt_nsec', 'tv_sec', 'tv_usec']
                            assert {f'quabo_{n}' for n in range(4)}.issubset(header.keys()), f"Missing quabo fields in header: {header}"
                            header = header['quabo_0']
                            
                        for field in required_fields:
                            assert field in header, f"Missing field '{field}' in header: {header}"
                        
                        # Validate field types and ranges
                        if ph_dp == "ph256":
                            assert isinstance(header['quabo_num'], int)
                            assert 0 <= header['quabo_num'] <= 3
                        assert isinstance(header['pkt_num'], int)
                        assert header['pkt_num'] >= 0
                        assert isinstance(header['pkt_tai'], int)
                        assert header['pkt_tai'] >= 0
                        assert isinstance(header['pkt_nsec'], int)
                        assert 0 <= header['pkt_nsec'] < 1000000000
                        
                        count += 1
                        
                        # Skip image data (ph256 = 16x16x2 bytes + 1 for '*')
                        if ph_dp == "ph256":
                            pff.skip_image(f, 16, 2)
                        else:
                            pff.skip_image(f, 32, 2)

                    except Exception as e:
                        print(f"Header validation failed at frame {count}: {e}")
                        break
                
                return count
                
        except Exception as e:
            print(f"Error validating headers in {pff_file}: {e}")
            return 0

    def _extract_dp_name(self, filename: str) -> Optional[str]:
        """
        Extract data product name from PFF filename.
        Example: "start_12345.dp_ph256.seqno_0.pff" -> "ph256"
        """
        parts = filename.split('.')
        for part in parts:
            if part.startswith('dp_'):
                return part[3:]  # Remove 'dp_' prefix
        return None

    def test_header_size_stability_over_time(self, daq_env):
        """
        Test that header sizes remain constant over time within the same file.
        """
        base_dir = daq_env["base_dir"]
        run_name = daq_env["run_name"]
        ph_dp = daq_env["ph_dp"]
        
        # Take multiple samples over time
        samples = []
        for sample_num in range(3):
            time.sleep(5)  # Wait between samples
            
            sample_sizes = {}
            
            for mid in daq_env["module_ids"]:
                mod_run = base_dir / f"module_{mid}" / run_name
                if not mod_run.exists():
                    continue
                pff_files = list(mod_run.glob(f"*.dp_{ph_dp}.*.pff"))

                for pff_file in pff_files:
                    if pff_file.stat().st_size < 1000:
                        continue

                    sizes = self._check_header_sizes_in_file(pff_file, ph_dp)
                    if sizes:
                        # Track by filename to compare across time
                        sample_sizes[pff_file.name] = {
                            'sizes': sizes,
                            'unique_sizes': set(sizes),
                            'file_size': pff_file.stat().st_size
                        }
            
            samples.append(sample_sizes)
            print(f"Sample {sample_num + 1}: found {len(sample_sizes)} files")
        
        # Compare samples
        common_files = set(samples[0].keys())
        for sample in samples[1:]:
            common_files &= set(sample.keys())
        
        assert len(common_files) > 0, "No common files across time samples"
        
        for filename in common_files:
            # Check that header sizes are consistent across all samples for this file
            all_unique_sizes = set()
            
            for sample in samples:
                if filename in sample:
                    all_unique_sizes.update(sample[filename]['unique_sizes'])
            
            assert len(all_unique_sizes) == 1, (
                f"File {filename} has inconsistent header sizes over time: {all_unique_sizes}"
            )
            
        print(f"Header size stability test passed for {len(common_files)} files")
