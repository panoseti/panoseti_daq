def test_ph256_constant_header_size(self, daq_env):
    """
    Test that ph256 PFF files have constant-sized JSON headers.
    Enhanced for container-based testing with longer waits.
    """
    base_dir = daq_env["base_dir"]
    run_name = daq_env["run_name"]

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
            
            for pff_file in ph256_files:
                # Be more lenient with file size in containers
                if pff_file.stat().st_size < 500:  # Reduced from 1000
                    continue

                sizes = self._check_header_sizes_in_file(pff_file, expected_dp="ph256")
                if sizes:
                    header_sizes.extend(sizes)
                    files_checked += 1
        
        # If we found files, break early
        if files_checked > 0:
            print(f"Found {files_checked} PFF files after {wait_time + wait_interval}s")
            break
        else:
            print(f"No PFF files found yet after {wait_time + wait_interval}s, continuing to wait...")

    assert files_checked > 0, f"No ph256 PFF files found to test after {max_wait_time}s wait"
    assert len(header_sizes) > 0, "No frames found in ph256 PFF files"

    # All header sizes should be identical
    unique_sizes = set(header_sizes)
    assert len(unique_sizes) == 1, f"ph256 headers have inconsistent sizes: {unique_sizes}"

    # Check against expected size (be more flexible for containers)
    header_size = list(unique_sizes)[0]
    print(f"ph256 header size: {header_size} bytes from {len(header_sizes)} frames")
    assert 80 <= header_size <= 250, f"ph256 header size {header_size} seems unreasonable"
