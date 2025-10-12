"""
csireader_batch.py

Batch processing script to read and plot CSI from multiple PCAP files
Processes all files in the rewis_A2 folder and saves images in csireader_image/rewis_A2/

Usage:
    python csireader_batch.py
"""

import numpy as np
import os
import glob
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for batch processing
import matplotlib.pyplot as plt
from readpcap import ReadPcap
from unpack_float import unpack_float
from plotcsi import plotcsi


def main():
    """
    Main function to read CSI data from multiple PCAP files and visualize them
    Groups files by activity (W=Walking, S=Sitting, E=Empty, J=Jumping)
    """
    
    # ========== CONFIGURATION ==========
    CHIP = '4366c0'           # WiFi chip (possible values: '4339', '4358', '43455c0', '4366c0')
    NPKTS_MAX = 1000         # Max number of UDP packets to process
    PLOT_MODE = 'save_only'  # Visualization mode: 'interactive', 'static', 'consolidated', or 'save_only'
    NORMALIZE = True         # Normalize CSI magnitude
    
    # Process all PCAP files in rewis_A2 folder
    PCAP_FOLDER = './pcap_files/rewis_A2'
    OUTPUT_FOLDER = 'rewis_A2'
    
    # ========== CONSTANTS ==========
    HOFFSET = 16              # Header offset
    
    # Define valid subcarriers for each bandwidth (remove DC and guard bands)
    VALID_SUBCARRIERS = {
        20: list(range(-26, 0)) + list(range(1, 27)),    # 52 subcarriers
        40: list(range(-58, -1)) + list(range(2, 59)),   # 108 subcarriers  
        80: list(range(-122, -1)) + list(range(2, 123))   # 234 subcarriers
    }
    
    # Activity mapping
    ACTIVITY_NAMES = {
        'W': 'Walking',
        'S': 'Sitting', 
        'E': 'Empty',
        'J': 'Jumping'
    }
    
    print(f"CSI Reader - Python Version (Activity Comparison)")
    print(f"===============================================")
    print(f"Chip: {CHIP}")
    print(f"Processing folder: {PCAP_FOLDER}")
    print(f"Max packets per file: {NPKTS_MAX}")
    print(f"Plot mode: {PLOT_MODE}")
    print()
    
    # Create output directory for images
    output_dir = os.path.join("csireader_image", OUTPUT_FOLDER)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created directory: {output_dir}")
    
    # Get all PCAP files
    pcap_pattern = os.path.join(PCAP_FOLDER, "*.pcap")
    pcap_files = glob.glob(pcap_pattern)
    
    if not pcap_files:
        print(f"No PCAP files found in {PCAP_FOLDER}")
        return
    
    # Group files by activity and bandwidth
    activity_groups = {}
    for file_path in pcap_files:
        filename = os.path.basename(file_path)
        activity = filename[0]  # First character (W, S, E, J)
        
        if '20Mhz' in filename:
            bw = 20
        elif '40Mhz' in filename:
            bw = 40
        elif '80Mhz' in filename:
            bw = 80
        else:
            continue  # Skip files with unknown bandwidth
        
        key = f"{activity}_{bw}"
        if key not in activity_groups:
            activity_groups[key] = []
        activity_groups[key].append(file_path)
    
    print(f"Found activity groups:")
    for key, files in activity_groups.items():
        activity, bw = key.split('_')
        print(f"  {ACTIVITY_NAMES[activity]} ({bw}MHz): {len(files)} files")
    print()
    
    # Process each activity group
    successful = 0
    failed = 0
    
    for group_key, file_paths in activity_groups.items():
        activity, bw_str = group_key.split('_')
        bw = int(bw_str)
        nfft = int(bw * 3.2)
        
        print(f"\n{'='*60}")
        print(f"Processing {ACTIVITY_NAMES[activity]} ({bw}MHz) - {len(file_paths)} files")
        print(f"{'='*60}")
        
        # Process all files in this group
        success = process_activity_group(file_paths, CHIP, bw, nfft, HOFFSET, VALID_SUBCARRIERS,
                                       NPKTS_MAX, PLOT_MODE, NORMALIZE, output_dir, activity, ACTIVITY_NAMES[activity])
        
        if success:
            print(f"✅ Successfully processed: {ACTIVITY_NAMES[activity]} ({bw}MHz)")
            successful += 1
        else:
            print(f"❌ Failed to process: {ACTIVITY_NAMES[activity]} ({bw}MHz)")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"Activity comparison processing complete!")
    print(f"✅ Successful groups: {successful}")
    print(f"❌ Failed groups: {failed}")
    print(f"📁 Images saved in: {output_dir}")
    print(f"{'='*60}")


def process_activity_group(file_paths, chip, bw, nfft, hoffset, valid_subcarriers,
                          npkts_max, plot_mode, normalize, output_dir, activity, activity_name):
    """
    Process a group of files for the same activity and create comparison plots
    """
    try:
        all_csi_data = []
        file_labels = []
        
        # Process each file in the group
        for file_path in file_paths:
            filename = os.path.basename(file_path)
            print(f"  Processing: {filename}")
            
            # Extract configuration from filename
            if '1x1' in filename:
                config = '1x1'
            elif '1x4' in filename:
                config = '1x4'
            else:
                config = 'unknown'
            
            # Process the file
            csi_data = process_single_file_data(file_path, chip, bw, nfft, hoffset, valid_subcarriers, npkts_max)
            
            if csi_data is not None:
                all_csi_data.append(csi_data)
                file_labels.append(f"{activity_name} {config}")
            else:
                print(f"    ❌ Failed to process: {filename}")
                return False
        
        if not all_csi_data:
            print(f"    ❌ No valid data for {activity_name}")
            return False
        
        # Create comparison plot
        print(f"  Creating comparison plot for {activity_name} ({bw}MHz)...")
        success = create_activity_comparison(all_csi_data, file_labels, bw, valid_subcarriers[bw], 
                                           normalize, output_dir, activity, activity_name)
        
        return success
        
    except Exception as e:
        print(f"Error processing activity group {activity_name}: {str(e)}")
        return False


def process_single_file_data(file_path, chip, bw, nfft, hoffset, valid_subcarriers, npkts_max):
    """
    Process a single PCAP file and return CSI data
    """
    try:
        # Open PCAP file
        p = ReadPcap()
        p.open(file_path)
        
        # Get all frames and limit to NPKTS_MAX
        all_frames = p.all()
        n = min(len(all_frames), npkts_max)
        
        # Initialize CSI buffer
        csi_buff = np.zeros((n, nfft), dtype=np.complex128)
        
        # Reset to start
        p.from_start()
        
        k = 0
        processed = 0
        skipped = 0
        
        while k < n:
            f = p.next()
            if f is None:
                break
            
            # Check frame size
            expected_size = nfft * 4
            actual_size = f['header']['orig_len'] - (hoffset - 1) * 4
            
            if actual_size != expected_size:
                skipped += 1
                continue
            
            payload = f['payload']
            # Adjust for 0-based indexing in Python (MATLAB uses 1-based)
            H = payload[hoffset-1:hoffset-1 + nfft]
            
            # Verify we have enough data
            if len(H) < nfft:
                skipped += 1
                continue
            
            # Process based on chip type
            if chip in ['4339', '43455c0']:
                # For these chips, use int16 typecast
                Hout = H.view(np.int16)
            elif chip == '4358':
                # Format 0 for bcm4358
                Hout = unpack_float(0, nfft, H)
            elif chip == '4366c0':
                # Format 1 for bcm4366c0
                Hout = unpack_float(1, nfft, H)
            else:
                break
            
            # Reshape to separate I/Q components
            Hout = Hout.reshape(2, -1, order='F')
            
            # Create complex values
            cmplx = Hout[0, :nfft].astype(np.float64) + 1j * Hout[1, :nfft].astype(np.float64)
            
            # Store in buffer
            csi_buff[k, :] = cmplx
            k += 1
            processed += 1
        
        # Close file
        p.close()
        
        # Trim buffer if needed
        if k < n:
            csi_buff = csi_buff[:k, :]
        
        # Filter valid subcarriers
        valid_indices = [idx + nfft//2 for idx in valid_subcarriers[bw]]
        valid_indices.sort()
        csi_buff_filtered = csi_buff[:, valid_indices]
        
        print(f"    Processed: {processed} packets, Filtered: {csi_buff_filtered.shape}")
        
        return csi_buff_filtered
        
    except Exception as e:
        print(f"    Error processing {file_path}: {str(e)}")
        return None


def create_activity_comparison(all_csi_data, file_labels, bw, valid_subcarrier_indices, normalize, output_dir, activity, activity_name):
    """
    Create comparison plot for all files in an activity group
    """
    try:
        from plotcsi import plotcsi_activity_comparison
        
        # Generate image filename
        image_name = f"{activity_name}_{bw}MHz_comparison"
        image_path = os.path.join(output_dir, f"{image_name}.png")
        
        # Create comparison plot
        plotcsi_activity_comparison(all_csi_data, file_labels, valid_subcarrier_indices, normalize, image_path)
        
        print(f"    Image saved: {image_path}")
        return True
        
    except Exception as e:
        print(f"    Error creating comparison plot: {str(e)}")
        return False


if __name__ == '__main__':
    main()
