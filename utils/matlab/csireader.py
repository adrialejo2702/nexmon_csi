"""
csireader.py

Main script to read and plot CSI from UDPs created using nexmon CSI extractor
Python port of csireader.m

Usage:
    python csireader.py
"""

import numpy as np
import os
import glob
from readpcap import ReadPcap
from unpack_float import unpack_float
from plotcsi import plotcsi


def main():
    """
    Main function to read CSI data from PCAP file and visualize it
    """
    
    # ========== CONFIGURATION ==========
    CHIP = '4366c0'           # WiFi chip (possible values: '4339', '4358', '43455c0', '4366c0')
    BW = 80                   # Bandwidth in MHz
    FILE = './pcap_files/rewis_A2/J_noBF_80Mhz_1x4_M1_1Mo_A2.pcap'  # Capture file
    NPKTS_MAX = 1000         # Max number of UDP packets to process
    PLOT_MODE = 'consolidated'  # Visualization mode: 'interactive', 'static', or 'consolidated'
    NORMALIZE = True         # Normalize CSI magnitude
    
    # ========== CONSTANTS ==========
    HOFFSET = 16              # Header offset
    NFFT = int(BW * 3.2)      # FFT size
    
    # Define valid subcarriers for each bandwidth (remove DC and guard bands)
    VALID_SUBCARRIERS = {
        20: list(range(-26, 0)) + list(range(1, 27)),    # 52 subcarriers
        40: list(range(-58, -1)) + list(range(2, 59)),   # 108 subcarriers  
        80: list(range(-122, -1)) + list(range(2, 123))   # 234 subcarriers
    }
    
    print(f"CSI Reader - Python Version")
    print(f"===========================")
    print(f"Chip: {CHIP}")
    print(f"Bandwidth: {BW} MHz")
    print(f"FFT Size: {NFFT}")
    print(f"Valid subcarriers: {len(VALID_SUBCARRIERS[BW])} (removing DC + guard bands)")
    print(f"File: {FILE}")
    print(f"Max packets: {NPKTS_MAX}")
    print(f"Plot mode: {PLOT_MODE}")
    print()
    
    # ========== READ FILE ==========
    print("Opening PCAP file...")
    p = ReadPcap()
    p.open(FILE)
    
    # Get all frames and limit to NPKTS_MAX
    all_frames = p.all()
    n = min(len(all_frames), NPKTS_MAX)
    print(f"Found {len(all_frames)} packets, processing {n} packets...")
    
    # Initialize CSI buffer
    csi_buff = np.zeros((n, NFFT), dtype=np.complex128)
    
    # Reset to start
    p.from_start()
    
    k = 0
    processed = 0
    skipped = 0
    
    while k < n:
        f = p.next()
        if f is None:
            print('No more frames')
            break
        
        # Check frame size
        expected_size = NFFT * 4
        actual_size = f['header']['orig_len'] - (HOFFSET - 1) * 4
        
        if actual_size != expected_size:
            skipped += 1
            continue
        
        payload = f['payload']
        # Adjust for 0-based indexing in Python (MATLAB uses 1-based)
        H = payload[HOFFSET-1:HOFFSET-1 + NFFT]
        
        # Verify we have enough data
        if len(H) < NFFT:
            skipped += 1
            continue
        
        # Process based on chip type
        if CHIP in ['4339', '43455c0']:
            # For these chips, use int16 typecast
            Hout = H.view(np.int16)
        elif CHIP == '4358':
            # Format 0 for bcm4358
            Hout = unpack_float(0, NFFT, H)
        elif CHIP == '4366c0':
            # Format 1 for bcm4366c0
            Hout = unpack_float(1, NFFT, H)
        else:
            print(f'Invalid CHIP: {CHIP}')
            break
        
        # Reshape to separate I/Q components
        Hout = Hout.reshape(2, -1, order='F')
        
        # Create complex values
        cmplx = Hout[0, :NFFT].astype(np.float64) + 1j * Hout[1, :NFFT].astype(np.float64)
        
        # Store in buffer
        csi_buff[k, :] = cmplx
        k += 1
        processed += 1
    
    # Close file
    p.close()
    
    print(f"\nProcessing complete:")
    print(f"  Processed: {processed} packets")
    print(f"  Skipped: {skipped} packets")
    print()
    
    # Trim buffer if needed
    if k < n:
        csi_buff = csi_buff[:k, :]
    
    # ========== FILTER VALID SUBCARRIERS ==========
    print("Filtering valid subcarriers (removing DC + guard bands)...")
    
    # Get valid subcarrier indices (convert from FFT indices to array indices)
    valid_indices = [idx + NFFT//2 for idx in VALID_SUBCARRIERS[BW]]
    valid_indices.sort()  # Ensure they're in order
    
    # Filter CSI data to keep only valid subcarriers
    csi_buff_filtered = csi_buff[:, valid_indices]
    
    print(f"Original CSI shape: {csi_buff.shape}")
    print(f"Filtered CSI shape: {csi_buff_filtered.shape}")
    print(f"Removed {csi_buff.shape[1] - csi_buff_filtered.shape[1]} invalid subcarriers")
    print()
    
    # ========== PLOT ==========
    print(f"Plotting CSI data (mode: {PLOT_MODE})...")
    
    # Create output directory for images
    output_dir = "csireader_image"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created directory: {output_dir}")
    
    # Generate image filename from PCAP filename
    pcap_basename = os.path.basename(FILE)
    image_name = os.path.splitext(pcap_basename)[0]  # Remove .pcap extension
    image_path = os.path.join(output_dir, f"{image_name}.png")
    
    plotcsi(csi_buff_filtered, VALID_SUBCARRIERS[BW], NORMALIZE, mode=PLOT_MODE, save_image=image_path)
    print(f"Image saved: {image_path}")
    print("Done!")


if __name__ == '__main__':
    main()

