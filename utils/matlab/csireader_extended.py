"""
csireader_extended.py

Extended CSI reader for updated UDP packet format with RSSI, MAC, sequence, etc.
Supports the new format introduced in nexmon_csi PR #256 with 18-byte header

Usage:
    python csireader_extended.py
"""

import numpy as np
import struct
from readpcap import ReadPcap
from unpack_float import unpack_float
from plotcsi import plotcsi
from plotcsi_extended import plotcsi_with_rssi


# Chip version mapping
CHIP_VERSIONS = {
    0x4339: 'bcm4339',
    0x4358: 'bcm4358',
    0x4366: 'bcm4366c0',
    0xaa52: 'bcm43455c0',
    0x0065: 'bcm43455c0'  # Additional mapping found in capture
}


def parse_csi_header(payload):
    """
    Parse the 18-byte CSI UDP header from updated format
    Automatically detects and skips Ethernet/IP/UDP headers if present
    
    Structure:
    - Offset 0-1: Magic bytes 0x1111 (uint16)
    - Offset 2: RSSI (int8)
    - Offset 3: Frame Control (uint8)
    - Offset 4-9: Source MAC (6 bytes)
    - Offset 10-11: Sequence Counter (uint16)
    - Offset 12-13: CSI Config - core y spatial stream (uint16)
    - Offset 14-15: Chanspec (uint16)
    - Offset 16-17: Chip version (uint16)
    - Offset 18+: CSI data
    
    Parameters:
    -----------
    payload : numpy.ndarray
        Raw payload data as uint32 or uint8 array
        
    Returns:
    --------
    header : dict
        Dictionary with all header fields
    valid : bool
        True if magic bytes are valid
    """
    # Convert to bytes if needed
    if payload.dtype == np.uint32:
        payload_bytes = payload.tobytes()
    else:
        payload_bytes = payload.tobytes()
    
    # Detect if Ethernet/IP/UDP headers are present
    # Look for magic bytes 0x1111 in the first 100 bytes
    csi_offset = 0
    
    for offset in range(min(100, len(payload_bytes) - 2)):
        magic_test = struct.unpack('<H', payload_bytes[offset:offset+2])[0]
        if magic_test == 0x1111:
            csi_offset = offset
            break
    
    # Parse header fields starting from detected offset
    magic = struct.unpack('<H', payload_bytes[csi_offset:csi_offset+2])[0]
    rssi = struct.unpack('<b', payload_bytes[csi_offset+2:csi_offset+3])[0]  # signed int8
    fc = struct.unpack('<B', payload_bytes[csi_offset+3:csi_offset+4])[0]
    src_mac = payload_bytes[csi_offset+4:csi_offset+10]
    seq = struct.unpack('<H', payload_bytes[csi_offset+10:csi_offset+12])[0]
    csiconf = struct.unpack('<H', payload_bytes[csi_offset+12:csi_offset+14])[0]
    chanspec = struct.unpack('<H', payload_bytes[csi_offset+14:csi_offset+16])[0]
    chip_ver = struct.unpack('<H', payload_bytes[csi_offset+16:csi_offset+18])[0]
    
    # Extract core and spatial stream from csiconf
    core = csiconf & 0x7  # 3 lowest bits
    spatial_stream = (csiconf >> 3) & 0x7  # next 3 bits
    
    # Decode chanspec
    channel = chanspec & 0xFF
    bw_code = (chanspec >> 11) & 0x7
    bw_map = {0: 5, 1: 10, 2: 20, 3: 40, 4: 80, 5: 160, 6: 80}
    bandwidth = bw_map.get(bw_code, 0)
    
    # Format MAC address
    mac_str = ':'.join([f'{b:02X}' for b in src_mac])
    
    # Map chip version
    chip_name = CHIP_VERSIONS.get(chip_ver, f'Unknown(0x{chip_ver:04X})')
    
    header = {
        'magic': magic,
        'rssi': rssi,
        'fc': fc,
        'src_mac': mac_str,
        'src_mac_bytes': src_mac,
        'seq': seq,
        'core': core,
        'spatial_stream': spatial_stream,
        'csiconf': csiconf,
        'chanspec': chanspec,
        'channel': channel,
        'bandwidth': bandwidth,
        'chip_version': chip_ver,
        'chip_name': chip_name,
        'csi_offset': csi_offset  # Store offset for CSI data extraction
    }
    
    valid = (magic == 0x1111)
    
    return header, valid


def decode_chanspec(chanspec):
    """
    Decode chanspec to human-readable format
    
    Parameters:
    -----------
    chanspec : int
        Channel specification value
        
    Returns:
    --------
    str : Human readable channel specification
    """
    channel = chanspec & 0xFF
    bw = (chanspec >> 11) & 0x7
    bw_map = {0: '5MHz', 1: '10MHz', 2: '20MHz', 3: '40MHz', 
              4: '80MHz', 5: '160MHz', 6: '80+80MHz'}
    return f"Channel {channel} @ {bw_map.get(bw, 'Unknown')}"


def print_packet_summary(packets_info):
    """
    Print summary table of all packets
    
    Parameters:
    -----------
    packets_info : list
        List of packet info dictionaries
    """
    print("\n" + "="*100)
    print("PACKET SUMMARY")
    print("="*100)
    print(f"{'#':>4} | {'RSSI':>5} | {'Seq':>6} | {'MAC Address':>17} | {'Core':>4} | {'SS':>2} | {'Chan':>4} | {'BW':>6}")
    print("-"*100)
    
    for i, pkt in enumerate(packets_info):
        print(f"{i+1:>4} | {pkt['rssi']:>5} | {pkt['seq']:>6} | {pkt['src_mac']:>17} | "
              f"{pkt['core']:>4} | {pkt['spatial_stream']:>2} | {pkt['channel']:>4} | {pkt['bandwidth']:>6}")
    
    print("="*100)


def print_statistics(packets_info):
    """
    Print statistics about the captured packets
    
    Parameters:
    -----------
    packets_info : list
        List of packet info dictionaries
    """
    if not packets_info:
        return
    
    rssi_values = [p['rssi'] for p in packets_info]
    seq_values = [p['seq'] for p in packets_info]
    macs = set([p['src_mac'] for p in packets_info])
    
    print("\n" + "="*100)
    print("STATISTICS")
    print("="*100)
    print(f"Total packets processed: {len(packets_info)}")
    print(f"\nRSSI Statistics:")
    print(f"  Min RSSI:  {min(rssi_values)} dBm")
    print(f"  Max RSSI:  {max(rssi_values)} dBm")
    print(f"  Mean RSSI: {np.mean(rssi_values):.2f} dBm")
    print(f"  Std RSSI:  {np.std(rssi_values):.2f} dBm")
    
    # Check for packet loss
    if len(seq_values) > 1:
        seq_diff = np.diff(seq_values)
        expected_gaps = np.sum(seq_diff - 1)
        if expected_gaps > 0:
            print(f"\nPacket Loss:")
            print(f"  Estimated missing packets: {expected_gaps}")
            loss_rate = (expected_gaps / (len(seq_values) + expected_gaps)) * 100
            print(f"  Loss rate: {loss_rate:.2f}%")
        else:
            print(f"\nNo packet loss detected (continuous sequence)")
    
    print(f"\nTransmitters detected: {len(macs)}")
    for mac in macs:
        count = sum(1 for p in packets_info if p['src_mac'] == mac)
        print(f"  {mac}: {count} packets")
    
    print(f"\nChannel information:")
    channels = set([(p['channel'], p['bandwidth']) for p in packets_info])
    for ch, bw in channels:
        count = sum(1 for p in packets_info if p['channel'] == ch and p['bandwidth'] == bw)
        print(f"  Channel {ch} @ {bw} MHz: {count} packets")
    
    print("="*100 + "\n")


def save_to_npz(filename, csi_data, packets_info):
    """
    Save CSI data and metadata to NumPy .npz file
    
    Parameters:
    -----------
    filename : str
        Output filename
    csi_data : numpy.ndarray
        CSI data array
    packets_info : list
        List of packet info dictionaries
    """
    # Convert packets_info to structured arrays
    rssi = np.array([p['rssi'] for p in packets_info])
    seq = np.array([p['seq'] for p in packets_info])
    core = np.array([p['core'] for p in packets_info])
    ss = np.array([p['spatial_stream'] for p in packets_info])
    channel = np.array([p['channel'] for p in packets_info])
    bandwidth = np.array([p['bandwidth'] for p in packets_info])
    
    np.savez(filename,
             csi=csi_data,
             rssi=rssi,
             sequence=seq,
             core=core,
             spatial_stream=ss,
             channel=channel,
             bandwidth=bandwidth)
    
    print(f"Data saved to {filename}")


def main():
    """
    Main function to read CSI data with extended header information
    """
    
    # ========== CONFIGURATION ==========
    CHIP = '4358'           # WiFi chip (possible values: '4339', '4358', '43455c0', '4366c0')
    BW = 80                   # Bandwidth in MHz (for CSI buffer size calculation)
    FILE = './example.pcap'  # Capture file
    NPKTS_MAX = 300           # Max number of UDP packets to process
    PLOT_MODE = 'consolidated'  # Visualization mode: 'interactive', 'static', or 'consolidated'
    NORMALIZE = True          # Normalize CSI magnitude
    SAVE_NPZ = False          # Save data to .npz file
    SHOW_TABLE = True         # Show packet summary table
    
    # ========== CONSTANTS ==========
    HEADER_SIZE = 18          # Updated header size (was 16 in old format)
    NFFT = int(BW * 3.2)      # FFT size
    
    print(f"CSI Reader Extended - Python Version")
    print(f"=" * 60)
    print(f"Chip: {CHIP}")
    print(f"Bandwidth: {BW} MHz")
    print(f"FFT Size: {NFFT}")
    print(f"File: {FILE}")
    print(f"Max packets: {NPKTS_MAX}")
    print(f"Plot mode: {PLOT_MODE}")
    print(f"Header format: Extended (18 bytes with RSSI, MAC, etc.)")
    print()
    
    # ========== READ FILE ==========
    print("Opening PCAP file...")
    p = ReadPcap()
    p.open(FILE)
    
    # Get all frames and limit to NPKTS_MAX
    all_frames = p.all()
    n = min(len(all_frames), NPKTS_MAX)
    print(f"Found {len(all_frames)} packets in PCAP file")
    print(f"Processing up to {n} packets...\n")
    
    # Initialize buffers
    csi_buff = []
    packets_info = []
    
    # Reset to start
    p.from_start()
    
    k = 0
    processed = 0
    skipped = 0
    invalid_magic = 0
    
    while k < n:
        f = p.next()
        if f is None:
            break
        
        payload = f['payload']
        
        # Parse header
        try:
            header, valid = parse_csi_header(payload)
        except Exception as e:
            print(f"Error parsing header: {e}")
            skipped += 1
            continue
        
        if not valid:
            invalid_magic += 1
            skipped += 1
            continue
        
        # Extract CSI data starting from detected offset + header size
        # Calculate expected CSI data size
        actual_bw = header['bandwidth']
        if actual_bw > 0:
            nfft_actual = int(actual_bw * 3.2)
        else:
            nfft_actual = NFFT
        
        # Get CSI data starting from detected offset + header size
        csi_data_offset_bytes = header['csi_offset'] + HEADER_SIZE
        
        # Get CSI data portion
        if payload.dtype == np.uint32:
            # Convert byte offset to uint32 offset
            csi_start_u32 = csi_data_offset_bytes // 4
            csi_end_u32 = csi_start_u32 + nfft_actual
            
            if csi_end_u32 > len(payload):
                skipped += 1
                continue
                
            H = payload[csi_start_u32:csi_end_u32]
        else:
            # uint8 array
            csi_start = csi_data_offset_bytes
            csi_end = csi_start + nfft_actual * 4
            
            if csi_end > len(payload):
                skipped += 1
                continue
            
            H = payload[csi_start:csi_end]
            # Convert to uint32
            H = np.frombuffer(H.tobytes(), dtype=np.uint32)
        
        if len(H) < nfft_actual:
            skipped += 1
            continue
        
        # Process based on chip type
        if CHIP in ['4339', '43455c0']:
            # For these chips, use int16 typecast
            Hout = H.view(np.int16)
        elif CHIP == '4358':
            # Format 0 for bcm4358
            Hout = unpack_float(0, nfft_actual, H)
        elif CHIP == '4366c0':
            # Format 1 for bcm4366c0
            Hout = unpack_float(1, nfft_actual, H)
        else:
            print(f'Invalid CHIP: {CHIP}')
            break
        
        # Reshape to separate I/Q components
        Hout = Hout.reshape(2, -1, order='F')
        
        # Create complex values
        cmplx = Hout[0, :nfft_actual].astype(np.float64) + 1j * Hout[1, :nfft_actual].astype(np.float64)
        
        # Store CSI and metadata
        csi_buff.append(cmplx)
        packets_info.append(header)
        
        k += 1
        processed += 1
    
    # Close file
    p.close()
    
    print(f"Processing complete:")
    print(f"  Processed: {processed} packets")
    print(f"  Skipped: {skipped} packets")
    print(f"  Invalid magic bytes: {invalid_magic} packets")
    
    if processed == 0:
        print("\nNo valid packets found!")
        return
    
    # Convert to numpy array
    # Pad shorter arrays if needed (different bandwidths)
    max_len = max([len(c) for c in csi_buff])
    csi_array = np.zeros((processed, max_len), dtype=np.complex128)
    for i, csi in enumerate(csi_buff):
        csi_array[i, :len(csi)] = csi
    
    # ========== STATISTICS ==========
    print_statistics(packets_info)
    
    # ========== PACKET TABLE ==========
    if SHOW_TABLE and processed <= 50:
        print_packet_summary(packets_info)
    elif SHOW_TABLE:
        print(f"\nShowing first 20 and last 20 packets:")
        print_packet_summary(packets_info[:20] + packets_info[-20:])
    
    # ========== SAVE DATA ==========
    if SAVE_NPZ:
        output_file = FILE.replace('.pcap', '_csi_data.npz')
        save_to_npz(output_file, csi_array, packets_info)
    
    # ========== PLOT ==========
    print(f"\nPlotting CSI data (mode: {PLOT_MODE})...")
    
    # Use extended plotting with RSSI information
    try:
        plotcsi_with_rssi(csi_array, max_len, NORMALIZE, packets_info, mode=PLOT_MODE)
    except Exception as e:
        print(f"Error using extended plotting: {e}")
        print("Falling back to standard plotting...")
        # Fallback to standard plotting
        if packets_info:
            rssi_values = [p['rssi'] for p in packets_info]
            print(f"RSSI range: {min(rssi_values)} to {max(rssi_values)} dBm")
        plotcsi(csi_array, max_len, NORMALIZE, mode=PLOT_MODE)
    
    print("\nDone!")


if __name__ == '__main__':
    main()

