"""
plotcsi_extended.py

Extended visualization functions for CSI data with metadata (RSSI, MAC, etc.)
"""

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec


def plotcsi_with_rssi(csi, nfft, normalize, packets_info, mode='consolidated'):
    """
    Plot CSI data with RSSI and metadata information
    
    Parameters:
    -----------
    csi : numpy.ndarray
        CSI data array with shape (num_packets, nfft)
    nfft : int
        FFT size
    normalize : bool
        Whether to normalize the CSI magnitude
    packets_info : list
        List of dictionaries with packet metadata
    mode : str
        Visualization mode: 'interactive', 'static', or 'consolidated'
    """
    # Apply FFT shift
    csi_buff = np.fft.fftshift(csi, axes=1)
    
    # Calculate phase in degrees
    csi_phase = np.rad2deg(np.angle(csi_buff))
    
    # Calculate magnitude
    csi_mag = np.abs(csi_buff)
    
    # Normalize if requested
    if normalize:
        for cs in range(csi_mag.shape[0]):
            max_val = np.max(csi_mag[cs, :])
            if max_val > 0:
                csi_mag[cs, :] = csi_mag[cs, :] / max_val
    
    # Subcarrier indices
    x = np.arange(-nfft//2, nfft//2)
    
    # Extract RSSI values
    rssi_values = np.array([p['rssi'] for p in packets_info])
    
    if mode == 'consolidated':
        _plot_consolidated_with_rssi(csi_mag, csi_phase, rssi_values, x, nfft, packets_info)
    elif mode == 'static':
        _plot_static_with_rssi(csi_mag, csi_phase, rssi_values, x, nfft, packets_info)
    else:  # interactive mode
        _plot_interactive_with_rssi(csi_mag, csi_phase, rssi_values, x, nfft, packets_info)


def _plot_consolidated_with_rssi(csi_mag, csi_phase, rssi_values, x, nfft, packets_info):
    """
    Consolidated mode with RSSI information
    """
    num_packets = csi_mag.shape[0]
    
    # ===== PART 1: Overview with RSSI =====
    print("\n=== VISTA GENERAL CON RSSI ===")
    print("Mostrando resumen con información de RSSI...")
    
    fig = plt.figure(figsize=(14, 10))
    gs = GridSpec(2, 2, figure=fig, hspace=0.3, wspace=0.3)
    
    # 1. All amplitudes overlaid (top left)
    ax1 = fig.add_subplot(gs[0, 0])
    for cs in range(num_packets):
        alpha = 0.3 if num_packets > 10 else 0.6
        ax1.plot(x, csi_mag[cs, :], alpha=alpha, linewidth=0.5)
    ax1.grid(True, alpha=0.3)
    ax1.set_xlim([x[0] - 0.5, x[-1] + 0.5])
    ax1.set_xlabel('Subcarrier')
    ax1.set_ylabel('Magnitude')
    ax1.set_title(f'All Amplitudes Overlaid ({num_packets} packets)')
    
    # 2. RSSI over time (top right)
    ax2 = fig.add_subplot(gs[0, 1])
    packet_nums = np.arange(1, num_packets + 1)
    ax2.plot(packet_nums, rssi_values, 'o-', linewidth=1, markersize=3)
    ax2.grid(True, alpha=0.3)
    ax2.set_xlabel('Packet Number')
    ax2.set_ylabel('RSSI (dBm)')
    ax2.set_title(f'RSSI over Time (Mean: {np.mean(rssi_values):.1f} dBm)')
    ax2.axhline(y=np.mean(rssi_values), color='r', linestyle='--', alpha=0.5, label='Mean')
    ax2.legend()
    
    # 3. Amplitude heatmap (bottom left)
    ax3 = fig.add_subplot(gs[1, 0])
    im3 = ax3.imshow(csi_mag, aspect='auto', extent=[x[0]-0.5, x[-1]+0.5, num_packets, 1], 
                     cmap='viridis')
    ax3.set_xlabel('Subcarrier')
    ax3.set_ylabel('Packet number')
    ax3.set_title('Amplitude Heatmap')
    plt.colorbar(im3, ax=ax3, label='Magnitude')
    
    # 4. Mean amplitude with std (bottom right)
    ax4 = fig.add_subplot(gs[1, 1])
    mean_mag = np.mean(csi_mag, axis=0)
    std_mag = np.std(csi_mag, axis=0)
    ax4.plot(x, mean_mag, 'b-', linewidth=2, label='Mean')
    ax4.fill_between(x, mean_mag - std_mag, mean_mag + std_mag, 
                      alpha=0.3, label='± 1 std')
    ax4.grid(True, alpha=0.3)
    ax4.set_xlim([x[0] - 0.5, x[-1] + 0.5])
    ax4.set_xlabel('Subcarrier')
    ax4.set_ylabel('Magnitude')
    ax4.set_title('Mean Amplitude with Std Deviation')
    ax4.legend()
    
    plt.show(block=True)
    
    # ===== PART 2: Interactive view =====
    print("\n=== VISTA INTERACTIVA ===")
    print("Navegando por cada paquete con información RSSI...")
    print("Presiona cualquier tecla para avanzar, 'q' o ESC para salir.\n")
    
    fig_interactive = plt.figure(figsize=(14, 10))
    
    def on_key(event):
        if event.key in ['q', 'escape']:
            plt.close(fig_interactive)
    
    fig_interactive.canvas.mpl_connect('key_press_event', on_key)
    
    max_y = np.max(csi_mag)
    
    for cs in range(num_packets):
        if not plt.fignum_exists(fig_interactive.number):
            print("\n¡Visualización cancelada por el usuario!")
            break
        
        fig_interactive.clf()
        
        # Get packet info
        pkt = packets_info[cs]
        
        # Create title with metadata
        title_info = (f"Packet #{cs+1}/{num_packets} | "
                     f"RSSI: {pkt['rssi']} dBm | "
                     f"MAC: {pkt['src_mac']} | "
                     f"Seq: {pkt['seq']} | "
                     f"Core: {pkt['core']}, SS: {pkt['spatial_stream']}")
        
        # Magnitude with context
        ax1 = plt.subplot(3, 1, 1)
        for i in range(num_packets):
            if i == cs:
                ax1.plot(x, csi_mag[i, :], 'b-', linewidth=2.5, label=f'Current')
            else:
                ax1.plot(x, csi_mag[i, :], 'gray', alpha=0.1, linewidth=0.5)
        ax1.grid(True)
        ax1.set_xlim([x[0] - 0.5, x[-1] + 0.5])
        ax1.set_ylim([0, max_y])
        ax1.set_xlabel('Subcarrier')
        ax1.set_ylabel('Magnitude')
        ax1.set_title(f'Magnitude - {title_info}')
        ax1.legend(loc='upper right')
        
        # Phase with context
        ax2 = plt.subplot(3, 1, 2)
        for i in range(num_packets):
            if i == cs:
                ax2.plot(x, csi_phase[i, :], 'r-', linewidth=2.5, label=f'Current')
            else:
                ax2.plot(x, csi_phase[i, :], 'gray', alpha=0.1, linewidth=0.5)
        ax2.grid(True)
        ax2.set_xlim([x[0] - 0.5, x[-1] + 0.5])
        ax2.set_ylim([-180, 180])
        ax2.set_xlabel('Subcarrier')
        ax2.set_ylabel('Phase (degrees)')
        ax2.set_title('Phase')
        ax2.legend(loc='upper right')
        
        # Combined heatmap with RSSI indicator
        ax3 = plt.subplot(3, 1, 3)
        im = ax3.imshow(csi_mag, aspect='auto', extent=[x[0]-0.5, x[-1]+0.5, num_packets, 1],
                        cmap='viridis')
        ax3.axhline(y=cs+1, color='red', linewidth=2.5, linestyle='--', alpha=0.8)
        
        # Add RSSI colorbar on the right side
        ax3_rssi = ax3.twinx()
        ax3_rssi.set_ylim([1, num_packets])
        ax3_rssi.set_ylabel('RSSI (dBm)', color='red')
        ax3_rssi.tick_params(axis='y', labelcolor='red')
        
        ax3.set_xlabel('Subcarrier')
        ax3.set_ylabel('Packet number')
        ax3.set_title(f'Position in capture (RSSI: {pkt["rssi"]} dBm)')
        
        plt.tight_layout()
        
        print(f'Paquete {cs+1}/{num_packets} - RSSI: {pkt["rssi"]} dBm - MAC: {pkt["src_mac"]} - Seq: {pkt["seq"]}')
        plt.waitforbuttonpress()
        
        if not plt.fignum_exists(fig_interactive.number):
            print("\n¡Visualización cancelada por el usuario!")
            break
    
    if plt.fignum_exists(fig_interactive.number):
        plt.close(fig_interactive)
        print("\n¡Visualización completada!")
    else:
        print("Fin de la sesión interactiva.")


def _plot_static_with_rssi(csi_mag, csi_phase, rssi_values, x, nfft, packets_info):
    """
    Static mode with RSSI: generates individual figures for each packet
    """
    max_y = np.max(csi_mag)
    num_packets = csi_mag.shape[0]
    
    for cs in range(num_packets):
        pkt = packets_info[cs]
        
        fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 10))
        
        title_info = (f"Packet #{cs+1}/{num_packets} | RSSI: {pkt['rssi']} dBm | "
                     f"MAC: {pkt['src_mac']} | Seq: {pkt['seq']}")
        
        # Magnitude
        ax1.plot(x, csi_mag[cs, :])
        ax1.grid(True)
        ax1.set_xlim([x[0] - 0.5, x[-1] + 0.5])
        ax1.set_ylim([0, max_y])
        ax1.set_xlabel('Subcarrier')
        ax1.set_ylabel('Magnitude')
        ax1.set_title(f'CSI Magnitude - {title_info}')
        
        # Phase
        ax2.plot(x, csi_phase[cs, :])
        ax2.grid(True)
        ax2.set_xlim([x[0] - 0.5, x[-1] + 0.5])
        ax2.set_ylim([-180, 180])
        ax2.set_xlabel('Subcarrier')
        ax2.set_ylabel('Phase (degrees)')
        ax2.set_title('CSI Phase')
        
        # Heatmap
        im = ax3.imshow(csi_mag, aspect='auto', extent=[x[0]-0.5, x[-1]+0.5, num_packets, 1])
        ax3.set_xlabel('Subcarrier')
        ax3.set_ylabel('Packet number')
        ax3.set_title('Amplitude Heatmap')
        
        plt.tight_layout()
        plt.show(block=False)
        plt.pause(0.1)


def _plot_interactive_with_rssi(csi_mag, csi_phase, rssi_values, x, nfft, packets_info):
    """
    Interactive mode with RSSI: similar to consolidated but starts directly with interactive view
    """
    # Just call the interactive part of consolidated
    _plot_consolidated_with_rssi(csi_mag, csi_phase, rssi_values, x, nfft, packets_info)

