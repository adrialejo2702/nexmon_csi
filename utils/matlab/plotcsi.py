"""
plotcsi.py

Visualization functions for CSI data
Equivalent to plotcsi.m MATLAB function with additional modes
"""

import numpy as np
import matplotlib.pyplot as plt


def plotcsi(csi, subcarrier_indices, normalize, mode='interactive', save_image=None):
    """
    Plot CSI data with different visualization modes
    
    Parameters:
    -----------
    csi : numpy.ndarray
        CSI data array with shape (num_packets, nfft)
    subcarrier_indices : list
        List of valid subcarrier indices (centered around 0)
    normalize : bool
        Whether to normalize the CSI magnitude
    mode : str
        Visualization mode: 'interactive', 'static', 'consolidated', or 'save_only'
    save_image : str, optional
        Path to save the consolidated view image (only for consolidated mode)
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
    
    # Use provided subcarrier indices (centered around 0, like original MATLAB)
    x = np.array(subcarrier_indices)
    
    if mode == 'consolidated':
        _plot_consolidated(csi_mag, csi_phase, x, len(subcarrier_indices), save_image)
    elif mode == 'save_only':
        _plot_save_only(csi_mag, csi_phase, x, len(subcarrier_indices), save_image)
    elif mode == 'static':
        _plot_static(csi_mag, csi_phase, x, len(subcarrier_indices))
    else:  # interactive mode
        _plot_interactive(csi_mag, csi_phase, x, len(subcarrier_indices))


def _plot_save_only(csi_mag, csi_phase, x, nfft, save_image):
    """
    Save-only mode: creates and saves the consolidated view without displaying it
    Optimized for batch processing
    """
    num_packets = csi_mag.shape[0]
    
    # Create figure without displaying it
    fig = plt.figure(figsize=(10, 6))
    
    # Create 2 subplots in 1x2 layout
    ax1 = plt.subplot(1, 2, 1)  # Heatmap of amplitudes
    ax2 = plt.subplot(1, 2, 2)  # Mean amplitude with std
    
    # 1. Heatmap of amplitudes (time vs amplitude)
    im1 = ax1.imshow(csi_mag.T, aspect='auto', extent=[1, num_packets, x[-1]+0.5, x[0]-0.5], 
                     cmap='viridis')
    ax1.set_xlabel('Packet number (Time)')
    ax1.set_ylabel('Subcarrier Index')
    ax1.set_title('Amplitude Heatmap (Time vs Subcarriers)')
    plt.colorbar(im1, ax=ax1)
    
    # 2. Mean amplitude with standard deviation
    mean_mag = np.mean(csi_mag, axis=0)
    std_mag = np.std(csi_mag, axis=0)
    ax2.plot(x, mean_mag, 'b-', linewidth=2, label='Mean')
    ax2.fill_between(x, mean_mag - std_mag, mean_mag + std_mag, 
                      alpha=0.3, label='± 1 std')
    ax2.grid(True, alpha=0.3)
    ax2.set_xlim([x[0] - 0.5, x[-1] + 0.5])
    ax2.set_xlabel('Subcarrier Index')
    ax2.set_ylabel('Magnitude')
    ax2.set_title('Mean Amplitude with Std Deviation')
    ax2.legend()
    
    plt.tight_layout()
    
    # Save image if path is provided
    if save_image:
        plt.savefig(save_image, dpi=300, bbox_inches='tight')
        print(f"Image saved: {save_image}")
    
    # Close figure without displaying
    plt.close(fig)


def plotcsi_activity_comparison(all_csi_data, file_labels, subcarrier_indices, normalize, save_image):
    """
    Create comparison plot for multiple CSI datasets (same activity, different configurations)
    Shows separate amplitude heatmaps + mean amplitude comparison
    """
    # Process each dataset
    processed_data = []
    
    for i, csi_data in enumerate(all_csi_data):
        # Apply FFT shift
        csi_buff = np.fft.fftshift(csi_data, axes=1)
        
        # Calculate magnitude
        csi_mag = np.abs(csi_buff)
        
        # Normalize if requested
        if normalize:
            for cs in range(csi_mag.shape[0]):
                max_val = np.max(csi_mag[cs, :])
                if max_val > 0:
                    csi_mag[cs, :] = csi_mag[cs, :] / max_val
        
        processed_data.append(csi_mag)
    
    # Use provided subcarrier indices (centered around 0, like original MATLAB)
    x = np.array(subcarrier_indices)
    
    # Create figure with 2 rows: heatmaps on top, mean amplitude comparison on bottom
    num_configs = len(processed_data)
    fig = plt.figure(figsize=(6 * num_configs, 10))
    
    # Colors for mean amplitude comparison
    colors = ['blue', 'red', 'green', 'orange']
    
    # Row 1: Individual heatmaps
    for i, (csi_mag, label) in enumerate(zip(processed_data, file_labels)):
        ax = plt.subplot(2, num_configs, i + 1)
        
        # Create heatmap (time vs amplitude)
        im = ax.imshow(csi_mag.T, aspect='auto', extent=[1, csi_mag.shape[0], x[-1]+0.5, x[0]-0.5], 
                       cmap='viridis')
        ax.set_xlabel('Packet number (Time)')
        ax.set_ylabel('Subcarrier Index')
        ax.set_title(f'{label}\nAmplitude Heatmap')
        
        # Add colorbar
        plt.colorbar(im, ax=ax)
    
    # Row 2: Mean amplitude comparison (spans all columns)
    ax_mean = plt.subplot(2, 1, 2)
    
    for i, (csi_mag, label) in enumerate(zip(processed_data, file_labels)):
        mean_mag = np.mean(csi_mag, axis=0)
        std_mag = np.std(csi_mag, axis=0)
        
        color = colors[i % len(colors)]
        
        # Plot mean with standard deviation band
        ax_mean.plot(x, mean_mag, color=color, linewidth=2, label=label)
        ax_mean.fill_between(x, mean_mag - std_mag, mean_mag + std_mag, 
                            color=color, alpha=0.2)
    
    ax_mean.grid(True, alpha=0.3)
    ax_mean.set_xlim([x[0] - 0.5, x[-1] + 0.5])
    ax_mean.set_xlabel('Valid Subcarrier Index')
    ax_mean.set_ylabel('Mean Magnitude')
    ax_mean.set_title('Mean Amplitude Comparison (with ± 1 std)')
    ax_mean.legend(loc='best')
    
    plt.tight_layout()
    
    # Save image
    if save_image:
        plt.savefig(save_image, dpi=300, bbox_inches='tight')
        print(f"Activity comparison saved: {save_image}")
    
    # Close figure
    plt.close(fig)


def _plot_interactive(csi_mag, csi_phase, x, nfft):
    """
    Interactive mode: shows one packet at a time, waiting for user input
    Similar to original MATLAB behavior
    """
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 10))
    
    max_y = np.max(csi_mag)
    num_packets = csi_mag.shape[0]
    
    for cs in range(num_packets):
        # Plot magnitude
        ax1.clear()
        ax1.plot(x, csi_mag[cs, :])
        ax1.grid(True)
        ax1.set_xlim([x[0] - 0.5, x[-1] + 0.5])
        ax1.set_ylim([0, max_y])
        ax1.set_xlabel('Subcarrier')
        ax1.set_ylabel('Magnitude')
        ax1.set_title('Channel State Information')
        ax1.text(x[-1], max_y - (0.05 * max_y), 
                f'Packet #{cs+1} of {num_packets}',
                horizontalalignment='right', color=[0.75, 0.75, 0.75])
        
        # Plot phase
        ax2.clear()
        ax2.plot(x, csi_phase[cs, :])
        ax2.grid(True)
        ax2.set_xlim([x[0] - 0.5, x[-1] + 0.5])
        ax2.set_ylim([-180, 180])
        ax2.set_xlabel('Subcarrier')
        ax2.set_ylabel('Phase')
        
        # Plot heatmap
        ax3.clear()
        im = ax3.imshow(csi_mag, aspect='auto', extent=[x[0]-0.5, x[-1]+0.5, num_packets, 1])
        ax3.set_xlabel('Subcarrier')
        ax3.set_ylabel('Packet number')
        
        plt.tight_layout()
        
        print(f'Press any key to continue... (Packet {cs+1}/{num_packets})')
        plt.waitforbuttonpress()
    
    plt.close(fig)


def _plot_static(csi_mag, csi_phase, x, nfft):
    """
    Static mode: generates individual figures for each packet
    """
    max_y = np.max(csi_mag)
    num_packets = csi_mag.shape[0]
    
    for cs in range(num_packets):
        fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 10))
        
        # Plot magnitude
        ax1.plot(x, csi_mag[cs, :])
        ax1.grid(True)
        ax1.set_xlim([x[0] - 0.5, x[-1] + 0.5])
        ax1.set_ylim([0, max_y])
        ax1.set_xlabel('Subcarrier')
        ax1.set_ylabel('Magnitude')
        ax1.set_title('Channel State Information')
        ax1.text(x[-1], max_y - (0.05 * max_y), 
                f'Packet #{cs+1} of {num_packets}',
                horizontalalignment='right', color=[0.75, 0.75, 0.75])
        
        # Plot phase
        ax2.plot(x, csi_phase[cs, :])
        ax2.grid(True)
        ax2.set_xlim([x[0] - 0.5, x[-1] + 0.5])
        ax2.set_ylim([-180, 180])
        ax2.set_xlabel('Subcarrier')
        ax2.set_ylabel('Phase')
        
        # Plot heatmap
        im = ax3.imshow(csi_mag, aspect='auto', extent=[x[0]-0.5, x[-1]+0.5, num_packets, 1])
        ax3.set_xlabel('Subcarrier')
        ax3.set_ylabel('Packet number')
        
        plt.tight_layout()
        plt.show(block=False)
        plt.pause(0.1)


def _plot_consolidated(csi_mag, csi_phase, x, nfft, save_image=None):
    """
    Consolidated mode: shows overview first, then interactive packet-by-packet view
    Combines static overview with MATLAB-style interactive navigation
    """
    num_packets = csi_mag.shape[0]
    
    # ===== PART 1: Static Overview =====
    print("\n=== VISTA GENERAL ===")
    print("Mostrando resumen de todos los paquetes...")
    
    fig_overview = plt.figure(figsize=(10, 6))
    
    # Create 2 subplots in 1x2 layout
    ax1 = plt.subplot(1, 2, 1)  # Heatmap of amplitudes
    ax2 = plt.subplot(1, 2, 2)  # Mean amplitude with std
    
    # 1. Heatmap of amplitudes (time vs amplitude)
    im1 = ax1.imshow(csi_mag.T, aspect='auto', extent=[1, num_packets, x[-1]+0.5, x[0]-0.5], 
                     cmap='viridis')
    ax1.set_xlabel('Packet number (Time)')
    ax1.set_ylabel('Subcarrier Index')
    ax1.set_title('Amplitude Heatmap (Time vs Subcarriers)')
    plt.colorbar(im1, ax=ax1)
    
    # 2. Mean amplitude with standard deviation
    mean_mag = np.mean(csi_mag, axis=0)
    std_mag = np.std(csi_mag, axis=0)
    ax2.plot(x, mean_mag, 'b-', linewidth=2, label='Mean')
    ax2.fill_between(x, mean_mag - std_mag, mean_mag + std_mag, 
                      alpha=0.3, label='± 1 std')
    ax2.grid(True, alpha=0.3)
    ax2.set_xlim([x[0] - 0.5, x[-1] + 0.5])
    ax2.set_xlabel('Subcarrier Index')
    ax2.set_ylabel('Magnitude')
    ax2.set_title('Mean Amplitude with Std Deviation')
    ax2.legend()
    
    plt.tight_layout()
    
    # Save image if path is provided
    if save_image:
        plt.savefig(save_image, dpi=300, bbox_inches='tight')
        print(f"Vista consolidada guardada como: {save_image}")
    
    plt.show(block=True)
    
    # ===== PART 2: Interactive packet-by-packet view (MATLAB style) =====
    print("\n=== VISTA INTERACTIVA ===")
    print("Navegando por cada paquete individualmente...")
    print("Presiona cualquier tecla para avanzar, 'q' o ESC para salir.\n")
    
    fig_interactive = plt.figure(figsize=(12, 9))
    
    # Connect keyboard event handler
    def on_key(event):
        if event.key in ['q', 'escape']:
            plt.close(fig_interactive)
    
    fig_interactive.canvas.mpl_connect('key_press_event', on_key)
    
    max_y = np.max(csi_mag)
    
    for cs in range(num_packets):
        # Check if figure was closed
        if not plt.fignum_exists(fig_interactive.number):
            print("\n¡Visualización cancelada por el usuario!")
            break
        
        # Clear all subplots
        fig_interactive.clf()
        
        # Magnitude with all packets overlaid (highlighting current)
        ax1 = plt.subplot(3, 1, 1)
        for i in range(num_packets):
            if i == cs:
                ax1.plot(x, csi_mag[i, :], 'b-', linewidth=2, label=f'Packet #{cs+1}')
            else:
                ax1.plot(x, csi_mag[i, :], 'gray', alpha=0.15, linewidth=0.5)
        ax1.grid(True)
        ax1.set_xlim([x[0] - 0.5, x[-1] + 0.5])
        ax1.set_ylim([0, max_y])
        ax1.set_xlabel('Subcarrier')
        ax1.set_ylabel('Magnitude')
        ax1.set_title('Channel State Information - Magnitude [Presiona Q o ESC para salir]')
        ax1.legend(loc='upper right')
        ax1.text(x[-1], max_y - (0.05 * max_y), 
                f'Packet #{cs+1} of {num_packets}',
                horizontalalignment='right', color=[0.5, 0.5, 0.5])
        
        # Phase with all packets overlaid (highlighting current)
        ax2 = plt.subplot(3, 1, 2)
        for i in range(num_packets):
            if i == cs:
                ax2.plot(x, csi_phase[i, :], 'r-', linewidth=2, label=f'Packet #{cs+1}')
            else:
                ax2.plot(x, csi_phase[i, :], 'gray', alpha=0.15, linewidth=0.5)
        ax2.grid(True)
        ax2.set_xlim([x[0] - 0.5, x[-1] + 0.5])
        ax2.set_ylim([-180, 180])
        ax2.set_xlabel('Subcarrier')
        ax2.set_ylabel('Phase (degrees)')
        ax2.set_title('Channel State Information - Phase')
        ax2.legend(loc='upper right')
        
        # Heatmap showing position
        ax3 = plt.subplot(3, 1, 3)
        im = ax3.imshow(csi_mag, aspect='auto', extent=[x[0]-0.5, x[-1]+0.5, num_packets, 1],
                        cmap='viridis')
        # Highlight current packet
        ax3.axhline(y=cs+1, color='red', linewidth=2, linestyle='--', alpha=0.7)
        ax3.set_xlabel('Subcarrier')
        ax3.set_ylabel('Packet number')
        ax3.set_title('Amplitude Heatmap (current packet highlighted)')
        
        plt.tight_layout()
        
        print(f'Mostrando paquete {cs+1}/{num_packets}... (Presiona Q o ESC para salir)')
        
        # Wait for button press
        result = plt.waitforbuttonpress()
        
        # Check if window was closed
        if not plt.fignum_exists(fig_interactive.number):
            print("\n¡Visualización cancelada por el usuario!")
            break
    
    # Close figure if still open
    if plt.fignum_exists(fig_interactive.number):
        plt.close(fig_interactive)
        print("\n¡Visualización completada!")
    else:
        print("Fin de la sesión interactiva.")

