#!/usr/bin/env python3
"""
Script para verificar que la eliminación de portadoras piloto y DC es correcta
en el procesamiento de datos CSI.

Este script:
1. Compara los rangos de subportadoras válidas con los estándares WiFi
2. Verifica que se eliminen correctamente DC y bandas de guarda
3. Analiza la distribución espectral de los datos CSI
4. Genera reportes de verificación
"""

import numpy as np
import matplotlib.pyplot as plt
from readpcap import ReadPcap
from unpack_float import unpack_float
import os

def get_wifi_standard_subcarriers():
    """
    Devuelve los rangos de subportadoras válidas según los estándares WiFi oficiales.
    
    Basado en IEEE 802.11n/ac:
    - 20MHz: 64 subportadoras totales, 52 válidas (excluyendo DC y guard bands)
    - 40MHz: 128 subportadoras totales, 108 válidas  
    - 80MHz: 256 subportadoras totales, 234 válidas
    
    Returns:
    --------
    dict: Diccionario con rangos válidos por ancho de banda
    """
    return {
        20: {
            'total': 64,
            'valid': list(range(-26, 0)) + list(range(1, 27)),  # 52 subportadoras
            'dc': 0,  # Índice DC
            'guard_left': list(range(-32, -26)),  # 6 subportadoras de guarda izquierda
            'guard_right': list(range(27, 32)),   # 5 subportadoras de guarda derecha
            'pilot': [-21, -7, 7, 21]  # Portadoras piloto en 20MHz
        },
        40: {
            'total': 128,
            'valid': list(range(-58, -1)) + list(range(2, 59)),  # 114 subportadoras
            'dc': 0,
            'guard_left': list(range(-64, -58)),  # 6 subportadoras de guarda izquierda
            'guard_right': list(range(59, 64)),   # 5 subportadoras de guarda derecha
            'pilot': [-53, -25, -11, 11, 25, 53]  # Portadoras piloto en 40MHz
        },
        80: {
            'total': 256,
            'valid': list(range(-122, -1)) + list(range(2, 123)),  # 242 subportadoras
            'dc': 0,
            'guard_left': list(range(-128, -122)),  # 6 subportadoras de guarda izquierda
            'guard_right': list(range(123, 128)),     # 5 subportadoras de guarda derecha
            'pilot': [-103, -75, -39, -11, 11, 39, 75, 103]  # Portadoras piloto en 80MHz
        }
    }

def get_current_implementation_subcarriers():
    """
    Devuelve los rangos de subportadoras válidas según la implementación actual.
    """
    return {
        20: list(range(-26, 0)) + list(range(1, 27)),      # 52 subportadoras
        40: list(range(-58, -1)) + list(range(2, 59)),     # 114 subportadoras  
        80: list(range(-122, -1)) + list(range(2, 123))    # 242 subportadoras
    }

def verify_subcarrier_ranges():
    """
    Verifica que los rangos de subportadoras válidas coincidan con los estándares WiFi.
    """
    print("=" * 60)
    print("VERIFICACIÓN DE RANGOS DE SUBPORTADORAS")
    print("=" * 60)
    
    wifi_standard = get_wifi_standard_subcarriers()
    current_impl = get_current_implementation_subcarriers()
    
    for bw in [20, 40, 80]:
        print(f"\nAncho de banda: {bw} MHz")
        print("-" * 30)
        
        standard_valid = set(wifi_standard[bw]['valid'])
        current_valid = set(current_impl[bw])
        
        # Verificar coincidencia
        if standard_valid == current_valid:
            print("✅ CORRECTO: Los rangos coinciden con el estándar WiFi")
        else:
            print("❌ ERROR: Los rangos NO coinciden con el estándar WiFi")
            missing = standard_valid - current_valid
            extra = current_valid - standard_valid
            if missing:
                print(f"   Faltan: {sorted(missing)}")
            if extra:
                print(f"   Sobran: {sorted(extra)}")
        
        # Estadísticas
        print(f"   Subportadoras válidas: {len(current_valid)}")
        print(f"   Total subportadoras: {wifi_standard[bw]['total']}")
        print(f"   Eliminadas: {wifi_standard[bw]['total'] - len(current_valid)}")
        
        # Verificar eliminación de DC
        if 0 not in current_valid:
            print("✅ DC eliminada correctamente")
        else:
            print("❌ ERROR: DC no eliminada")
        
        # Verificar eliminación de bandas de guarda
        guard_left = set(wifi_standard[bw]['guard_left'])
        guard_right = set(wifi_standard[bw]['guard_right'])
        guard_removed = (guard_left | guard_right) - current_valid
        
        if len(guard_removed) == len(guard_left) + len(guard_right):
            print("✅ Bandas de guarda eliminadas correctamente")
        else:
            print("❌ ERROR: Bandas de guarda no eliminadas completamente")
        
        # Verificar eliminación de portadoras piloto
        pilot_removed = set(wifi_standard[bw]['pilot']) - current_valid
        if len(pilot_removed) == len(wifi_standard[bw]['pilot']):
            print("✅ Portadoras piloto eliminadas correctamente")
        else:
            print("❌ ERROR: Portadoras piloto no eliminadas completamente")
            remaining_pilots = set(wifi_standard[bw]['pilot']) - pilot_removed
            print(f"   Pilotos restantes: {sorted(remaining_pilots)}")

def analyze_csi_spectral_distribution(file_path, chip='4366c0', bw=20, max_packets=100):
    """
    Analiza la distribución espectral de los datos CSI para verificar
    que la eliminación de DC y portadoras piloto es efectiva.
    """
    print("\n" + "=" * 60)
    print("ANÁLISIS DE DISTRIBUCIÓN ESPECTRAL CSI")
    print("=" * 60)
    
    # Configuración
    HOFFSET = 16
    NFFT = int(bw * 3.2)
    
    # Leer datos CSI
    p = ReadPcap()
    p.open(file_path)
    all_frames = p.all()
    n = min(len(all_frames), max_packets)
    
    print(f"Analizando {n} paquetes de {file_path}")
    print(f"NFFT: {NFFT}, Ancho de banda: {bw} MHz")
    
    # Buffer para CSI
    csi_buff = np.zeros((n, NFFT), dtype=np.complex128)
    
    p.from_start()
    processed = 0
    
    for i in range(n):
        f = p.next()
        if f is None:
            break
        
        payload = f['payload']
        H = payload[HOFFSET-1:HOFFSET-1 + NFFT]
        
        if len(H) < NFFT:
            continue
        
        # Decodificar CSI
        if chip == '4366c0':
            Hout = unpack_float(1, NFFT, H)
        elif chip == '4358':
            Hout = unpack_float(0, NFFT, H)
        else:
            Hout = H.view(np.int16)
        
        Hout = Hout.reshape(2, -1, order='F')
        cmplx = Hout[0, :NFFT].astype(np.float64) + 1j * Hout[1, :NFFT].astype(np.float64)
        
        csi_buff[processed, :] = cmplx
        processed += 1
    
    p.close()
    
    if processed == 0:
        print("❌ No se pudieron procesar paquetes")
        return
    
    # Recortar buffer
    csi_buff = csi_buff[:processed, :]
    
    # Aplicar fftshift
    csi_shifted = np.fft.fftshift(csi_buff, axes=1)
    
    # Obtener magnitudes
    csi_mag = np.abs(csi_shifted)
    
    # Análisis estadístico
    print(f"\nEstadísticas espectrales:")
    print(f"  Paquetes procesados: {processed}")
    print(f"  Media de magnitud: {np.mean(csi_mag):.6f}")
    print(f"  Desviación estándar: {np.std(csi_mag):.6f}")
    
    # Análisis específico de DC (índice NFFT//2 después de fftshift)
    dc_index = NFFT // 2
    dc_values = csi_mag[:, dc_index]
    print(f"\nAnálisis de DC (índice {dc_index}):")
    print(f"  Media DC: {np.mean(dc_values):.6f}")
    print(f"  Desviación DC: {np.std(dc_values):.6f}")
    print(f"  Máximo DC: {np.max(dc_values):.6f}")
    
    # Obtener subportadoras válidas según implementación actual
    current_impl = get_current_implementation_subcarriers()
    valid_indices = [idx + NFFT//2 for idx in current_impl[bw]]
    
    # Filtrar subportadoras válidas
    csi_valid = csi_mag[:, valid_indices]
    
    print(f"\nAnálisis de subportadoras válidas:")
    print(f"  Subportadoras válidas: {len(valid_indices)}")
    print(f"  Media magnitud válida: {np.mean(csi_valid):.6f}")
    print(f"  Desviación válida: {np.std(csi_valid):.6f}")
    
    # Comparar DC vs subportadoras válidas
    dc_mean = np.mean(dc_values)
    valid_mean = np.mean(csi_valid)
    
    print(f"\nComparación DC vs subportadoras válidas:")
    print(f"  Ratio DC/válidas: {dc_mean/valid_mean:.6f}")
    
    if dc_mean < valid_mean * 0.1:  # DC debería ser mucho menor
        print("✅ DC está suprimida correctamente")
    else:
        print("⚠️  ADVERTENCIA: DC podría no estar suprimida adecuadamente")
    
    return csi_mag, valid_indices

def create_verification_plot(csi_mag, valid_indices, bw, save_path=None):
    """
    Crea un gráfico de verificación mostrando la distribución espectral
    antes y después del filtrado.
    """
    NFFT = csi_mag.shape[1]
    
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle(f'Verificación de Eliminación de DC y Portadoras Piloto - {bw}MHz', fontsize=16)
    
    # 1. Espectro completo (media de todos los paquetes)
    ax1 = axes[0, 0]
    mean_spectrum = np.mean(csi_mag, axis=0)
    x_full = np.arange(-NFFT//2, NFFT//2)
    ax1.plot(x_full, mean_spectrum, 'b-', linewidth=1)
    ax1.axvline(x=0, color='r', linestyle='--', alpha=0.7, label='DC')
    ax1.set_title('Espectro Completo (Media)')
    ax1.set_xlabel('Índice de Subportadora')
    ax1.set_ylabel('Magnitud')
    ax1.grid(True, alpha=0.3)
    ax1.legend()
    
    # 2. Espectro filtrado (solo subportadoras válidas)
    ax2 = axes[0, 1]
    valid_spectrum = mean_spectrum[valid_indices]
    x_valid = np.array([idx - NFFT//2 for idx in valid_indices])
    ax2.plot(x_valid, valid_spectrum, 'g-', linewidth=1)
    ax2.set_title('Espectro Filtrado (Solo Válidas)')
    ax2.set_xlabel('Índice de Subportadora')
    ax2.set_ylabel('Magnitud')
    ax2.grid(True, alpha=0.3)
    
    # 3. Comparación DC vs subportadoras válidas
    ax3 = axes[1, 0]
    dc_index = NFFT // 2
    dc_values = csi_mag[:, dc_index]
    valid_values = csi_mag[:, valid_indices].flatten()
    
    ax3.hist(dc_values, bins=50, alpha=0.7, label='DC', color='red')
    ax3.hist(valid_values, bins=50, alpha=0.7, label='Válidas', color='green')
    ax3.set_title('Distribución de Magnitudes')
    ax3.set_xlabel('Magnitud')
    ax3.set_ylabel('Frecuencia')
    ax3.legend()
    ax3.grid(True, alpha=0.3)
    
    # 4. Heatmap de subportadoras válidas
    ax4 = axes[1, 1]
    valid_csi = csi_mag[:, valid_indices]
    im = ax4.imshow(valid_csi.T, aspect='auto', cmap='viridis')
    ax4.set_title('Heatmap Subportadoras Válidas')
    ax4.set_xlabel('Número de Paquete')
    ax4.set_ylabel('Índice de Subportadora')
    plt.colorbar(im, ax=ax4)
    
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Gráfico guardado: {save_path}")
    
    plt.show()

def main():
    """
    Función principal de verificación.
    """
    print("VERIFICADOR DE ELIMINACIÓN DE PORTADORAS PILOTO Y DC")
    print("=" * 60)
    
    # 1. Verificar rangos de subportadoras
    verify_subcarrier_ranges()
    
    # 2. Analizar distribución espectral (si hay archivos disponibles)
    pcap_files = [
        './pcap_files/rewis_A2/E_noBF_20Mhz_1x1_M1_1Mo_A2.pcap',
        './pcap_files/rewis_A2/J_noBF_80Mhz_1x1_M1_1Mo_A2.pcap',
        './example.pcap'
    ]
    
    for file_path in pcap_files:
        if os.path.exists(file_path):
            print(f"\nAnalizando archivo: {file_path}")
            try:
                # Determinar ancho de banda del nombre del archivo
                if '20Mhz' in file_path:
                    bw = 20
                elif '80Mhz' in file_path:
                    bw = 80
                else:
                    bw = 20  # Default
                
                csi_mag, valid_indices = analyze_csi_spectral_distribution(
                    file_path, chip='4366c0', bw=bw, max_packets=50
                )
                
                if csi_mag is not None:
                    # Crear gráfico de verificación
                    output_path = f'verification_{bw}MHz.png'
                    create_verification_plot(csi_mag, valid_indices, bw, output_path)
                
            except Exception as e:
                print(f"❌ Error analizando {file_path}: {e}")
            break  # Solo analizar el primer archivo disponible
    
    print("\n" + "=" * 60)
    print("VERIFICACIÓN COMPLETADA")
    print("=" * 60)

if __name__ == '__main__':
    main()

