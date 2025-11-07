"""
csireader_difference.py

Lector específico para BCM4366C0 con preprocesado de diferencia:
- Solo procesa archivos 1x4
- Calcula la diferencia de magnitudes de cores 1, 2, 3 respecto al core 0
- Genera visualización comparativa: arriba heatmaps originales, abajo diferencias
- Detecta automáticamente el bandwidth desde el nombre del archivo

Configuración en este archivo (sin CLI).
"""

import numpy as np
import struct
import os
import glob
import re
import matplotlib.pyplot as plt

from readpcap import ReadPcap
from unpack_float import unpack_float


def _get_valid_subcarriers(bw: int) -> list:
    """
    Devuelve los índices de subportadoras válidas según el estándar WiFi,
    eliminando DC, bandas de guarda y portadoras piloto.
    
    Parameters:
    -----------
    bw : int
        Ancho de banda en MHz (20, 40, 80)
    
    Returns:
    --------
    list : Índices de subportadoras válidas centrados en 0 (sin DC, guard, ni pilot)
    """
    # Portadoras piloto según IEEE 802.11n/ac
    PILOT_SUBCARRIERS = {
        20: [-21, -7, 7, 21],
        40: [-53, -25, -11, 11, 25, 53],
        80: [-103, -75, -39, -11, 11, 39, 75, 103]
    }
    
    VALID_SUBCARRIERS = {
        20: list(range(-26, 0)) + list(range(1, 27)),      # 52 subportadoras
        40: list(range(-58, -1)) + list(range(2, 59)),     # 114 subportadoras
        80: list(range(-122, -1)) + list(range(2, 123))    # 242 subportadoras
    }
    
    # Obtener rango válido
    valid_all = VALID_SUBCARRIERS.get(bw, [])
    
    # Eliminar portadoras piloto
    pilot_tones = PILOT_SUBCARRIERS.get(bw, [])
    valid_no_pilot = [sc for sc in valid_all if sc not in pilot_tones]
    
    return valid_no_pilot


def _fftshift_and_abs(csi_matrix: np.ndarray, bw: int) -> tuple:
    """
    Aplica fftshift por columnas, filtra subportadoras válidas y devuelve la magnitud absoluta.
    
    Parameters:
    -----------
    csi_matrix : np.ndarray
        Matriz CSI compleja (num_packets, nfft)
    bw : int
        Ancho de banda en MHz para determinar subportadoras válidas
    
    Returns:
    --------
    tuple : (magnitud_filtrada, índices_subportadoras_válidas)
    """
    if csi_matrix.size == 0:
        return csi_matrix, []
    
    nfft = csi_matrix.shape[1]
    shifted = np.fft.fftshift(csi_matrix, axes=1)
    
    # Obtener índices de subportadoras válidas
    valid_subcarriers = _get_valid_subcarriers(bw)
    if not valid_subcarriers:
        # Si no hay definición, usar todas
        return np.abs(shifted), list(range(-nfft//2, nfft//2))
    
    # Convertir índices centrados en 0 a índices de array
    valid_indices = [idx + nfft//2 for idx in valid_subcarriers]
    
    # Filtrar solo subportadoras válidas
    shifted_filtered = shifted[:, valid_indices]
    
    return np.abs(shifted_filtered), valid_subcarriers


def _normalize_per_packet(mag_matrix: np.ndarray) -> np.ndarray:
    """
    Normaliza cada fila (paquete) por su máximo, evitando división por cero.
    """
    if mag_matrix.size == 0:
        return mag_matrix
    out = mag_matrix.copy()
    for i in range(out.shape[0]):
        max_val = np.max(out[i, :])
        if max_val > 0:
            out[i, :] = out[i, :] / max_val
    return out


def _find_magic_offset(payload_bytes: bytes, search_window: int = 128) -> int:
    """
    Busca el magic antiguo 0x11111111 (uint32 little-endian) en los primeros bytes del payload.
    Devuelve el offset en bytes donde se encontró, o 0 si no se encuentra.
    """
    max_off = min(len(payload_bytes) - 4, search_window)
    for off in range(max_off):
        word = struct.unpack_from('<I', payload_bytes, off)[0]
        if word == 0x11111111:
            return off
    return 0


def _parse_core_ss_from_old_header(payload_bytes: bytes, magic_off: int) -> tuple:
    """
    Extrae (core, spatial_stream, chanspec, seq_counter) del header antiguo Nexmon.
    
    Basado en hex dump real y tu información:
    - Magic (4 bytes): 0x11111111
    - Campos fijos (8 bytes): 3c 37 86 24 52 63 60 29
    - Sequence Counter (2 bytes): 20 7a (0x7a20) - constante entre paquetes
    - CSI Config (2 bytes): 00 00 / 00 01 -> core = csiconf & 0x7, ss = (csiconf >> 3) & 0x7
    - Chanspec (2 bytes): 24 d0
    """
    if magic_off + 16 > len(payload_bytes):
        return None, None, None, None
    
    # Sequence Counter está en offset 10-11 (bytes 10-11 tras magic)
    seq_off = magic_off + 10
    seq_counter = struct.unpack_from('>H', payload_bytes, seq_off)[0]  # Big-endian
    
    # CSI Config está en offset 12-13 (bytes 12-13 tras magic)
    csiconf_off = magic_off + 12
    csiconf = struct.unpack_from('>H', payload_bytes, csiconf_off)[0]  # Big-endian
    
    # Chanspec está en offset 14-15 (bytes 14-15 tras magic)
    chanspec_off = magic_off + 14
    chanspec = struct.unpack_from('>H', payload_bytes, chanspec_off)[0]  # Big-endian
    
    # csiconf es directamente el valor del Core
    core = csiconf        # El valor directo es el Core
    ss = 0               # Spatial Stream siempre es 0
    
    # Validar que core y ss estén en rango válido
    if 0 <= core <= 3 and 0 <= ss <= 3:
        return core, ss, chanspec, seq_counter
    
    return None, None, None, None


def _detect_bandwidth_from_filename(filename: str) -> int:
    """
    Detecta el bandwidth desde el nombre del archivo.
    
    Parameters:
    -----------
    filename : str
        Nombre del archivo (.pcap)
    
    Returns:
    --------
    int : Bandwidth en MHz (20, 40, 80) o None si no se detecta
    """
    # Buscar patrones de bandwidth (case-insensitive)
    pattern_20 = re.search(r'20[mM][hH][zZ]', filename)
    pattern_40 = re.search(r'40[mM][hH][zZ]', filename)
    pattern_80 = re.search(r'80[mM][hH][zZ]', filename)
    
    if pattern_80:
        return 80
    elif pattern_40:
        return 40
    elif pattern_20:
        return 20
    
    return None


def _calculate_core_differences(groups: dict, bw: int, method: str = 'normalized') -> tuple:
    """
    Calcula las diferencias de magnitudes de cores 1, 2, 3 respecto al core 0.
    Implementa múltiples métodos de diferencia para mejorar la detección de actividades.
    
    Parameters:
    -----------
    groups : dict[(core, ss)] -> np.ndarray
        Datos CSI complejos agrupados por (core, ss)
    bw : int
        Ancho de banda en MHz
    method : str
        Método de diferencia a aplicar:
        - 'normalized': Diferencia normalizada (mag_N - mag_0) / (mag_N + mag_0 + eps)
        - 'simple': Diferencia simple mag_N - mag_0
        - 'absolute': Valor absoluto de la diferencia |mag_N - mag_0|
        - 'relative': Diferencia relativa (mag_N - mag_0) / mag_0
    
    Returns:
    --------
    tuple : (originales, diferencias)
        - originales: dict con magnitudes originales para todos los cores
        - diferencias: dict con diferencias de cores 1, 2, 3 respecto a core 0
    """
    # Verificar que tenemos core 0
    if (0, 0) not in groups:
        print('Error: No se encontró core 0 en los datos')
        return {}, {}
    
    # Procesar magnitudes para todos los cores
    original_mag = {}
    for (core, ss), data in groups.items():
        if data.size > 0:
            mag, _ = _fftshift_and_abs(data, bw)
            original_mag[core] = mag
    
    # Verificar que tenemos cores 0, 1, 2, 3
    required_cores = [0, 1, 2, 3]
    for core in required_cores:
        if core not in original_mag:
            print(f'Advertencia: No se encontró core {core} en los datos')
    
    if 0 not in original_mag:
        return {}, {}
    
    # Calcular diferencias para cores 1, 2, 3
    diff_mag = {}
    eps = 1e-8  # Pequeño valor para evitar división por cero
    
    # Core 0 sin diferencia (mantener original)
    diff_mag[0] = original_mag[0].copy()
    
    # Calcular diferencias según el método seleccionado
    for core in [1, 2, 3]:
        if core in original_mag and 0 in original_mag:
            # Asegurar que tienen el mismo número de paquetes
            min_packets = min(original_mag[core].shape[0], original_mag[0].shape[0])
            mag_N = original_mag[core][:min_packets, :]
            mag_0 = original_mag[0][:min_packets, :]
            
            if method == 'normalized':
                # Diferencia normalizada: (mag_N - mag_0) / (mag_N + mag_0 + eps)
                diff = (mag_N - mag_0) / (mag_N + mag_0 + eps)
            elif method == 'absolute':
                # Valor absoluto de la diferencia
                diff = np.abs(mag_N - mag_0)
            elif method == 'relative':
                # Diferencia relativa: (mag_N - mag_0) / (mag_0 + eps)
                diff = (mag_N - mag_0) / (mag_0 + eps)
            else:  # 'simple'
                # Diferencia simple
                diff = mag_N - mag_0
            
            diff_mag[core] = diff
        else:
            print(f'Advertencia: No se pudo calcular diferencia para core {core}')
    
    return original_mag, diff_mag


def _plot_difference_comparison(original_data: dict, diff_data: dict, bw: int, 
                                 normalize: bool, activity_name: str, output_path: str,
                                 method: str = 'normalized'):
    """
    Visualiza comparación entre datos originales y diferencias calculadas.
    
    Parameters:
    -----------
    original_data : dict[core] -> np.ndarray
        Magnitudes originales por core
    diff_data : dict[core] -> np.ndarray
        Diferencias de magnitudes por core
    bw : int
        Ancho de banda en MHz
    normalize : bool
        Si normalizar las magnitudes
    activity_name : str
        Nombre de la actividad
    output_path : str
        Ruta donde guardar la imagen
    method : str
        Método de diferencia usado ('normalized', 'simple', 'absolute', 'relative')
    """
    if not original_data and not diff_data:
        print('No hay datos para visualizar.')
        return
    
    # Obtener subportadoras válidas
    valid_subcarriers = _get_valid_subcarriers(bw)
    x = np.array(valid_subcarriers)
    
    # Normalizar si es necesario
    if normalize:
        for core in original_data.keys():
            if original_data[core].size > 0:
                original_data[core] = _normalize_per_packet(original_data[core])
        for core in diff_data.keys():
            if diff_data[core].size > 0:
                diff_data[core] = _normalize_per_packet(diff_data[core])
    
    # Layout: 2 filas × 4 columnas
    fig = plt.figure(figsize=(20, 10))
    
    # Fila 1: Originales (cores 0, 1, 2, 3)
    for col_idx in range(4):
        ax = plt.subplot(2, 4, col_idx + 1)
        core = col_idx
        
        if core in original_data and original_data[core].size > 0:
            mag = original_data[core]
            im = ax.imshow(mag.T, aspect='auto', extent=[1, mag.shape[0], x[-1] + 0.5, x[0] - 0.5], 
                          cmap='jet')
            ax.set_title(f'Core {core} - Original')
            ax.set_xlabel('Packet number')
            ax.set_ylabel('Subcarrier Index')
            plt.colorbar(im, ax=ax)
        else:
            ax.text(0.5, 0.5, f'No data for Core {core}', 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title(f'Core {core} - Original (No data)')
    
    # Fila 2: Diferencias (core 0 repetido, cores 1, 2, 3 diferenciados)
    # Columna 0: Core 0 original
    ax = plt.subplot(2, 4, 5)
    if 0 in original_data and original_data[0].size > 0:
        mag = original_data[0]
        im = ax.imshow(mag.T, aspect='auto', extent=[1, mag.shape[0], x[-1] + 0.5, x[0] - 0.5], 
                      cmap='jet')
        ax.set_title('Core 0 - Reference')
        ax.set_xlabel('Packet number')
        ax.set_ylabel('Subcarrier Index')
        plt.colorbar(im, ax=ax)
    else:
        ax.text(0.5, 0.5, 'No data for Core 0', 
               ha='center', va='center', transform=ax.transAxes)
        ax.set_title('Core 0 - Reference (No data)')
    
    # Columnas 1-3: Diferencias de cores 1, 2, 3
    for col_idx in range(1, 4):
        ax = plt.subplot(2, 4, col_idx + 5)
        core = col_idx
        
        if core in diff_data and diff_data[core].size > 0:
            mag = diff_data[core]
            im = ax.imshow(mag.T, aspect='auto', extent=[1, mag.shape[0], x[-1] + 0.5, x[0] - 0.5], 
                          cmap='jet')
            ax.set_title(f'Core {core} - Difference')
            ax.set_xlabel('Packet number')
            ax.set_ylabel('Subcarrier Index')
            plt.colorbar(im, ax=ax)
        else:
            ax.text(0.5, 0.5, f'No diff data for Core {core}', 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title(f'Core {core} - Difference (No data)')
    
    # Añadir información del método en el título
    method_names = {
        'normalized': 'Normalized',
        'absolute': 'Absolute',
        'relative': 'Relative',
        'simple': 'Simple'
    }
    method_name = method_names.get(method, method)
    
    plt.suptitle(f'{activity_name} - Core Difference Analysis ({bw}MHz) - Method: {method_name}', 
                 fontsize=16, y=0.995)
    plt.tight_layout(rect=[0, 0, 1, 0.98])
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f'Imagen guardada: {output_path}')
    plt.close(fig)


def _process_file_for_batch(file_path: str, chip: str, bw: int, nfft: int, hoffset: int, 
                             npkts_max: int) -> dict:
    """
    Procesa un archivo .pcap y devuelve los datos CSI agrupados por (core, ss).
    
    Returns:
    --------
    dict[(core, ss)] -> np.ndarray complejo de forma (num_packets, nfft)
    """
    groups = {}
    
    p = ReadPcap()
    p.open(file_path)
    all_frames = p.all()
    n = min(len(all_frames), npkts_max)
    
    p.from_start()
    processed = 0
    
    for _ in range(n):
        f = p.next()
        if f is None:
            break
        
        payload = f['payload']
        
        try:
            payload_bytes = payload.tobytes()
        except Exception:
            payload_bytes = bytes(payload)
        
        magic_off = _find_magic_offset(payload_bytes)
        core, ss, chanspec, seq_counter = _parse_core_ss_from_old_header(payload_bytes, magic_off)
        
        if core is None or ss is None:
            continue
        
        # Calcular offset real del CSI
        if magic_off > 0:
            csi_offset_words = magic_off // 4 + 4
        else:
            csi_offset_words = hoffset
        
        # Verificar datos suficientes
        if csi_offset_words + nfft > len(payload):
            continue
        
        # Extraer CSI
        H = payload[csi_offset_words:csi_offset_words + nfft]
        if len(H) < nfft:
            continue
        
        # Decodificación bcm4366c0 (formato 1)
        Hout = unpack_float(1, nfft, H)
        Hout = Hout.reshape(2, -1, order='F')
        cmplx = Hout[0, :nfft].astype(np.float64) + 1j * Hout[1, :nfft].astype(np.float64)
        
        key = (core, ss)
        if key not in groups:
            groups[key] = []
        groups[key].append(cmplx)
        processed += 1
    
    p.close()
    
    # Convertir listas a matrices por grupo
    for key in list(groups.keys()):
        arr = np.vstack(groups[key]) if len(groups[key]) > 0 else np.empty((0, nfft), dtype=np.complex128)
        groups[key] = arr
    
    return groups


def _process_batch_difference(pcap_folder: str, output_folder: str, chip: str, 
                               npkts_max: int, normalize: bool, method: str = 'normalized'):
    """
    Procesa múltiples archivos .pcap 1x4 y crea comparaciones con diferencias.
    Detecta automáticamente el bandwidth desde el nombre de cada archivo.
    
    Parameters:
    -----------
    method : str
        Método de diferencia a usar ('normalized', 'simple', 'absolute', 'relative')
    """
    # Mapeo de actividades
    ACTIVITY_NAMES = {
        'E': 'Empty',
        'J': 'Jumping',
        'S': 'Sitting',
        'W': 'Walking'
    }
    
    # Crear directorio de salida
    output_dir = os.path.join('csireader_image', output_folder)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f'Creado directorio: {output_dir}')
    
    # Buscar solo archivos 1x4
    pcap_pattern = os.path.join(pcap_folder, '*1x4*.pcap')
    pcap_files = glob.glob(pcap_pattern)
    
    if not pcap_files:
        print(f'No se encontraron archivos .pcap 1x4 en {pcap_folder}')
        return
    
    # Agrupar archivos por actividad y bandwidth
    activity_groups = {}
    for file_path in pcap_files:
        filename = os.path.basename(file_path)
        
        # Obtener código de actividad
        activity_code = filename[0] if len(filename) > 0 else 'Unknown'
        activity_name = ACTIVITY_NAMES.get(activity_code, 'Unknown')
        
        # Detectar bandwidth automáticamente
        bw = _detect_bandwidth_from_filename(filename)
        if bw is None:
            print(f'No se pudo detectar BW para: {filename}')
            continue
        
        # Inicializar estructura si es necesario
        if activity_name not in activity_groups:
            activity_groups[activity_name] = {}
        
        if bw not in activity_groups[activity_name]:
            activity_groups[activity_name][bw] = []
        
        activity_groups[activity_name][bw].append(file_path)
    
    print(f'Grupos de actividad encontrados: {len(activity_groups)}')
    
    # Procesar cada actividad y bandwidth
    hoffset = 16
    
    for activity_name, bw_dict in activity_groups.items():
        for bw, files in bw_dict.items():
            nfft = int(bw * 3.2)
            
            print(f'\n{"="*60}')
            print(f'Procesando: {activity_name} ({bw}MHz)')
            print(f'{"="*60}')
            
            # Procesar cada archivo del grupo
            for file_path in files:
                filename = os.path.basename(file_path)
                print(f'  Procesando: {filename}')
                
                # Ajustar npkts_max para 1x4 (multiplicar por 4 para igualar duración temporal)
                # NPKTS_MAX es la base para 1x1, pero en 1x4 necesitamos x4 más paquetes
                # para igualar el tiempo por core
                npkts_adjusted = npkts_max * 4
                print(f'    Ajustando NPKTS_MAX: {npkts_max} -> {npkts_adjusted} (1x4 = 4 cores/paquete, x4 para igualar tiempo)')
                
                # Procesar archivo
                groups = _process_file_for_batch(file_path, chip, bw, nfft, hoffset, npkts_adjusted)
                print(f'    Cores detectados: {sorted(set([k[0] for k in groups.keys()]))}')
                
                # Calcular diferencias
                original_mag, diff_mag = _calculate_core_differences(groups, bw, method)
                
                # Crear visualización
                output_filename = f'{activity_name}_{bw}MHz_difference.png'
                output_path = os.path.join(output_dir, output_filename)
                
                _plot_difference_comparison(original_mag, diff_mag, bw, normalize, 
                                          activity_name, output_path, method)
    
    print(f'\n{"="*60}')
    print(f'Procesamiento por lotes completado!')
    print(f'Imágenes guardadas en: {output_dir}')
    print(f'{"="*60}')


def main():
    """
    Lógica principal para procesar archivos 1x4 con cálculo de diferencias.
    """
    # ========== CONFIGURACIÓN ==========
    CHIP = '4366c0'           # fijo: este script es específico para bcm4366c0
    FILE = './J_noBF_20Mhz_1x4_M1_1Mo_A2.pcap'   # ruta al .pcap (solo 1x4)
    NPKTS_MAX = 4000         # límite de paquetes a procesar
    NORMALIZE = True          # normalizar magnitud por paquete
    SAVE_PNG = False          # guardar figura a PNG (True/False)
    OUTPUT_PATH = './csireader_image/difference_output.png'  # ruta de salida si SAVE_PNG=True
    
    # Modo batch (comparación por lotes)
    BATCH_MODE = True         # True para procesar múltiples archivos y crear comparaciones
    PCAP_FOLDER = './pcap_files/rewis_A2'  # carpeta con archivos .pcap
    OUTPUT_FOLDER = 'rewis_A2_difference_2'  # carpeta donde guardar imágenes
    
    # Método de diferencia: 'normalized', 'simple', 'absolute', 'relative'
    DIFFERENCE_METHOD = 'relative'  # Método recomendado
    
    # Override manual de BW si detección falla (None = detectar automáticamente)
    BW_OVERRIDE = None
    
    # ========== VALIDACIÓN ==========
    # Validar que el archivo es 1x4 (en modo individual)
    if not BATCH_MODE and '1x4' not in FILE:
        print('Error: Este script solo procesa archivos 1x4')
        print(f'El archivo especificado: {FILE}')
        return
    
    # Detectar bandwidth automáticamente
    if BATCH_MODE:
        # En modo batch, la detección se hace por archivo
        pass
    else:
        # En modo individual, detectar BW del archivo especificado
        filename = os.path.basename(FILE)
        BW = _detect_bandwidth_from_filename(filename)
        
        if BW is None:
            if BW_OVERRIDE is not None:
                BW = BW_OVERRIDE
                print(f'Usando bandwidth override: {BW}MHz')
            else:
                print('Error: No se pudo detectar el bandwidth desde el nombre del archivo')
                print(f'Archivo: {filename}')
                print('Especifica BW_OVERRIDE en la configuración o verifica el nombre del archivo')
                return
        else:
            print(f'Bandwidth detectado automáticamente: {BW}MHz')
    
    # Si está activado el modo batch, procesar por lotes
    if BATCH_MODE:
        _process_batch_difference(PCAP_FOLDER, OUTPUT_FOLDER, CHIP, NPKTS_MAX, NORMALIZE, DIFFERENCE_METHOD)
        return
    
    # ========== PROCESAMIENTO INDIVIDUAL ==========
    # Calcular NFFT
    NFFT = int(BW * 3.2)
    HOFFSET = 16
    
    print('CSI Difference Reader — BCM4366C0')
    print('=' * 60)
    print(f'Chip: {CHIP}')
    print(f'Bandwidth: {BW} MHz  -> NFFT={NFFT}')
    print(f'File: {FILE}')
    print(f'Max packets: {NPKTS_MAX}')
    print()
    
    # Procesar archivo
    groups = _process_file_for_batch(FILE, CHIP, BW, NFFT, HOFFSET, NPKTS_MAX)
    
    print('\nProcesamiento completado:')
    print(f'  Cores detectados: {sorted(set([k[0] for k in groups.keys()]))}')
    for key in sorted(groups.keys()):
        print(f'  Grupo (core={key[0]}, ss={key[1]}): {groups[key].shape[0]} paquetes')
    
    # Calcular diferencias
    original_mag, diff_mag = _calculate_core_differences(groups, BW, DIFFERENCE_METHOD)
    
    # Visualización
    activity_name = os.path.basename(FILE)[0]
    activity_map = {'E': 'Empty', 'J': 'Jumping', 'S': 'Sitting', 'W': 'Walking'}
    activity_name = activity_map.get(activity_name, 'Unknown')
    
    _plot_difference_comparison(original_mag, diff_mag, BW, NORMALIZE, activity_name, OUTPUT_PATH, DIFFERENCE_METHOD)
    
    if not SAVE_PNG:
        plt.show(block=True)


if __name__ == '__main__':
    main()

