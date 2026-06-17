"""
csireader_bcm4366c0.py

Lector específico para BCM4366C0 con formato antiguo (magic 0x11111111, header clásico):
- Decodifica CSI usando unpack_float(format=1)
- Agrupa por (core, spatial stream) detectados en el header antiguo
- Genera una figura con, por cada (core,SS), dos subgráficos apilados:
  arriba: heatmap de amplitudes (azul→rojo), abajo: media de amplitud con banda ±1 std

Configuración en este archivo (sin CLI).
"""

import numpy as np
import struct
import os
import glob
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


def _plot_groups(groups, nfft: int, bw: int, normalize: bool, save_png: bool, output_path: str):
    """
    Dibuja una figura con un bloque por cada (core, ss):
      - Arriba: heatmap de amplitud (tiempo vs subportadoras)
      - Abajo: media de amplitud
    groups: dict[(core, ss)] -> np.ndarray de forma (num_packets, nfft) complejo
    bw: Ancho de banda en MHz para filtrar subportadoras válidas
    """
    if not groups:
        print('No hay datos para visualizar.')
        return

    # Orden estable por (core, ss)
    keys = sorted(groups.keys())
    num_groups = len(keys)

    # Construimos figura: 2 filas por grupo, 2 columnas por grupo
    # Layout: cada grupo tiene 2 subplots apilados verticalmente
    fig_height = max(8, 3 * num_groups)
    fig = plt.figure(figsize=(16, fig_height))

    for g_idx, (core, ss) in enumerate(keys):
        data = groups[(core, ss)]  # (num_packets, nfft) complejo
        if data.size == 0:
            continue

        mag, valid_subcarriers = _fftshift_and_abs(data, bw)
        if normalize:
            mag = _normalize_per_packet(mag)

        num_packets = mag.shape[0]
        x = np.array(valid_subcarriers)  # subportadoras válidas centradas en 0

        # Heatmap (arriba) - subplot en posición (g_idx, 0) de un grid de num_groups x 2
        ax1 = plt.subplot(num_groups, 2, g_idx * 2 + 1)
        im = ax1.imshow(
            mag.T,
            aspect='auto',
            extent=[1, num_packets, x[-1] + 0.5, x[0] - 0.5],
            cmap='jet'
        )
        ax1.set_title(f'Core {core} — SS {ss} | Amplitude Heatmap ({len(valid_subcarriers)} subcarriers)')
        ax1.set_xlabel('Packet number (Time)')
        ax1.set_ylabel('Subcarrier Index')
        plt.colorbar(im, ax=ax1)

        # Media de amplitud (abajo) - subplot en posición (g_idx, 1) de un grid de num_groups x 2
        ax2 = plt.subplot(num_groups, 2, g_idx * 2 + 2)
        mean_mag = np.mean(mag, axis=0)
        ax2.plot(x, mean_mag, 'b-', linewidth=2, label='Mean')
        ax2.grid(True, alpha=0.3)
        ax2.set_xlim([x[0] - 0.5, x[-1] + 0.5])
        ax2.set_xlabel('Subcarrier Index')
        ax2.set_ylabel('Magnitude')
        ax2.set_title(f'Mean Amplitude ({len(valid_subcarriers)} valid subcarriers)')
        ax2.legend()

    plt.tight_layout()

    if save_png:
        out = output_path if output_path else 'csi_cores_4366c0.png'
        plt.savefig(out, dpi=300, bbox_inches='tight')
        print(f'Imagen guardada: {out}')
        plt.close(fig)
    else:
        plt.show(block=True)


def _plot_core_comparison(config_1x1_data, config_1x4_data, bw: int, normalize: bool, 
                          activity_name: str, output_path: str):
    """
    Crea visualización comparativa entre configuraciones 1x1 y 1x4 para una misma actividad.
    
    Parameters:
    -----------
    config_1x1_data : dict[(core, ss)] -> np.ndarray
        Datos CSI de configuración 1x1, agrupados por (core, ss)
    config_1x4_data : dict[(core, ss)] -> np.ndarray  
        Datos CSI de configuración 1x4, agrupados por (core, ss)
    bw : int
        Ancho de banda en MHz
    normalize : bool
        Si normalizar las magnitudes
    activity_name : str
        Nombre de la actividad (Empty, Jumping, Sitting, Walking)
    output_path : str
        Ruta donde guardar la imagen
    """
    valid_subcarriers = _get_valid_subcarriers(bw)
    x = np.array(valid_subcarriers)
    
    # Configurar layout: 2 filas (heatmaps arriba, mean comparison abajo)
    # Columnas: 1 para 1x1, 4 para 1x4 = 5 total
    num_cols = 5  # 1x1 tiene 1 core, 1x4 tiene 4 cores
    fig = plt.figure(figsize=(20, 10))
    
    # Procesar config 1x1 (solo Core 0)
    config_1x1_processed = {}
    if config_1x1_data:
        for (core, ss), data in config_1x1_data.items():
            mag, _ = _fftshift_and_abs(data, bw)
            if normalize:
                mag = _normalize_per_packet(mag)
            config_1x1_processed[(core, ss)] = mag
    
    # Procesar config 1x4 (Cores 0, 1, 2, 3)
    config_1x4_processed = {}
    if config_1x4_data:
        for (core, ss), data in config_1x4_data.items():
            mag, _ = _fftshift_and_abs(data, bw)
            if normalize:
                mag = _normalize_per_packet(mag)
            config_1x4_processed[(core, ss)] = mag
    
    # Filas 1: Heatmaps
    # Ordenar cores para visualización consistente
    cores_1x1 = sorted([c for (c, ss) in config_1x1_processed.keys()]) if config_1x1_processed else []
    cores_1x4 = sorted([c for (c, ss) in config_1x4_processed.keys()]) if config_1x4_processed else []
    
    # Columna 0: Config 1x1
    ax = plt.subplot(2, num_cols, 1)
    if cores_1x1 and config_1x1_processed:
        core_0 = cores_1x1[0]  # Tomar el primer core de 1x1
        for (c, ss), mag in config_1x1_processed.items():
            if c == core_0:
                im = ax.imshow(mag.T, aspect='auto', extent=[1, mag.shape[0], x[-1] + 0.5, x[0] - 0.5], 
                               cmap='jet')
                ax.set_title(f'Core {core_0} - 1x1')
                ax.set_xlabel('Packet number (Time)')
                ax.set_ylabel('Subcarrier Index')
                plt.colorbar(im, ax=ax)
                break
    else:
        ax.text(0.5, 0.5, 'No 1x1 data', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('1x1 (No data)')
    
    # Columnas 1-4: Config 1x4 para cores 0, 1, 2, 3
    for col_idx in range(1, num_cols):
        core = col_idx - 1
        ax = plt.subplot(2, num_cols, col_idx + 1)
        
        # Buscar datos para este core en 1x4
        found = False
        if config_1x4_processed:
            for (c, ss), mag in config_1x4_processed.items():
                if c == core:
                    im = ax.imshow(mag.T, aspect='auto', extent=[1, mag.shape[0], x[-1] + 0.5, x[0] - 0.5], 
                                   cmap='jet')
                    ax.set_title(f'Core {core} - 1x4')
                    ax.set_xlabel('Packet number (Time)')
                    ax.set_ylabel('Subcarrier Index')
                    plt.colorbar(im, ax=ax)
                    found = True
                    break
        
        if not found:
            ax.text(0.5, 0.5, f'No data for Core {core}', 
                    ha='center', va='center', transform=ax.transAxes)
            ax.set_title(f'Core {core} - 1x4 (No data)')
    
    # Fila 2: Mean Amplitude Comparison
    ax_mean = plt.subplot(2, 1, 2)
    
    colors = ['blue', 'red', 'green', 'orange', 'purple']
    color_idx = 0
    
    # Plot config 1x1
    if config_1x1_processed:
        for (core, ss), mag in config_1x1_processed.items():
            mean_mag = np.mean(mag, axis=0)
            ax_mean.plot(x, mean_mag, color=colors[color_idx], linewidth=2, 
                        label=f'Core {core} - 1x1', linestyle='-')
            color_idx += 1
    
    # Plot config 1x4
    for core in range(4):  # Cores 0, 1, 2, 3
        for (c, ss), mag in config_1x4_processed.items():
            if c == core:
                mean_mag = np.mean(mag, axis=0)
                ax_mean.plot(x, mean_mag, color=colors[color_idx], linewidth=2, 
                            label=f'Core {core} - 1x4', linestyle='--')
                color_idx += 1
    
    ax_mean.grid(True, alpha=0.3)
    ax_mean.set_xlim([x[0] - 0.5, x[-1] + 0.5])
    ax_mean.set_xlabel('Subcarrier Index')
    ax_mean.set_ylabel('Mean Magnitude')
    ax_mean.set_title(f'{activity_name} - Mean Amplitude Comparison ({bw}MHz)')
    ax_mean.legend(loc='best', fontsize=8)
    
    plt.tight_layout()
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


def _adjust_npkts_max_for_config(filename: str, npkts_max: int) -> int:
    """
    Ajusta npkts_max según la configuración del archivo (1x1 o 1x4).
    
    En configuración 1x4, cada paquete contiene 4 cores distribuidos.
    Para tener la MISMA DURACIÓN TEMPORAL que 1x1, debemos multiplicar 
    npkts_max por 4 en 1x4.
    
    Parameters:
    -----------
    filename : str
        Nombre del archivo .pcap
    npkts_max : int
        Número máximo de paquetes deseado (base para 1x1)
    
    Returns:
    --------
    int : npkts_max ajustado para igualar duración temporal
    """
    if '1x4' in filename:
        # En 1x4, necesitamos 4x más paquetes para igualar duración temporal
        # Porque cada core solo tiene 1/4 de los paquetes
        return npkts_max * 4
    elif '1x1' in filename:
        # En 1x1, cada paquete = 1 core, no hay necesidad de ajustar
        return npkts_max
    else:
        # Por defecto, asumir 1x4
        return npkts_max * 4


def _process_batch_comparison(pcap_folder: str, output_folder: str, chip: str, 
                               npkts_max: int, normalize: bool):
    """
    Procesa múltiples archivos .pcap y crea comparaciones agrupadas por actividad y bandwidth.
    Procesa automáticamente archivos de 20MHz y 80MHz.
    Ajusta automáticamente npkts_max para igualar duración temporal entre 1x1 y 1x4.
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
    
    # Buscar todos los archivos .pcap
    pcap_pattern = os.path.join(pcap_folder, '*.pcap')
    pcap_files = glob.glob(pcap_pattern)
    
    if not pcap_files:
        print(f'No se encontraron archivos .pcap en {pcap_folder}')
        return
    
    # Agrupar archivos por actividad, bandwidth y config (1x1 o 1x4)
    # Estructura: activity_groups[activity][bw][config] = file_path
    activity_groups = {}
    for file_path in pcap_files:
        filename = os.path.basename(file_path)
        activity_code = filename[0]  # E, J, S, W
        activity_name = ACTIVITY_NAMES.get(activity_code, 'Unknown')
        
        # Determinar bandwidth
        if '20Mhz' in filename or '20MHz' in filename:
            bw = 20
        elif '40Mhz' in filename or '40MHz' in filename:
            bw = 40
        elif '80Mhz' in filename or '80MHz' in filename:
            bw = 80
        else:
            continue
        
        # Determinar config
        if '1x1' in filename:
            config = '1x1'
        elif '1x4' in filename:
            config = '1x4'
        else:
            continue
        
        # Inicializar estructura si es necesario
        if activity_name not in activity_groups:
            activity_groups[activity_name] = {}
        if bw not in activity_groups[activity_name]:
            activity_groups[activity_name][bw] = {'1x1': None, '1x4': None}
        
        activity_groups[activity_name][bw][config] = file_path
    
    print(f'Grupos de actividad encontrados: {len(activity_groups)}')
    
    # Procesar cada actividad y bandwidth
    hoffset = 16
    
    for activity_name, bw_dict in activity_groups.items():
        for bw, files in bw_dict.items():
            nfft = int(bw * 3.2)
            
            print(f'\n{"="*60}')
            print(f'Procesando: {activity_name} ({bw}MHz)')
            print(f'{"="*60}')
            
            config_1x1_data = None
            config_1x4_data = None
            
            # Procesar archivo 1x1
            if files['1x1']:
                filename_1x1 = os.path.basename(files['1x1'])
                print(f'  Procesando 1x1: {filename_1x1}')
                npkts_1x1 = _adjust_npkts_max_for_config(filename_1x1, npkts_max)
                print(f'    Ajustando NPKTS_MAX: {npkts_max} -> {npkts_1x1} (1x1 = 1 paquete/core)')
                config_1x1_data = _process_file_for_batch(files['1x1'], chip, bw, nfft, hoffset, npkts_1x1)
                print(f'    Cores detectados: {sorted(set([k[0] for k in config_1x1_data.keys()]))}')
            
            # Procesar archivo 1x4
            if files['1x4']:
                filename_1x4 = os.path.basename(files['1x4'])
                print(f'  Procesando 1x4: {filename_1x4}')
                npkts_1x4 = _adjust_npkts_max_for_config(filename_1x4, npkts_max)
                print(f'    Ajustando NPKTS_MAX: {npkts_max} -> {npkts_1x4} (1x4 = 4 cores/paquete, x4 para igualar tiempo)')
                config_1x4_data = _process_file_for_batch(files['1x4'], chip, bw, nfft, hoffset, npkts_1x4)
                print(f'    Cores detectados: {sorted(set([k[0] for k in config_1x4_data.keys()]))}')
            
            # Crear visualización comparativa
            output_path = os.path.join(output_dir, f'{activity_name}_{bw}MHz_comparison.png')
            _plot_core_comparison(config_1x1_data, config_1x4_data, bw, normalize, 
                                 activity_name, output_path)
    
    print(f'\n{"="*60}')
    print(f'Procesamiento por lotes completado!')
    print(f'Imágenes guardadas en: {output_dir}')
    print(f'{"="*60}')


def _debug_first_packets(p, n_debug=4):
    """
    Lee los primeros n_debug paquetes para mostrar los valores de csiconf detectados.
    Útil para verificar cuántos cores diferentes hay en el archivo.
    """
    print(f'\n=== DEBUG: Analizando primeros {n_debug} paquetes ===')
    p.from_start()
    
    csiconf_values = []
    for i in range(n_debug):
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
        
        if core is not None and ss is not None:
            csiconf_values.append((core, ss, chanspec, seq_counter))
        else:
            print(f'  Paquete {i+1}: No se pudo extraer (core,ss) - magic_off={magic_off}')
    
    unique_cores = set([c[0] for c in csiconf_values])
    unique_ss = set([c[1] for c in csiconf_values])
    print(f'\nResumen debug:')
    print(f'  Cores únicos detectados: {sorted(unique_cores)}')
    print(f'  SS únicos detectados: {sorted(unique_ss)}')
    print(f'  Combinaciones (core,ss): {csiconf_values}')
    print('=' * 50)
    
    return csiconf_values


def main():
    """
    Lógica principal para leer .pcap antiguo (magic 0x11111111), agrupar por (core, SS) y visualizar.
    """
    # ========== CONFIGURACIÓN ==========
    CHIP = '4366c0'           # fijo: este script es específico para bcm4366c0
    BW = 20                   # 20 / 40 / 80 MHz
    FILE = './J_noBF_20Mhz_1x4_M1_1Mo_A2.pcap'   # ruta al .pcap
    NPKTS_MAX = 4000         # límite de paquetes a procesar
    NORMALIZE = True          # normalizar magnitud por paquete
    SAVE_PNG = False          # guardar figura a PNG (True/False)
    OUTPUT_PATH = './csireader_image/S_20_1x4_A2.png'  # ruta de salida si SAVE_PNG=True
    
    # Modo batch (comparación por lotes)
    BATCH_MODE = True         # True para procesar múltiples archivos y crear comparaciones
    PCAP_FOLDER = './pcap_files/rewis_A3'  # carpeta con archivos .pcap
    OUTPUT_FOLDER = 'rewis_A3_good'  # carpeta donde guardar imágenes comparativas
 
    # ========== CONSTANTES ==========
    HOFFSET = 16              # header antiguo Nexmon: offset en palabras de 32 bits
    NFFT = int(BW * 3.2)      # tamaño FFT

    # Si está activado el modo batch, procesar por lotes
    if BATCH_MODE:
        _process_batch_comparison(PCAP_FOLDER, OUTPUT_FOLDER, CHIP, NPKTS_MAX, NORMALIZE)
        return

    # Modo normal: procesar un solo archivo
    valid_subcarriers_list = _get_valid_subcarriers(BW)
    num_valid = len(valid_subcarriers_list) if valid_subcarriers_list else NFFT
    
    print('CSI Reader — BCM4366C0 (formato antiguo)')
    print('=' * 60)
    print(f'Chip: {CHIP}')
    print(f'Bandwidth: {BW} MHz  -> NFFT={NFFT}')
    print(f'Valid subcarriers: {num_valid} (eliminando DC y bandas de guarda)')
    print(f'File: {FILE}')
    print(f'Max packets: {NPKTS_MAX}')
    print()

    # ========== LECTURA ==========
    p = ReadPcap()
    p.open(FILE)
    all_frames = p.all()
    n = min(len(all_frames), NPKTS_MAX)
    print(f'Encontrados {len(all_frames)} paquetes, procesando {n}...')
    
    # Debug: analizar primeros paquetes para ver cores detectados
    debug_values = _debug_first_packets(p, n_debug=4)
    
    p.from_start()

    # Agrupación por (core, ss): cada valor será lista de vectores complejos (1D, nfft)
    groups = {}
    processed = 0
    skipped = 0

    for _ in range(n):
        f = p.next()
        if f is None:
            break

        payload = f['payload']
        
        # Extraer (core, ss) del header antiguo ANTES de procesar CSI
        try:
            payload_bytes = payload.tobytes()
        except Exception:
            payload_bytes = bytes(payload)

        magic_off = _find_magic_offset(payload_bytes)
        core, ss, chanspec, seq_counter = _parse_core_ss_from_old_header(payload_bytes, magic_off)
        
        if core is None or ss is None:
            # Fallback: usar offset fijo como en MATLAB (HOFFSET = 16 palabras)
            core, ss = -1, -1
        
        # Calcular offset real del CSI basado en magic encontrado
        if magic_off > 0:
            # Header antiguo real: magic (4 bytes) + campos fijos (8 bytes) + seq (2 bytes) + chanspec (2 bytes) = 16 bytes total
            # Convertir a palabras de 32 bits: 16 bytes / 4 = 4 palabras
            csi_offset_words = magic_off // 4 + 4  # magic_off en palabras + 4 palabras de header
        else:
            # Fallback: usar HOFFSET fijo como en MATLAB
            csi_offset_words = HOFFSET
        
        # Verificar que tenemos suficientes datos
        if csi_offset_words + NFFT > len(payload):
            skipped += 1
            continue
            
        # Extraer CSI usando el offset calculado
        H = payload[csi_offset_words:csi_offset_words + NFFT]
        if len(H) < NFFT:
            skipped += 1
            continue

        # Decodificación específica bcm4366c0 (formato 1)
        Hout = unpack_float(1, NFFT, H)
        # Reorganiza a I/Q y construye números complejos
        Hout = Hout.reshape(2, -1, order='F')
        cmplx = Hout[0, :NFFT].astype(np.float64) + 1j * Hout[1, :NFFT].astype(np.float64)

        key = (core, ss)
        if key not in groups:
            groups[key] = []
        groups[key].append(cmplx)

        processed += 1

    p.close()

    # Convertir listas a matrices por grupo
    for key in list(groups.keys()):
        arr = np.vstack(groups[key]) if len(groups[key]) > 0 else np.empty((0, NFFT), dtype=np.complex128)
        groups[key] = arr

    # Resumen
    print('\nProcesamiento completado:')
    print(f'  Paquetes en PCAP: {len(all_frames)}')
    print(f'  Procesados: {processed} paquetes')
    print(f'  Omitidos:   {skipped} paquetes')
    print(f'  Cores detectados: {len(set([k[0] for k in groups.keys() if k[0] >= 0]))}')
    print(f'  Spatial streams detectados: {len(set([k[1] for k in groups.keys() if k[1] >= 0]))}')
    print(f'  Grupos únicos (core,ss): {len([k for k in groups.keys() if k[0] >= 0 and k[1] >= 0])}')
    for key in sorted(groups.keys()):
        print(f'  Grupo (core={key[0]}, ss={key[1]}): {groups[key].shape[0]} paquetes')

    # Visualización
    _plot_groups(groups, NFFT, BW, NORMALIZE, SAVE_PNG, OUTPUT_PATH)


if __name__ == '__main__':
    main()


