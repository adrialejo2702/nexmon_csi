"""
compare_formats.py

Script de comparación entre el formato antiguo (16 bytes header) 
y el formato nuevo (18 bytes header con RSSI y metadata adicional)

Muestra qué información adicional se obtiene con el formato actualizado.
"""

import numpy as np
from readpcap import ReadPcap
from csireader_extended import parse_csi_header


def compare_formats():
    """
    Muestra una comparación visual entre los dos formatos
    """
    print("="*80)
    print("COMPARACIÓN DE FORMATOS UDP CSI")
    print("="*80)
    print()
    
    print("FORMATO ANTIGUO (Pre-PR#256)")
    print("-" * 80)
    print("Offset | Size | Field          | Description")
    print("-" * 80)
    print("0-3    | 4 B  | Magic Bytes    | 0x11111111 (validación)")
    print("4-9    | 6 B  | Source MAC     | Dirección MAC origen")
    print("10-11  | 2 B  | Sequence       | Número de secuencia")
    print("12-13  | 2 B  | CSI Config     | Core y Spatial Stream")
    print("14-15  | 2 B  | Chanspec       | Canal y bandwidth")
    print("16+    | Var  | CSI Data       | Datos CSI")
    print("-" * 80)
    print("TOTAL HEADER: 16 bytes")
    print()
    
    print("FORMATO NUEVO (Post-PR#256) ⭐")
    print("-" * 80)
    print("Offset | Size | Field          | Description")
    print("-" * 80)
    print("0-1    | 2 B  | Magic Bytes    | 0x1111 (validación)")
    print("2      | 1 B  | RSSI           | 🆕 Potencia de señal (dBm)")
    print("3      | 1 B  | Frame Control  | 🆕 Primer byte frame WiFi")
    print("4-9    | 6 B  | Source MAC     | Dirección MAC origen")
    print("10-11  | 2 B  | Sequence       | Número de secuencia")
    print("12-13  | 2 B  | CSI Config     | Core y Spatial Stream")
    print("14-15  | 2 B  | Chanspec       | Canal y bandwidth")
    print("16-17  | 2 B  | Chip Version   | 🆕 Identificador del chip")
    print("18+    | Var  | CSI Data       | Datos CSI")
    print("-" * 80)
    print("TOTAL HEADER: 18 bytes")
    print()
    
    print("INFORMACIÓN ADICIONAL DISPONIBLE CON FORMATO NUEVO:")
    print("-" * 80)
    print("✓ RSSI (Received Signal Strength Indicator)")
    print("  - Permite análisis de calidad de señal")
    print("  - Correlación CSI vs RSSI")
    print("  - Filtrado por nivel de señal")
    print()
    print("✓ Frame Control")
    print("  - Identifica tipo de frame WiFi")
    print("  - Permite filtrado más preciso")
    print()
    print("✓ Chip Version")
    print("  - Identificación automática del chip")
    print("  - Validación de compatibilidad")
    print("  - No requiere configuración manual")
    print()
    print("✓ Magic Bytes optimizados")
    print("  - Reducidos de 4 a 2 bytes")
    print("  - Libera espacio para nueva metadata")
    print("="*80)
    print()


def analyze_file(filename):
    """
    Analiza un archivo y detecta qué formato usa
    """
    print(f"\nAnalizando archivo: {filename}")
    print("="*80)
    
    p = ReadPcap()
    try:
        p.open(filename)
    except Exception as e:
        print(f"✗ Error abriendo archivo: {e}")
        return
    
    all_frames = p.all()
    if len(all_frames) == 0:
        print("✗ Archivo vacío")
        p.close()
        return
    
    print(f"Total de paquetes: {len(all_frames)}\n")
    
    p.from_start()
    f = p.next()
    p.close()
    
    if f is None:
        print("✗ No se pudo leer el primer paquete")
        return
    
    payload = f['payload']
    
    # Intentar parsear como formato nuevo
    try:
        header, valid = parse_csi_header(payload)
        
        if valid:
            print("✓ FORMATO DETECTADO: NUEVO (Post-PR#256)")
            print("-" * 80)
            print(f"  Magic bytes: 0x{header['magic']:04X}")
            print(f"  RSSI: {header['rssi']} dBm")
            print(f"  Frame Control: 0x{header['fc']:02X}")
            print(f"  MAC: {header['src_mac']}")
            print(f"  Sequence: {header['seq']}")
            print(f"  Core: {header['core']}, SS: {header['spatial_stream']}")
            print(f"  Channel: {header['channel']} @ {header['bandwidth']} MHz")
            print(f"  Chip: {header['chip_name']}")
            print()
            print("➜ Usar: python csireader_extended.py")
            print()
            print("VENTAJAS DEL FORMATO NUEVO:")
            print("  • Acceso a RSSI para análisis de calidad")
            print("  • Identificación automática de chip")
            print("  • Más metadata para análisis avanzado")
            print("  • Mejor detección de errores")
            return True
        else:
            # Magic bytes no coincide con formato nuevo
            print("✗ FORMATO DETECTADO: ANTIGUO (Pre-PR#256)")
            print("-" * 80)
            print(f"  Magic bytes: 0x{header['magic']:04X} (esperado: 0x1111)")
            print()
            print("➜ Usar: python csireader.py")
            print()
            print("CONSIDERACIONES:")
            print("  • Sin información de RSSI")
            print("  • Sin identificación automática de chip")
            print("  • Header de 16 bytes (no 18)")
            print()
            print("RECOMENDACIÓN:")
            print("  Considera actualizar a la versión más reciente de Nexmon CSI")
            print("  para aprovechar el formato mejorado")
            return False
            
    except Exception as e:
        print(f"✗ Error analizando formato: {e}")
        return None


if __name__ == '__main__':
    import sys
    
    print()
    compare_formats()
    
    if len(sys.argv) > 1:
        for filename in sys.argv[1:]:
            analyze_file(filename)
            print()
    else:
        print("INSTRUCCIONES:")
        print("-" * 80)
        print("Para analizar un archivo PCAP específico:")
        print(f"  python {sys.argv[0]} <archivo.pcap>")
        print()
        print("Ejemplo:")
        print(f"  python {sys.argv[0]} capture1.pcap capture2.pcap")
        print()

