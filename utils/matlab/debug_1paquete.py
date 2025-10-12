"""
debug_1paquete.py - Script de debugging para verificar el archivo 1paquete.pcap
"""

from readpcap import ReadPcap
from csireader_extended import parse_csi_header
import struct

# Abrir archivo
p = ReadPcap()
p.open('./csi_dump.pcap')

# Leer todos los frames
all_frames = p.all()
print(f"Total frames en archivo: {len(all_frames)}")

# Volver al inicio
p.from_start()

# Leer primer frame
f = p.next()
p.close()

if f is None:
    print("ERROR: No se pudo leer el frame")
else:
    print(f"\nFrame leído correctamente")
    print(f"Header info:")
    print(f"  ts_sec: {f['header']['ts_sec']}")
    print(f"  ts_usec: {f['header']['ts_usec']}")
    print(f"  incl_len: {f['header']['incl_len']}")
    print(f"  orig_len: {f['header']['orig_len']}")
    
    payload = f['payload']
    print(f"\nPayload info:")
    print(f"  Type: {payload.dtype}")
    print(f"  Length: {len(payload)}")
    print(f"  Size in bytes: {payload.nbytes}")
    
    # Mostrar primeros bytes en hex
    if payload.dtype.name == 'uint32':
        payload_bytes = payload.tobytes()
    else:
        payload_bytes = payload.tobytes()
    
    print(f"\nPrimeros 60 bytes del payload (hex):")
    for i in range(0, min(60, len(payload_bytes)), 20):
        hex_str = ' '.join([f'{b:02x}' for b in payload_bytes[i:i+20]])
        print(f"  {i:04x}: {hex_str}")
    
    # Parsear header
    print(f"\n{'='*60}")
    print("PARSEANDO HEADER CSI")
    print('='*60)
    
    try:
        header, valid = parse_csi_header(payload)
        
        if valid:
            print("✓ Header válido!")
            print(f"  Magic: 0x{header['magic']:04X}")
            print(f"  RSSI: {header['rssi']} dBm")
            print(f"  FC: 0x{header['fc']:02X}")
            print(f"  MAC: {header['src_mac']}")
            print(f"  Seq: {header['seq']}")
            print(f"  Core: {header['core']}, SS: {header['spatial_stream']}")
            print(f"  Channel: {header['channel']} @ {header['bandwidth']} MHz")
            print(f"  Chip: {header['chip_name']} (0x{header['chip_version']:04X})")
        else:
            print(f"✗ Magic bytes inválidos: 0x{header['magic']:04X}")
            
    except Exception as e:
        print(f"✗ ERROR parseando header: {e}")
        import traceback
        traceback.print_exc()
    
    # Calcular tamaño esperado de CSI
    print(f"\n{'='*60}")
    print("VERIFICACIÓN DE TAMAÑO CSI")
    print('='*60)
    
    BW = 80  # Como en tu configuración
    NFFT = int(BW * 3.2)
    HEADER_SIZE = 18
    
    print(f"  Bandwidth configurado: {BW} MHz")
    print(f"  NFFT calculado: {NFFT}")
    print(f"  CSI data esperado: {NFFT * 4} bytes")
    print(f"  Header size: {HEADER_SIZE} bytes")
    print(f"  Total esperado: {HEADER_SIZE + NFFT * 4} bytes")
    print(f"  Payload disponible: {payload.nbytes} bytes")
    
    if payload.nbytes >= (HEADER_SIZE + NFFT * 4):
        print("  ✓ Tamaño suficiente")
    else:
        print(f"  ✗ Tamaño insuficiente (faltan {(HEADER_SIZE + NFFT * 4) - payload.nbytes} bytes)")