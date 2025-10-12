"""
example_parse_header.py

Script de ejemplo que muestra cómo usar las funciones de parsing del header CSI
de manera independiente sin necesidad de procesar todo el archivo.

Útil para inspección rápida de archivos PCAP o debugging.
"""

import sys
from readpcap import ReadPcap
from csireader_extended import parse_csi_header, decode_chanspec


def inspect_pcap(filename, num_packets=10):
    """
    Inspecciona los primeros N paquetes de un archivo PCAP
    mostrando solo la información del header
    
    Parameters:
    -----------
    filename : str
        Ruta al archivo PCAP
    num_packets : int
        Número de paquetes a inspeccionar (default: 10)
    """
    print(f"Inspeccionando archivo: {filename}")
    print(f"Mostrando primeros {num_packets} paquetes\n")
    
    # Abrir archivo PCAP
    p = ReadPcap()
    try:
        p.open(filename)
    except Exception as e:
        print(f"Error abriendo archivo: {e}")
        return
    
    # Obtener todos los frames
    all_frames = p.all()
    n = min(len(all_frames), num_packets)
    
    print(f"Total de paquetes en archivo: {len(all_frames)}")
    print(f"Procesando: {n} paquetes\n")
    print("="*120)
    
    # Resetear al inicio
    p.from_start()
    
    valid_count = 0
    invalid_count = 0
    
    for i in range(n):
        f = p.next()
        if f is None:
            break
        
        payload = f['payload']
        
        try:
            header, valid = parse_csi_header(payload)
        except Exception as e:
            print(f"\nPaquete #{i+1}: Error parseando header - {e}")
            invalid_count += 1
            continue
        
        if not valid:
            print(f"\nPaquete #{i+1}: Magic bytes inválidos (0x{header['magic']:04X}) - Formato antiguo o datos corruptos")
            invalid_count += 1
            continue
        
        valid_count += 1
        
        # Mostrar información del paquete
        print(f"\n{'='*120}")
        print(f"PAQUETE #{i+1}")
        print(f"{'='*120}")
        print(f"  Magic Bytes:      0x{header['magic']:04X} ✓")
        print(f"  RSSI:             {header['rssi']} dBm")
        print(f"  Frame Control:    0x{header['fc']:02X}")
        print(f"  Source MAC:       {header['src_mac']}")
        print(f"  Sequence Number:  {header['seq']}")
        print(f"  Core:             {header['core']}")
        print(f"  Spatial Stream:   {header['spatial_stream']}")
        print(f"  CSI Config:       0x{header['csiconf']:04X}")
        print(f"  Chanspec:         0x{header['chanspec']:04X} ({decode_chanspec(header['chanspec'])})")
        print(f"  Channel:          {header['channel']}")
        print(f"  Bandwidth:        {header['bandwidth']} MHz")
        print(f"  Chip Version:     0x{header['chip_version']:04X} ({header['chip_name']})")
        print(f"  Payload size:     {len(payload)} bytes")
    
    p.close()
    
    # Resumen final
    print(f"\n{'='*120}")
    print(f"RESUMEN")
    print(f"{'='*120}")
    print(f"  Paquetes válidos:   {valid_count}")
    print(f"  Paquetes inválidos: {invalid_count}")
    print(f"  Total analizados:   {n}")
    
    if valid_count > 0:
        print(f"\n✓ Archivo compatible con formato extendido (csireader_extended.py)")
    else:
        print(f"\n✗ Archivo NO compatible con formato extendido")
        print(f"  Usar csireader.py para formato antiguo")
    
    print(f"{'='*120}\n")


def quick_check(filename):
    """
    Verificación rápida: solo revisa el primer paquete
    
    Parameters:
    -----------
    filename : str
        Ruta al archivo PCAP
    """
    print(f"Verificación rápida de: {filename}\n")
    
    p = ReadPcap()
    try:
        p.open(filename)
    except Exception as e:
        print(f"✗ Error abriendo archivo: {e}")
        return False
    
    all_frames = p.all()
    if len(all_frames) == 0:
        print(f"✗ Archivo vacío")
        p.close()
        return False
    
    p.from_start()
    f = p.next()
    p.close()
    
    if f is None:
        print(f"✗ No se pudo leer el primer paquete")
        return False
    
    try:
        header, valid = parse_csi_header(f['payload'])
    except Exception as e:
        print(f"✗ Error parseando header: {e}")
        return False
    
    if not valid:
        print(f"✗ Magic bytes inválidos: 0x{header['magic']:04X}")
        print(f"  Se esperaba: 0x1111 (formato nuevo)")
        print(f"  Usar csireader.py para formato antiguo")
        return False
    
    print(f"✓ Formato válido detectado")
    print(f"  Magic bytes: 0x{header['magic']:04X}")
    print(f"  Chip: {header['chip_name']}")
    print(f"  Total paquetes: {len(all_frames)}")
    print(f"  RSSI: {header['rssi']} dBm")
    print(f"  MAC: {header['src_mac']}")
    print(f"  Canal: {header['channel']} @ {header['bandwidth']} MHz")
    print(f"\n✓ Compatible con csireader_extended.py")
    return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso:")
        print(f"  {sys.argv[0]} <archivo.pcap> [num_packets]")
        print(f"\nEjemplos:")
        print(f"  {sys.argv[0]} capture.pcap           # Inspecciona primeros 10 paquetes")
        print(f"  {sys.argv[0]} capture.pcap 5         # Inspecciona primeros 5 paquetes")
        print(f"  {sys.argv[0]} capture.pcap quick     # Verificación rápida (solo 1er paquete)")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    if len(sys.argv) > 2:
        if sys.argv[2].lower() == 'quick':
            quick_check(filename)
        else:
            try:
                num_packets = int(sys.argv[2])
                inspect_pcap(filename, num_packets)
            except ValueError:
                print(f"Error: '{sys.argv[2]}' no es un número válido")
                sys.exit(1)
    else:
        inspect_pcap(filename, 10)

