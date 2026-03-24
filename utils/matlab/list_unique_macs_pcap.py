"""
Lista las direcciones MAC unicas encontradas en paquetes UDP de un archivo .pcap.

El script inspecciona:
1. Las MAC origen y destino de la cabecera Ethernet.
2. La MAC origen embebida en la cabecera CSI de Nexmon, si existe.

Uso:
    python utils/matlab/list_unique_macs_pcap.py ruta/al/archivo.pcap
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

ETH_HEADER_SIZE = 14
UDP_PROTOCOL = 17
ETHERTYPE_IPV4 = 0x0800
CSI_HEADER_SIZE = 18
CSI_MAGIC = 0x1111
PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16
PCAP_MAGIC_TO_ENDIANNESS = {
    b"\xd4\xc3\xb2\xa1": "<",  # classic pcap, little endian
    b"\xa1\xb2\xc3\xd4": ">",  # classic pcap, big endian
    b"\x4d\x3c\xb2\xa1": "<",  # pcap nanosecond, little endian
    b"\xa1\xb2\x3c\x4d": ">",  # pcap nanosecond, big endian
}


def _format_mac(mac_bytes: bytes) -> str:
    """Convierte 6 bytes a una MAC legible."""
    return ":".join(f"{byte:02X}" for byte in mac_bytes)


def _iter_pcap_frames(pcap_path: str):
    """Itera sobre los frames de un PCAP clasico sin dependencias externas."""
    with open(pcap_path, "rb") as file_obj:
        global_header = file_obj.read(PCAP_GLOBAL_HEADER_SIZE)
        if len(global_header) < PCAP_GLOBAL_HEADER_SIZE:
            raise ValueError("El archivo es demasiado pequeno para ser un PCAP valido.")

        magic_bytes = global_header[:4]
        endianness = PCAP_MAGIC_TO_ENDIANNESS.get(magic_bytes)
        if endianness is None:
            raise ValueError("Formato PCAP no soportado o cabecera no reconocida.")

        packet_header_struct = struct.Struct(f"{endianness}IIII")

        while True:
            packet_header = file_obj.read(PCAP_PACKET_HEADER_SIZE)
            if not packet_header:
                break
            if len(packet_header) < PCAP_PACKET_HEADER_SIZE:
                raise ValueError("Cabecera de paquete incompleta dentro del PCAP.")

            _, _, incl_len, _ = packet_header_struct.unpack(packet_header)
            frame_bytes = file_obj.read(incl_len)
            if len(frame_bytes) < incl_len:
                raise ValueError("Payload de paquete incompleto dentro del PCAP.")

            yield frame_bytes


def _extract_udp_payload(frame_bytes: bytes) -> bytes | None:
    """Devuelve el payload UDP si la trama es Ethernet + IPv4 + UDP."""
    if len(frame_bytes) < ETH_HEADER_SIZE:
        return None

    ethertype = struct.unpack("!H", frame_bytes[12:14])[0]
    if ethertype != ETHERTYPE_IPV4:
        return None

    ip_start = ETH_HEADER_SIZE
    if len(frame_bytes) < ip_start + 20:
        return None

    version = frame_bytes[ip_start] >> 4
    ihl = (frame_bytes[ip_start] & 0x0F) * 4
    if version != 4 or ihl < 20:
        return None

    if len(frame_bytes) < ip_start + ihl + 8:
        return None

    protocol = frame_bytes[ip_start + 9]
    if protocol != UDP_PROTOCOL:
        return None

    total_length = struct.unpack("!H", frame_bytes[ip_start + 2 : ip_start + 4])[0]
    udp_start = ip_start + ihl
    udp_length = struct.unpack("!H", frame_bytes[udp_start + 4 : udp_start + 6])[0]

    if udp_length < 8:
        return None

    payload_start = udp_start + 8
    payload_end = min(len(frame_bytes), ip_start + total_length, udp_start + udp_length)
    if payload_end <= payload_start:
        return None

    return frame_bytes[payload_start:payload_end]


def _extract_csi_mac(udp_payload: bytes) -> str | None:
    """Busca una cabecera CSI de Nexmon dentro del payload UDP y devuelve su MAC."""
    max_offset = min(len(udp_payload) - CSI_HEADER_SIZE, 256)
    if max_offset < 0:
        return None

    for offset in range(max_offset + 1):
        magic = struct.unpack_from("<H", udp_payload, offset)[0]
        if magic == CSI_MAGIC:
            src_mac = udp_payload[offset + 4 : offset + 10]
            return _format_mac(src_mac)

    return None


def collect_unique_macs(pcap_path: str) -> tuple[list[str], int, int]:
    """Recorre el PCAP y devuelve las MAC unicas detectadas en paquetes UDP."""
    unique_macs: set[str] = set()
    total_packets = 0
    udp_packets = 0

    for frame_bytes in _iter_pcap_frames(pcap_path):
        total_packets += 1
        if len(frame_bytes) < ETH_HEADER_SIZE:
            continue

        udp_payload = _extract_udp_payload(frame_bytes)
        if udp_payload is None:
            continue

        udp_packets += 1

        dst_mac = _format_mac(frame_bytes[0:6])
        src_mac = _format_mac(frame_bytes[6:12])
        unique_macs.add(dst_mac)
        unique_macs.add(src_mac)

        csi_mac = _extract_csi_mac(udp_payload)
        if csi_mac is not None:
            unique_macs.add(csi_mac)

    return sorted(unique_macs), total_packets, udp_packets


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Muestra por terminal las direcciones MAC unicas encontradas en paquetes UDP de un .pcap."
    )
    parser.add_argument("pcap", help="Ruta al archivo .pcap")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.is_file():
        raise SystemExit(f"No existe el archivo: {pcap_path}")

    unique_macs, total_packets, udp_packets = collect_unique_macs(str(pcap_path))

    print("Direcciones MAC unicas detectadas")
    print("=" * 40)
    print(f"Archivo         : {pcap_path}")
    print(f"Paquetes totales: {total_packets}")
    print(f"Paquetes UDP    : {udp_packets}")
    print()

    if not unique_macs:
        print("No se encontraron direcciones MAC en paquetes UDP.")
        return

    for index, mac in enumerate(unique_macs, start=1):
        print(f"{index:>3}. {mac}")


if __name__ == "__main__":
    main()
