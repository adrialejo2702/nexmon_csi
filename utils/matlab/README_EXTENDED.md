# CSI Reader Extended - Formato UDP Actualizado

Lector CSI mejorado para el formato UDP actualizado de Nexmon CSI que incluye RSSI, dirección MAC origen, número de secuencia y más metadatos.

## 🆕 Novedades del Formato Actualizado

El formato UDP fue actualizado en [PR #256](https://github.com/seemoo-lab/nexmon_csi/pull/256) con los siguientes cambios:

### Cambios principales:
1. **Magic bytes reducidos**: De 4 bytes (`0x11111111`) a 2 bytes (`0x1111`)
2. **RSSI añadido**: Nuevo campo de 1 byte con la potencia de señal recibida
3. **Frame Control añadido**: Nuevo campo de 1 byte
4. **Header total**: 18 bytes (antes 16 bytes)

### Estructura del Header (18 bytes):

| Offset | Tamaño | Campo | Tipo | Descripción |
|--------|--------|-------|------|-------------|
| 0-1 | 2 bytes | Magic bytes | uint16 | Valor fijo `0x1111` para validación |
| 2 | 1 byte | RSSI | int8 | Potencia de señal recibida en dBm |
| 3 | 1 byte | Frame Control | uint8 | Primer byte del frame WiFi 802.11 |
| 4-9 | 6 bytes | Source MAC | uint8[6] | Dirección MAC del transmisor |
| 10-11 | 2 bytes | Sequence Counter | uint16 | Número de secuencia del frame |
| 12-13 | 2 bytes | CSI Config | uint16 | Core (3 bits bajos) y Spatial Stream (3 bits siguientes) |
| 14-15 | 2 bytes | Chanspec | uint16 | Especificación del canal y ancho de banda |
| 16-17 | 2 bytes | Chip Version | uint16 | Identificador del chip WiFi |
| 18+ | Variable | CSI Data | uint32[] | Datos CSI propiamente dichos |

## 📦 Archivos Nuevos

### `csireader_extended.py`
Script principal que lee archivos PCAP con el formato actualizado y extrae toda la información del header.

**Características:**
- Parser completo del header de 18 bytes
- Extracción de RSSI, MAC, sequence number, core, spatial stream, etc.
- Tabla resumen con toda la metadata
- Estadísticas de RSSI (min, max, media, desviación)
- Detección de pérdida de paquetes
- Identificación de múltiples transmisores
- Exportación a formato `.npz` con metadata

### `plotcsi_extended.py`
Funciones de visualización mejoradas que incluyen información de RSSI y metadata.

**Visualizaciones adicionales:**
- Gráfico de RSSI vs tiempo
- Heatmap de RSSI
- Información de metadata en títulos
- Coloreado por RSSI
- Vista interactiva con información completa por paquete

## 🚀 Uso

### Instalación
Los mismos requisitos que el lector estándar:
```bash
pip install -r requirements.txt
```

### Ejecución Básica
```bash
python csireader_extended.py
```

### Configuración

Edita las variables en `csireader_extended.py`:

```python
# ========== CONFIGURATION ==========
CHIP = '4366c0'           # Chip: '4339', '4358', '43455c0', '4366c0'
BW = 20                   # Ancho de banda en MHz
FILE = './capture.pcap'   # Archivo PCAP
NPKTS_MAX = 300          # Máximo de paquetes a procesar
PLOT_MODE = 'consolidated'  # Modo: 'interactive', 'static', 'consolidated'
NORMALIZE = True          # Normalizar magnitud CSI
SAVE_NPZ = False          # Guardar datos en .npz
SHOW_TABLE = True         # Mostrar tabla resumen
```

## 📊 Salida del Programa

### 1. Tabla Resumen de Paquetes

```
====================================================================================================
PACKET SUMMARY
====================================================================================================
   # |  RSSI |    Seq | MAC Address       | Core | SS | Chan |     BW
----------------------------------------------------------------------------------------------------
   1 |   -45 |   1024 | AA:BB:CC:DD:EE:FF |    0 |  1 |  157 |     80
   2 |   -46 |   1025 | AA:BB:CC:DD:EE:FF |    0 |  1 |  157 |     80
   3 |   -44 |   1026 | AA:BB:CC:DD:EE:FF |    0 |  1 |  157 |     80
...
====================================================================================================
```

### 2. Estadísticas

```
====================================================================================================
STATISTICS
====================================================================================================
Total packets processed: 300

RSSI Statistics:
  Min RSSI:  -52 dBm
  Max RSSI:  -38 dBm
  Mean RSSI: -45.23 dBm
  Std RSSI:  3.45 dBm

Packet Loss:
  Estimated missing packets: 5
  Loss rate: 1.64%

Transmitters detected: 1
  AA:BB:CC:DD:EE:FF: 300 packets

Channel information:
  Channel 157 @ 80 MHz: 300 packets
====================================================================================================
```

### 3. Visualizaciones

#### Modo Consolidado
1. **Vista General** (6 subplots):
   - Todas las amplitudes superpuestas
   - RSSI vs tiempo (NUEVO)
   - Heatmap de amplitudes
   - Heatmap de RSSI (NUEVO)
   - Amplitud media con desviación estándar
   - Todas las fases superpuestas

2. **Vista Interactiva**:
   - Navegación paquete por paquete
   - Información completa en títulos: RSSI, MAC, Seq, Core, SS
   - Paquete actual resaltado sobre contexto de todos los paquetes
   - Indicador de posición en heatmap

## 🔍 Análisis Disponibles

### 1. Análisis de Calidad de Señal
- Rango de RSSI (min, max, media)
- Variabilidad de RSSI (desviación estándar)
- Correlación CSI vs RSSI

### 2. Análisis de Pérdida de Paquetes
- Detección automática de saltos en sequence number
- Cálculo de tasa de pérdida
- Identificación de gaps en la captura

### 3. Análisis Multi-Transmisor
- Identificación de múltiples MACs
- Conteo de paquetes por transmisor
- Separación de datos por origen

### 4. Análisis de Canal
- Detección de cambios de canal
- Identificación de ancho de banda usado
- Validación de configuración

## 💾 Exportación de Datos

### Formato NPZ (NumPy)

Activa `SAVE_NPZ = True` para guardar:

```python
# Cargar datos guardados
data = np.load('capture_csi_data.npz')

# Acceder a arrays
csi = data['csi']              # Array complejo (num_packets, nfft)
rssi = data['rssi']            # Array (num_packets,)
sequence = data['sequence']    # Array (num_packets,)
core = data['core']            # Array (num_packets,)
spatial_stream = data['spatial_stream']  # Array (num_packets,)
channel = data['channel']      # Array (num_packets,)
bandwidth = data['bandwidth']  # Array (num_packets,)
```

## 🔄 Compatibilidad

### Con el formato antiguo
Si tus archivos PCAP fueron capturados con la versión antigua de Nexmon CSI (antes del PR #256), usa el lector estándar `csireader.py`.

### Con el formato nuevo
Si tus archivos PCAP fueron capturados con la versión actualizada (después del PR #256), usa `csireader_extended.py`.

### ¿Cómo saber qué versión usar?

Ejecuta ambos y verifica los errores:
- Si `csireader_extended.py` muestra "Invalid magic bytes", usa `csireader.py`
- Si `csireader.py` funciona pero ignora metadata, considera actualizar a la nueva versión de Nexmon CSI

## 📝 Decodificación de Campos

### CSI Config (csiconf)
```python
core = csiconf & 0x7              # 3 bits bajos
spatial_stream = (csiconf >> 3) & 0x7  # siguientes 3 bits
```

### Chanspec
```python
channel = chanspec & 0xFF         # Canal
bw_code = (chanspec >> 11) & 0x7  # Código de ancho de banda
# bw_code: 0=5MHz, 1=10MHz, 2=20MHz, 3=40MHz, 4=80MHz, 5=160MHz
```

### Chip Version
```python
CHIP_VERSIONS = {
    0x4339: 'bcm4339',
    0x4358: 'bcm4358',
    0x4366: 'bcm4366c0',
    0xaa52: 'bcm43455c0'
}
```

## 🐛 Troubleshooting

### Error: "Invalid magic bytes"
**Causa**: El archivo PCAP fue capturado con formato antiguo o no es un archivo CSI válido.  
**Solución**: Usa `csireader.py` o verifica que el archivo sea correcto.

### Error: "Index out of bounds"
**Causa**: Header size incorrecto o datos corruptos.  
**Solución**: Verifica que `HEADER_SIZE = 18` y que el archivo PCAP no esté corrupto.

### Advertencia: "Estimated missing packets"
**Causa**: Pérdida de paquetes durante la captura.  
**Solución**: Normal en capturas WiFi. Considera mejorar la señal o reducir la tasa de transmisión.

### Los gráficos no muestran RSSI
**Causa**: Problema con `plotcsi_extended.py`.  
**Solución**: El programa hace fallback automático a `plotcsi.py` estándar.

## 🔗 Referencias

- [Nexmon CSI Repository](https://github.com/seemoo-lab/nexmon_csi)
- [PR #256 - Format Update](https://github.com/seemoo-lab/nexmon_csi/pull/256)
- [WiNTECH 2019 Paper](https://doi.org/10.1145/3349623.3355477)

## 📧 Contacto

Para preguntas sobre el formato actualizado, consulta el repositorio oficial de Nexmon CSI o contacta a los autores originales.

