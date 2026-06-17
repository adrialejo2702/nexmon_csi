# Guía Completa del Formato CSI Extendido

Esta guía documenta la implementación completa del lector CSI para el formato UDP actualizado de Nexmon CSI.

## 📚 Archivos Creados

### Módulos Principales

#### 1. `csireader_extended.py`
**Propósito**: Script principal para leer archivos PCAP con formato UDP actualizado (18 bytes header).

**Funciones clave**:
- `parse_csi_header(payload)`: Parsea el header completo de 18 bytes
- `decode_chanspec(chanspec)`: Decodifica especificación de canal
- `print_packet_summary(packets_info)`: Muestra tabla resumen
- `print_statistics(packets_info)`: Calcula y muestra estadísticas
- `save_to_npz(filename, csi_data, packets_info)`: Exporta a formato NumPy
- `main()`: Función principal con toda la lógica de procesamiento

**Características**:
- Header de 18 bytes (actualizado desde 16)
- Extracción de RSSI, Frame Control, Chip Version
- Validación de magic bytes (0x1111)
- Detección automática de pérdida de paquetes
- Identificación de múltiples transmisores
- Estadísticas completas de RSSI
- Exportación a .npz con metadata

#### 2. `plotcsi_extended.py`
**Propósito**: Funciones de visualización mejoradas con información de metadata.

**Funciones**:
- `plotcsi_with_rssi()`: Función principal de plotting con RSSI
- `_plot_consolidated_with_rssi()`: Modo consolidado (6 subplots + interactivo)
- `_plot_static_with_rssi()`: Modo estático con metadata
- `_plot_interactive_with_rssi()`: Modo interactivo puro

**Nuevas visualizaciones**:
- Gráfico de RSSI vs tiempo
- Heatmap de RSSI por paquete
- Información de metadata en títulos (RSSI, MAC, Seq)
- Indicadores visuales de paquete actual
- Leyendas mejoradas con contexto

### Scripts de Utilidad

#### 3. `example_parse_header.py`
**Propósito**: Script de ejemplo e inspección de headers CSI.

**Uso**:
```bash
# Inspeccionar primeros 10 paquetes
python example_parse_header.py archivo.pcap

# Inspeccionar N paquetes
python example_parse_header.py archivo.pcap 20

# Verificación rápida (solo 1 paquete)
python example_parse_header.py archivo.pcap quick
```

**Características**:
- Inspección detallada de headers sin procesar CSI completo
- Verificación rápida de compatibilidad
- Detección de formato (antiguo vs nuevo)
- Debugging de archivos problemáticos

#### 4. `compare_formats.py`
**Propósito**: Comparación entre formato antiguo y nuevo.

**Uso**:
```bash
# Ver comparación de formatos
python compare_formats.py

# Analizar archivo(s) específico(s)
python compare_formats.py archivo1.pcap archivo2.pcap
```

**Características**:
- Tabla comparativa de estructuras
- Detección automática de formato
- Recomendaciones de uso
- Explicación de ventajas del formato nuevo

### Documentación

#### 5. `README_EXTENDED.md`
**Propósito**: Documentación completa del formato extendido.

**Contenido**:
- Estructura detallada del header (18 bytes)
- Instrucciones de uso
- Ejemplos de configuración
- Descripción de salidas
- Guía de troubleshooting
- Referencias y contactos

#### 6. `EXTENDED_FORMAT_GUIDE.md` (este archivo)
**Propósito**: Guía maestra de toda la implementación.

## 🔄 Flujo de Trabajo

### Workflow Normal

```
1. Captura con Nexmon CSI (formato actualizado)
   ↓
2. Archivo .pcap generado
   ↓
3. Verificación (opcional): python example_parse_header.py archivo.pcap quick
   ↓
4. Procesamiento: python csireader_extended.py
   ↓
5. Visualización con metadata
   ↓
6. (Opcional) Exportación a .npz
```

### Workflow de Debugging

```
1. Archivo .pcap con problemas
   ↓
2. python compare_formats.py archivo.pcap  # Detectar formato
   ↓
3. python example_parse_header.py archivo.pcap  # Inspeccionar headers
   ↓
4. Ajustar configuración en csireader_extended.py
   ↓
5. Procesar con configuración correcta
```

## 📊 Estructura del Paquete UDP Completa

### Vista General
```
+------------------+
| Ethernet Header  |
+------------------+
| IP Header        |
+------------------+
| UDP Header       |
+------------------+
| CSI UDP Payload  |
|  ┌─────────────┐ |
|  │ Magic (2B)  │ | Offset 0-1: 0x1111
|  ├─────────────┤ |
|  │ RSSI (1B)   │ | Offset 2: int8
|  ├─────────────┤ |
|  │ FC (1B)     │ | Offset 3: uint8
|  ├─────────────┤ |
|  │ MAC (6B)    │ | Offset 4-9: 6 bytes
|  ├─────────────┤ |
|  │ Seq (2B)    │ | Offset 10-11: uint16
|  ├─────────────┤ |
|  │ Conf (2B)   │ | Offset 12-13: uint16
|  ├─────────────┤ |
|  │ Chan (2B)   │ | Offset 14-15: uint16
|  ├─────────────┤ |
|  │ Chip (2B)   │ | Offset 16-17: uint16
|  ├─────────────┤ |
|  │             │ |
|  │  CSI Data   │ | Offset 18+: uint32[]
|  │             │ |
|  └─────────────┘ |
+------------------+
```

### Decodificación de Campos

#### CSI Config (offset 12-13)
```python
csiconf = uint16_value
core = csiconf & 0b0000000000000111  # bits 0-2
spatial_stream = (csiconf >> 3) & 0b0000000000000111  # bits 3-5
# bits 6-15: reservados
```

#### Chanspec (offset 14-15)
```python
chanspec = uint16_value
channel = chanspec & 0xFF  # bits 0-7
bandwidth_code = (chanspec >> 11) & 0x7  # bits 11-13

# Mapeo de bandwidth_code:
# 0 → 5 MHz
# 1 → 10 MHz
# 2 → 20 MHz
# 3 → 40 MHz
# 4 → 80 MHz
# 5 → 160 MHz
# 6 → 80+80 MHz
```

#### Chip Version (offset 16-17)
```python
chip_version = uint16_value

# Valores conocidos:
# 0x4339 → bcm4339
# 0x4358 → bcm4358
# 0x4366 → bcm4366c0
# 0xAA52 → bcm43455c0
```

## 🎯 Casos de Uso

### 1. Análisis Básico de CSI
```bash
# Configurar en csireader_extended.py
CHIP = '4366c0'
BW = 80
FILE = './capture.pcap'
PLOT_MODE = 'consolidated'
NORMALIZE = True

# Ejecutar
python csireader_extended.py
```

### 2. Análisis de Calidad de Enlace (RSSI)
```bash
# Configurar
SHOW_TABLE = True  # Ver tabla con RSSI por paquete
SAVE_NPZ = True    # Guardar para análisis posterior

# En código externo:
import numpy as np
data = np.load('capture_csi_data.npz')
rssi = data['rssi']
csi = data['csi']
# Analizar correlación CSI vs RSSI
```

### 3. Detección de Múltiples Transmisores
```python
# csireader_extended.py automáticamente detecta y reporta:
# - Número de MACs únicas
# - Paquetes por transmisor
# - Cambios de transmisor en la captura
```

### 4. Análisis de Pérdida de Paquetes
```python
# Automático en print_statistics():
# - Detecta saltos en sequence number
# - Calcula tasa de pérdida
# - Identifica gaps en la captura
```

### 5. Debugging de Capturas
```bash
# Paso 1: Verificar formato
python compare_formats.py capture.pcap

# Paso 2: Inspeccionar headers
python example_parse_header.py capture.pcap 5

# Paso 3: Procesar si es válido
python csireader_extended.py
```

## 🔧 Configuración Avanzada

### Variables de Configuración en `csireader_extended.py`

```python
# Básicas
CHIP = '4366c0'           # Chip WiFi
BW = 20                   # Ancho de banda
FILE = './capture.pcap'   # Archivo
NPKTS_MAX = 300          # Límite de paquetes

# Visualización
PLOT_MODE = 'consolidated'  # 'interactive', 'static', 'consolidated'
NORMALIZE = True            # Normalizar magnitudes

# Salida
SAVE_NPZ = False           # Exportar a .npz
SHOW_TABLE = True          # Mostrar tabla resumen

# Constantes (no cambiar usualmente)
HEADER_SIZE = 18           # Tamaño del header (formato nuevo)
NFFT = int(BW * 3.2)      # Tamaño FFT calculado
```

### Personalización de Visualizaciones

Editar `plotcsi_extended.py` para:
- Cambiar colormaps
- Ajustar transparencias
- Modificar tamaños de figura
- Añadir más subplots
- Personalizar títulos y leyendas

## ⚠️ Advertencias y Limitaciones

### Compatibilidad
- **Solo funciona con formato nuevo** (Post-PR#256)
- Archivos antiguos deben usar `csireader.py`
- No hay conversión automática entre formatos

### Rendimiento
- Archivos muy grandes (>1000 paquetes) pueden ser lentos en modo interactivo
- Se recomienda `NPKTS_MAX` para capturas largas
- La exportación a .npz puede ocupar mucho espacio

### Datos
- Guard carriers y null carriers contienen valores arbitrarios
- RSSI puede estar saturado en señales muy fuertes
- Pérdida de paquetes es normal en WiFi, no siempre es un problema

## 📈 Próximas Mejoras Posibles

- [ ] Exportación a CSV con metadata
- [ ] Filtrado interactivo por RSSI
- [ ] Análisis de correlación CSI-RSSI automático
- [ ] Detección de anomalías basada en RSSI
- [ ] Comparación de múltiples capturas
- [ ] Exportación a formato compatible con Intel CSI Tool
- [ ] GUI para configuración visual
- [ ] Procesamiento en streaming para archivos grandes

## 🔗 Enlaces Útiles

- [Nexmon CSI Repository](https://github.com/seemoo-lab/nexmon_csi)
- [PR #256 - Format Update](https://github.com/seemoo-lab/nexmon_csi/pull/256)
- [CSI Extractor Source](https://github.com/seemoo-lab/nexmon_csi/blob/master/src/csi_extractor.c)
- [WiNTECH 2019 Paper](https://doi.org/10.1145/3349623.3355477)

## 📧 Soporte

Para preguntas sobre:
- **Formato del paquete**: Ver `csi_extractor.c` en el repositorio oficial
- **Uso de scripts**: Ver este documento o `README_EXTENDED.md`
- **Bugs en Nexmon CSI**: Abrir issue en repositorio oficial
- **Implementación Python**: Revisar código fuente con comentarios

---

**Versión**: 1.0  
**Fecha**: Octubre 2025  
**Basado en**: Nexmon CSI PR #256 y posteriores

