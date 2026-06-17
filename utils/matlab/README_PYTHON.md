# CSI Reader - Versión Python

Adaptación a Python del código MATLAB para leer y visualizar datos CSI del extractor Nexmon CSI.

## Instalación

Instala las dependencias necesarias:

```bash
pip install -r requirements.txt
```

## Archivos

- **`csireader.py`**: Script principal para leer y visualizar datos CSI
- **`readpcap.py`**: Clase para leer archivos PCAP
- **`unpack_float.py`**: Funciones para desempaquetar datos flotantes de chips bcm4358 y bcm4366c0
- **`plotcsi.py`**: Funciones de visualización con múltiples modos

## Uso

### Ejecución básica

```bash
python csireader.py
```

### Configuración

Edita las variables de configuración en `csireader.py`:

```python
CHIP = '4366c0'           # Chip WiFi: '4339', '4358', '43455c0', '4366c0'
BW = 20                   # Ancho de banda en MHz
FILE = './E_noBF_20Mhz_1x1_M1_1Mo_A2.pcap'  # Archivo de captura
NPKTS_MAX = 300           # Número máximo de paquetes UDP a procesar
PLOT_MODE = 'consolidated'  # Modo de visualización
NORMALIZE = False         # Normalizar magnitud CSI
```

## Modos de Visualización

### 1. Modo Interactivo (`PLOT_MODE = 'interactive'`)
- Muestra un paquete a la vez
- Presiona cualquier tecla para avanzar al siguiente paquete
- Comportamiento similar al código MATLAB original
- Incluye: magnitud, fase y mapa de calor

### 2. Modo Estático (`PLOT_MODE = 'static'`)
- Genera todas las figuras de una vez
- Útil para revisar rápidamente múltiples paquetes
- Cada figura muestra: magnitud, fase y mapa de calor

### 3. Modo Consolidado (`PLOT_MODE = 'consolidated'`)
- **NUEVO**: Vista completa con todos los datos en una sola figura
- Incluye 4 subplots:
  1. **Todas las amplitudes superpuestas**: Permite comparación visual rápida
  2. **Mapa de calor de amplitudes**: Vista temporal de todas las magnitudes
  3. **Amplitud media con desviación estándar**: Análisis estadístico
  4. **Mapa de calor de fase**: Vista temporal de todas las fases

## Chips Soportados

- **bcm4339**: Usa conversión int16 directa
- **bcm4358**: Usa `unpack_float` con formato 0
- **bcm43455c0**: Usa conversión int16 directa
- **bcm4366c0**: Usa `unpack_float` con formato 1

## Diferencias con MATLAB

1. **Sintaxis Python**: Usa numpy para operaciones numéricas y matplotlib para visualización
2. **Modo consolidado adicional**: Nueva visualización no disponible en versión MATLAB
3. **Gestión automática de archivos**: Los archivos PCAP se cierran automáticamente
4. **Información de progreso**: Imprime estadísticas durante el procesamiento

## Ejemplos

### Visualizar con modo consolidado
```python
PLOT_MODE = 'consolidated'
python csireader.py
```

### Procesar archivo diferente
```python
FILE = './J_noBF_20Mhz_1x4_M1_1Mo_A2.pcap'
python csireader.py
```

### Normalizar amplitudes
```python
NORMALIZE = True
python csireader.py
```

## Notas

- Asegúrate de que los archivos `.pcap` estén en el mismo directorio o proporciona la ruta completa
- El tamaño FFT se calcula automáticamente como `BW * 3.2`
- Los paquetes con tamaño incorrecto se omiten automáticamente

