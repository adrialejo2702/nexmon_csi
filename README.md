
# Nexmon Channel State Information Extractor — Adaptación para Asus RT-AC86U

> **Rama `python_adaptation`** — Este README documenta las herramientas desarrolladas en la rama `python_adaptation` de este fork.
>
> **Este repositorio es un fork** de [seemoo-lab/nexmon_csi](https://github.com/seemoo-lab/nexmon_csi) adaptado para su uso exclusivo en routers Asus con chipset Broadcom bcm4366c0 (RT-AC86U, RT-AC88U, RT-AC3100). El proyecto original permite extraer Channel State Information (CSI) de tramas Wi-Fi OFDM (802.11a/g/n/ac) por trama individual con hasta 80 MHz de ancho de banda.
>
> **Fork mantenido por [@adrialejo2702](https://github.com/adrialejo2702)**

---

## Tabla de contenidos

1. [Fundamentos teóricos](#1-fundamentos-teoricos)
2. [Chips soportados](#2-chips-soportados)
3. [Estructura del paquete CSI](#3-estructura-del-paquete-csi)
4. [Compilación e instalación en el router](#4-compilacion-e-instalacion-en-el-router)
5. [Uso básico: captura de CSI](#5-uso-basico-captura-de-csi)
6. [Ecosistema de herramientas Python](#6-ecosistema-de-herramientas-python)
   - [6.0 Recomendaciones previas para nuevos usuarios](#60-recomendaciones-previas-para-nuevos-usuarios)
   - [6.1 csireader_extended.py — Lector de terminal](#61-csireader_extendedpy)
   - [6.2 csi_web — Visualizador web](#62-csi_web)
   - [6.3 CNN — Clasificación multicore vía API Edge Impulse](#63-cnn)
   - [6.4 CNNv2 — Clasificación local](#64-cnnv2)
   - [6.5 Scripts complementarios](#65-scripts-complementarios)
7. [Preguntas frecuentes](#7-preguntas-frecuentes)
8. [Licencia y atribuciones](#8-licencia-y-atribuciones)

---

## 1. Fundamentos teóricos

### 1.1 Channel State Information (CSI)

En sistemas de comunicaciones inalámbricas, la **Channel State Information** describe cómo se propaga una señal desde el transmisor hasta el receptor, considerando los efectos del canal (trayectorias múltiples, atenuación, desvanecimiento, etc.). Mientras que el **RSSI** (Received Signal Strength Indicator) proporciona un único valor escalar que representa la potencia media de la señal recibida, el **CSI** ofrece una descripción detallada del canal en el dominio de la frecuencia: entrega un valor complejo (magnitud y fase) para cada subportadora OFDM.

Para un sistema con `N` subportadoras, el CSI se representa como un vector de `N` números complejos:

```
H(f_k) = |H(f_k)| · e^{j·∠H(f_k)}   para k = 1, 2, ..., N
```

donde `|H(f_k)|` es la amplitud y `∠H(f_k)` es la fase en la subportadora `f_k`.

### 1.2 Nexmon y el parche de firmware

[Nexmon](https://nexmon.org) es un framework de parcheo de firmware basado en C para chips WiFi Broadcom/Cypress. Permite modificar el firmware binario (`dhd.ko`) para habilitar funcionalidades no disponibles en el firmware original, como la extracción de CSI.

El mecanismo de extracción funciona de la siguiente manera:

1. El firmware original se descompone en sus partes constituyentes: **ucode** (microcódigo ejecutado en el procesador de banda base), **templateram**, **flashpatches** y **parches**.

2. Se inyecta código en el **ucode** para que, cuando el chip recibe una trama Wi-Fi, copie los valores crudos del equalizador (que contienen la estimación del canal) a una región de memoria compartida.

3. Un **hook** en C (en `src/csi_extractor.c`) intercepta las tramas recibidas, empaqueta los datos CSI en un datagrama UDP y los envía al host.

4. En el caso concreto del **bcm4366c0**, el CSI se codifica en un formato de punto flotante propietario: cada valor de 32 bits contiene signo (1 bit) + parte real (12 bits) + signo (1 bit) + parte imaginaria (12 bits) + exponente (6 bits). Este formato se desempaqueta en el software receptor.

---

## 2. Chips soportados

Este fork está limitado al chipset **bcm4366c0**, presente en los siguientes routers Asus:

| WiFi Chip | Firmware Version | Router        |
|-----------|------------------|---------------|
| bcm4366c0 | 10_10_122_20     | Asus RT-AC86U |
| bcm4366c0 | 10_10_122_20     | Asus RT-AC88U |
| bcm4366c0 | 10_10_122_20     | Asus RT-AC3100 |

> **Nota:** Para otros chips (bcm4339, bcm43455c0, bcm4358), consulta el [repositorio upstream](https://github.com/seemoo-lab/nexmon_csi).

---

## 3. Estructura del paquete CSI

Cada paquete UDP que contiene CSI se envía desde la dirección `10.10.10.10` al puerto `5500` en `255.255.255.255`. El payload sigue el formato extendido introducido en el PR #256 del repositorio original.

### 3.1 Header de 18 bytes

| Offset | Tamaño | Campo         | Tipo     | Descripción                                      |
|--------|--------|---------------|----------|--------------------------------------------------|
| 0–1    | 2 B    | Magic bytes   | `uint16` | Valor fijo `0x1111` para validación              |
| 2      | 1 B    | RSSI          | `int8`   | Potencia de señal recibida en dBm                |
| 3      | 1 B    | Frame Control | `uint8`  | Primer byte de la trama WiFi 802.11              |
| 4–9    | 6 B    | Source MAC    | `uint8[6]` | Dirección MAC del transmisor                   |
| 10–11  | 2 B    | Sequence Cnt  | `uint16` | Número de secuencia de la trama                  |
| 12–13  | 2 B    | CSI Config    | `uint16` | Core (bits 0–2) y spatial stream (bits 3–5)      |
| 14–15  | 2 B    | Chanspec      | `uint16` | Canal y ancho de banda (ver §3.2)                |
| 16–17  | 2 B    | Chip Version  | `uint16` | Identificador del chip (`0x4366` para bcm4366c0) |
| 18+    | —      | CSI Data      | `uint32[]` | Valores CSI en formato float bcm4366c0          |

### 3.2 Decodificación de Chanspec

```
bits 0–7   → canal (p.ej., 36, 157)
bits 11–13 → código de ancho de banda:
              0 = 5 MHz
              1 = 10 MHz
              2 = 20 MHz
              3 = 40 MHz
              4 = 80 MHz
              5 = 160 MHz
```

### 3.3 Formato de datos CSI

Para el bcm4366c0, cada palabra de 32 bits contiene:

```
bit 31     → signo de la parte real
bits 30–19 → parte real (12 bits, magnitud)
bit 18     → signo de la parte imaginaria
bits 17–6  → parte imaginaria (12 bits, magnitud)
bits 5–0   → exponente común (6 bits)
```

El número de palabras CSI depende del ancho de banda:

| Ancho de banda | Subportadoras | Palabras CSI |
|----------------|---------------|--------------|
| 20 MHz         | 64            | 64           |
| 40 MHz         | 128           | 128          |
| 80 MHz         | 256           | 256          |

Incluye subportadoras null/guard, que deben ser ignoradas en el procesamiento:

- **20 MHz 802.11n/ac**: índices `-32..-29, 0, +29..+31`
- **40 MHz**: `-64..-59, -1..+1, +59..+63`
- **80 MHz**: `-128..-123, -1..+1, +123..+127`

---

## 4. Compilación e instalación en el router

El proceso de instalación sigue los pasos descritos en el repositorio original de seemoo-lab, con las adaptaciones necesarias para el **bcm4366c0** en el router Asus RT-AC86U. A continuación se resumen los pasos principales; para una guía detallada, consulta la sección **bcm4366c0** en el [README original](https://github.com/seemoo-lab/nexmon_csi#bcm4366c0).

### 4.1 Resumen del proceso

1. **Preparar el entorno de compilación** en Xubuntu 18.04 LTS (64 bits):
   - Instalar dependencias: `git gawk qpdf flex bison xxd`
   - En x86_64, añadir librerías i386 (`libc6:i386`, `libncurses5:i386`, `libstdc++6:i386`)

2. **Clonar el framework nexmon base** y configurar el entorno:
   ```bash
   git clone https://github.com/seemoo-lab/nexmon.git
   cd nexmon
   source setup_env.sh
   make
   ```

3. **Clonar este repositorio** como subproyecto de nexmon:
   ```bash
   cd patches/bcm4366c0/10_10_122_20/
   git clone https://github.com/adrialejo2702/nexmon_csi.git
   cd nexmon_csi
   ```

4. **Compilar e instalar el firmware** en el router (sustituye `<ip>` por la dirección IP del router):
   ```bash
   make install-firmware REMOTEADDR=<ip>
   ```

5. **Compilar nexutil** de forma estática con la toolchain cruzada aarch64 y transferirlo al router:
   ```bash
   git clone https://github.com/RMerl/am-toolchains.git
   # Configurar variables AMCC y LD_LIBRARY_PATH
   # Compilar nexutil con -static y copiar a /jffs/nexutil
   ```

6. **Compilar makecsiparams**:
   ```bash
   cd nexmon_csi/utils/makecsiparams
   make
   ```

7. **Cargar el módulo** en el router vía SSH:
   ```bash
   ssh admin@<ip>
   /sbin/rmmod dhd
   /sbin/insmod /jffs/dhd.ko
   ```

Para los detalles completos de cada paso (configuración de la toolchain, flags de compilación de nexutil, etc.), consulta la [guía original](https://github.com/seemoo-lab/nexmon_csi#bcm4366c0).

---

## 5. Uso básico: captura de CSI

Una vez que el firmware parcheado está cargado en el router, se pueden capturar tramas CSI siguiendo estos pasos.

### 5.1 Generación de parámetros de configuración

La herramienta `makecsiparams` genera una cadena codificada en base64 que configura el extractor:

```bash
./makecsiparams -c 157/80 -C 1 -N 1 -m 00:11:22:33:44:55 -b 0x88
```

**Opciones principales:**

| Opción | Descripción                                         |
|--------|-----------------------------------------------------|
| `-c`   | Especificación de canal: `<canal>/<ancho_MHz>`      |
| `-C`   | Máscara de cores donde activar la captura           |
| `-N`   | Máscara de spatial streams a capturar               |
| `-m`   | Filtro por dirección MAC origen (hasta 4, separadas por coma) |
| `-b`   | Filtro por primer byte de la trama (p.ej., `0x88` = QoS Data) |
| `-d`   | Retardo en µs tras cada operación CSI               |
| `-e`   | Activar/desactivar la colección (1/0)               |
| `-h`   | Muestra la ayuda completa                           |

### 5.2 Configuración del extractor

```bash
# La interfaz WiFi del RT-AC86U es eth6
ifconfig eth6 up

# Configurar el extractor con los parámetros generados
nexutil -ieth6 -s500 -b -l34 -v<m+IBEQGIAgAAESIzRFWqu6q7qrsAAAAAAAAAAAAAAAAAAA==>
```

### 5.3 Activación del modo monitor

```bash
/usr/sbin/wl -i eth6 monitor 1
```

### 5.4 Captura de paquetes CSI

Los paquetes CSI se envían como datagramas UDP al puerto 5500:

```bash
# Capturar en el propio router
tcpdump -i eth6 dst port 5500 -w captura.pcap

# O desde un ordenador en la misma red
# (los paquetes se mandan a 255.255.255.255:5500)
tcpdump dst port 5500 -w captura.pcap
```

### 5.5 Ejemplo completo

```bash
# Terminal 1: en el router
ssh admin@192.168.1.1

# Generar parámetros (canal 36, 20 MHz, core 0, SS 1, filtro MAC)
# (ejecutado desde la máquina de desarrollo o desde el router si makecsiparams está presente)
makecsiparams -c 36/20 -C 1 -N 1 -m aa:bb:cc:dd:ee:ff -b 0x88

# Configurar
ifconfig eth6 up
nexutil -ieth6 -s500 -b -l34 -v<parametros_generados>

# Activar monitor
/usr/sbin/wl -i eth6 monitor 1

# Capturar
tcpdump -i eth6 dst port 5500 -w captura.pcap
```

---

## 6. Ecosistema de herramientas Python

El directorio `utils/matlab/` contiene un conjunto de herramientas Python para el análisis, visualización y clasificación de los datos CSI capturados. Todas las herramientas están diseñadas específicamente para el chip **bcm4366c0** y el formato de paquete extendido.

### 6.0 Recomendaciones previas para nuevos usuarios

Si no estás familiarizado con Python o el desarrollo web, las siguientes recomendaciones te ayudarán a empezar sin problemas.

#### Entorno virtual de Python

Se recomienda trabajar dentro de un **entorno virtual** para aislar las dependencias del proyecto del sistema base. Esto evita conflictos entre versiones de librerías y garantiza la reproducibilidad del entorno:

```bash
# 1. Abre una terminal en el directorio utils/matlab/
cd nexmon_csi/utils/matlab

# 2. Crea un entorno virtual (solo la primera vez)
python3 -m venv .venv

# 3. Activa el entorno virtual
source .venv/bin/activate

# En Windows (PowerShell): .venv\Scripts\activate
# En Windows (CMD): .venv\Scripts\activate.bat

# 4. Instala las dependencias del proyecto
pip install -r requirements.txt
```

A partir de este momento, todos los comandos Python que ejecutes usarán las librerías instaladas en el entorno virtual, sin afectar al sistema. Para salir del entorno, ejecuta:

```bash
deactivate
```

Cada vez que retomes el trabajo, recuerda activar el entorno de nuevo (`source .venv/bin/activate`).

#### Editor recomendado: Visual Studio Code

Se recomienda usar **Visual Studio Code** (VS Code) como editor por su integración nativa con Python y entornos virtuales:

1. Descarga VS Code desde [code.visualstudio.com](https://code.visualstudio.com/)
2. Abre la carpeta del proyecto (`nexmon_csi/`)
3. Instala la extensión **Python** de Microsoft (pub.creator: `ms-python.python`)
4. Cuando abras un archivo `.py`, VS Code te preguntará si quieres usar el entorno virtual `.venv/` como intérprete — acepta la sugerencia

**Características útiles de VS Code para este proyecto:**

- **Terminal integrada** (`Ctrl+Ñ` o `Cmd+Ñ`): ejecuta comandos sin salir del editor
- **Depurador** (`F5`): establece puntos de interrupción y examina variables mientras se ejecuta el código
- **Autocompletado** y **análisis estático**: detecta errores antes de ejecutar
- **Explorador de archivos** integrado para navegar por la estructura del proyecto

Alternativas válidas incluyen **PyCharm** (IDE completo para Python) o **Cursor** (editor basado en VS Code con asistencia de IA integrada).

#### Estructura de archivos

Todo el código Python se encuentra en `utils/matlab/`. Los archivos generados (capturas PCAP, imágenes exportadas, resultados de clasificación) se almacenan en subdirectorios dentro de esta misma carpeta, siguiendo la convención del proyecto.

### 6.1 `csireader_extended.py`

Lector de CSI para terminal que parsea archivos PCAP con el formato UDP extendido (18 bytes de header).

#### Instalación

```bash
cd utils/matlab
pip install -r requirements.txt
```

#### Configuración

Edita las variables en `csireader_extended.py`:

```python
CHIP = '4366c0'              # Chip WiFi
BW = 20                      # Ancho de banda en MHz
FILE = './captura.pcap'      # Archivo PCAP
NPKTS_MAX = 300              # Máximo de paquetes a procesar
PLOT_MODE = 'consolidated'   # Modo: 'interactive', 'static', 'consolidated'
NORMALIZE = True             # Normalizar magnitud CSI
SAVE_NPZ = False             # Exportar a .npz
SHOW_TABLE = True            # Mostrar tabla resumen
```

#### Ejecución

```bash
python csireader_extended.py
```

#### Salida

1. **Tabla resumen** con RSSI, número de secuencia, MAC, core, SS, canal y ancho de banda por paquete.
2. **Estadísticas**: RSSI mínimo, máximo, media, desviación estándar; tasa de pérdida de paquetes; número de transmisores detectados.
3. **Visualizaciones** (modo consolidado):
   - Amplitudes superpuestas de todos los paquetes
   - RSSI vs tiempo
   - Mapa de calor de amplitudes
   - Mapa de calor de RSSI
   - Amplitud media con desviación estándar
   - Fases superpuestas
4. **Exportación a `.npz`** con los datos CSI como array complejo y toda la metadata.

---

### 6.2 `csi_web` — Visualizador web de capturas

Interfaz web para explorar, visualizar y etiquetar archivos PCAP de CSI. Construida con **FastAPI**, **matplotlib** y **JavaScript vanilla**, permite dos modos de operación y está diseñada para trabajar con la estructura de directorios del proyecto.

#### 6.2.1 Arquitectura

```
csi_web/
├── app.py                  # Servidor FastAPI (punto de entrada)
├── path_resolve.py         # Resolución de rutas en el sistema de archivos
├── pcap_summary.py         # Resumen rápido de archivos PCAP
├── python_preview_window.py # Ventana interactiva Matplotlib
├── requirements.txt        # Dependencias Python
├── static/
│   ├── index.html          # Interfaz de usuario
│   ├── app.js              # Lógica frontend
│   └── style.css           # Estilos
└── uploads/                # Archivos subidos temporalmente
```

#### 6.2.2 Instalación y arranque

```bash
cd utils/matlab/csi_web

# Crear y activar entorno virtual
python3 -m venv .venv
source .venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Arrancar servidor de desarrollo
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

Abrir en el navegador: `http://127.0.0.1:8000/`

#### 6.2.3 Modo explorador (GOLD_DISK)

El modo explorador permite navegar por los archivos PCAP almacenados en `pcap_files/mydata/GOLD_DISK/`. La estructura de directorios esperada es:

```
pcap_files/mydata/GOLD_DISK/
├── experimento_001/
│   ├── captura_157_80_10s_157_80_20260315_170304.pcap
│   └── captura_36_20_30s_36_20_20260315_171200.pcap
├── experimento_002/
│   └── ...
└── ...
```

El sistema de resolución de rutas (`path_resolve.py`) garantiza que:
- No se puede navegar fuera del directorio base (`GOLD_DISK`)
- Las rutas con `..` son rechazadas
- Se muestran solo archivos `.pcap` y directorios
- Las carpetas de exportación generadas (que terminan en `_edge_impulse`) se ocultan automáticamente

**Funcionalidades del explorador:**

- Navegación por directorios con botón "Subir carpeta"
- Búsqueda textual de archivos `.pcap` (por nombre, recorre recursivamente)
- Selección múltiple de archivos para procesamiento por lotes

#### 6.2.4 Modo subida

Permite cargar archivos PCAP desde cualquier carpeta del ordenador local:

1. Seleccionar una carpeta con el selector de archivos (el navegador incluye todas las subcarpetas)
2. Elegir un archivo `.pcap` de la lista
3. Pulsar "Subir" (el archivo se copia al directorio `uploads/`)
4. El límite de subida es de 500 MiB

#### 6.2.5 Resumen del archivo

Una vez seleccionado un PCAP (por exploración o subida), la aplicación muestra:

- Nombre del fichero
- Paquetes CSI válidos
- Duración de la captura (extraída del nombre del fichero)
- Cores detectados
- Tasa de paquetes por segundo
- Estado de exportación de imágenes (si ya se generaron)

#### 6.2.6 Vista previa (mapas de calor)

La aplicación genera mapas de calor de amplitud CSI para cada core y, opcionalmente, una vista combinada que suma las contribuciones de todos los cores.

**Vista normal**: Genera un mapa de calor por core, dispuesto en una cuadrícula:

```
┌──────────────┬──────────────┐
│   Core 0     │   Core 1     │
├──────────────┼──────────────┤
│   Core 2     │   Core 3     │
└──────────────┴──────────────┘
```

**Vista combinada**: Suma las matrices de CSI de todos los cores recortadas al mínimo número de paquetes común, produciendo un único mapa de calor que agrega la información de las cuatro antenas.

La generación de la previsualización sigue el siguiente flujo:

```
1. Parsear el PCAP con csireader_master._collect_csi_packets_interval()
2. Agrupar vectores CSI por core (core_groups)
3. Construir matriz 2D para cada core (paquetes × subportadoras)
4. Generar PNG con matplotlib (backend Agg, sin abrir ventana)
5. Devolver imagen como respuesta HTTP (StreamingResponse)
```

Además, se puede abrir una **ventana interactiva de Matplotlib** en el propio ordenador (endpoint `/api/preview-python`), que permite explorar los datos con las herramientas interactivas estándar de Matplotlib (zoom, pan, guardar).

#### 6.2.7 Sistema de etiquetado

El panel de etiquetado permite asignar categorías a intervalos de paquetes dentro de una captura. Las etiquetas disponibles son:

| Etiqueta     | Descripción                          |
|--------------|--------------------------------------|
| `movimiento` | Actividad con movimiento en el entorno |
| `vacio`      | Entorno sin actividad                 |
| `presencia`  | Presencia estática sin movimiento     |

El flujo de etiquetado es:

1. Seleccionar un PCAP
2. Definir intervalo en segundos (inicio y fin)
3. Elegir etiqueta y core (o "Todos")
4. Añadir la etiqueta a la lista
5. Guardar las etiquetas (se almacenan en un archivo `labels.json` junto al PCAP)

Las etiquetas se guardan en el siguiente formato JSON:

```json
{
  "pcap_name": "captura_157_80_10s_157_80_20260315_170304.pcap",
  "labels": [
    {
      "label": "movimiento",
      "start_packet": 1,
      "end_packet": 150,
      "core": "all"
    },
    {
      "label": "vacio",
      "start_packet": 151,
      "end_packet": 300,
      "core": "0"
    }
  ]
}
```

#### 6.2.8 Exportación a imágenes para Edge Impulse

Esta funcionalidad genera imágenes PNG de ventanas deslizantes de ~1 segundo (con solapamiento del 50% por defecto) para ser utilizadas como conjunto de entrenamiento en [Edge Impulse](https://edgeimpulse.com/) u otras plataformas de aprendizaje automático.

**Parámetros de exportación:**

- **Solapamiento**: 50% (por defecto) o 0% (ventanas sin solapar, activando `no_overlap`)
- **Imágenes**: Siempre en color (RGB), usando el colormap `jet`
- **Etiquetado automático**: Si el nombre del archivo contiene `movimiento` o `vacio`, se detecta automáticamente
- **Etiquetado manual**: Si se han guardado etiquetas, se pueden generar imágenes con nombre de etiqueta
- **Modo combinado**: Exporta imágenes de la suma de todos los cores

El tamaño de ventana se calcula automáticamente:

```python
packet_rate = total_packets / duration_seconds    # paquetes/s
window_packets = round_down_to_ten(packet_rate)   # ~1 segundo
stride = window_packets // 2                      # 50% solapamiento
```

Las imágenes se exportan en la siguiente estructura:

```
captura.pcap/
└── captura_edge_impulse/
    └── ov50/
        ├── core0/
        │   ├── img_000001_pkts_000001_000050.png
        │   └── ...
        ├── core1/
        ├── core2/
        ├── core3/
        └── combined/    # (si se selecciona modo combinado)
```

---

### 6.3 `CNN` — Clasificación multicore vía API Edge Impulse

Interfaz web que permite comparar las predicciones de cuatro modelos de Edge Impulse (uno por core) sobre el mismo conjunto de imágenes.

#### 6.3.1 Configuración

```bash
cd utils/matlab/CNN
cp config/projects.local.example.json config/projects.local.json
```

Editar `config/projects.local.json` con las credenciales de los proyectos de Edge Impulse:

```json
{
  "core0": { "projectId": "...", "apiKey": "...", "impulseId": null },
  "core1": { "projectId": "...", "apiKey": "...", "impulseId": null },
  "core2": { "projectId": "...", "apiKey": "...", "impulseId": null },
  "core3": { "projectId": "...", "apiKey": "...", "impulseId": null }
}
```

#### 6.3.2 Arranque

```bash
pip install -r requirements.txt
python3 app.py
# Abrir http://127.0.0.1:5050
```

#### 6.3.3 Flujo de uso

1. Seleccionar experimento (directorio dentro de `GOLD_DISK`)
2. Seleccionar carpeta dentro del experimento
3. Seleccionar la carpeta OV (`ov0`, `ov50`, etc.)
4. Pulsar "Ejecutar clasificación por lote"

#### 6.3.4 Resultados

Se generan cuatro archivos en `outputs/<experimento>/`:

- **`*_comparativa_horizontal.csv`**: Una fila por imagen con predicciones de los cuatro cores, más hard vote y soft vote.
- **`*_etiquetas_erroneas.csv`**: Imágenes donde el voto no coincide con la etiqueta esperada.
- **`*_detalle_por_core.csv`**: Una fila por imagen y por core (hasta 4× filas).
- **`*_resumen_metricas.json`**: Métricas agregadas por core (accuracy, confianza media, etc.).

---

### 6.4 `CNNv2` — Clasificación local

Permite ejecutar la inferencia de los modelos CNN **completamente en local**, sin necesidad de conexión a internet ni API de Edge Impulse. Utiliza los modelos compilados a C++ exportados desde Edge Impulse.

#### 6.4.1 Compilación de los modelos

```bash
cd utils/matlab/CNNv2

# Compilar los cuatro modelos
python3 build_local_models.py

# O compilar solo un core específico
python3 build_local_models.py --core core0
```

Esto genera los binarios:

```
build/core0/app
build/core1/app
build/core2/app
build/core3/app
```

Cada binario es un ejecutable C++ que:
1. Lee un archivo de features (píxeles PNG convertidos a texto)
2. Ejecuta `run_classifier()` (de Edge Impulse SDK)
3. Devuelve un JSON con las probabilidades por clase

#### 6.4.2 Interfaz web

```bash
python3 app.py
# Abrir http://127.0.0.1:5051
```

La interfaz permite:
- Seleccionar experimento, carpeta y OV
- Configurar timeout por imagen
- Forzar re-etiquetado
- Visualizar resultados por core y métodos de ensemble

#### 6.4.3 Métodos de ensemble

| Método                     | Descripción                                         |
|----------------------------|-----------------------------------------------------|
| **Hard vote**              | Predicción por mayoría entre los 4 cores.           |
| **Soft vote**              | Media de probabilidades entre cores.                |
| **Weighted soft vote**     | Media ponderada por accuracy histórica de cada core.|
| **Adaptive weighted vote** | Ponderación adaptativa basada en ventana deslizante de confianza. |

#### 6.4.4 Inferencia desde línea de comandos

```python
from local_infer import classify_image_local, extract_top_result

resultado = classify_image_local('core0', 'ruta/imagen.png')
etiqueta, confianza = extract_top_result(resultado)
print(f"Predicción: {etiqueta} (confianza: {confianza:.2f})")
```

---

### 6.5 Scripts complementarios

| Script | Descripción |
|--------|-------------|
| `plotcsi_extended.py` | Funciones de visualización con RSSI y metadata. Modos: interactivo, estático, consolidado con 6 subplots. |
| `plotcsi.py` | Visualización básica (modo interactivo, estático y consolidado). |
| `export_csimaster_window_images.py` | Exportación de imágenes por ventanas deslizantes desde terminal (sin interfaz web). |
| `csireader_batch.py` | Procesamiento por lotes de múltiples archivos PCAP. |
| `csireader_difference.py` | Análisis de diferencias entre capturas. |
| `pcap_summary.py` | Resumen rápido de un PCAP: frames totales, CSI válidos, duración, tasa. |
| `compare_formats.py` | Comparación entre formato antiguo (16 bytes) y nuevo (18 bytes). |
| `example_parse_header.py` | Inspección detallada de headers UDP. |
| `list_unique_macs_pcap.py` | Lista las direcciones MAC únicas en una captura. |
| `plot_rssi_by_antenna.py` | Visualización de RSSI por antena. |
| `verify_subcarrier_removal.py` | Verifica la eliminación de subportadoras null/guard. |

---

## 7. Preguntas frecuentes

<details>
<summary><strong>No recibo paquetes CSI en el puerto 5500</strong></summary>

> Verifica los siguientes puntos:
> * La interfaz correcta es `eth6` (no `wlan0`). El router Asus denomina `eth6` a la interfaz WiFi de 5 GHz.
> * Confirma que el módulo `dhd.ko` parcheado está cargado: `lsmod | grep dhd`. Si no aparece, cárgalo con `insmod /jffs/dhd.ko`.
> * Comprueba que el monitor mode está activo: ejecuta `wl -i eth6 monitor 1` y verifica el resultado.
> * Asegúrate de que el filtro de MAC en `makecsiparams -m` coincide con la dirección del transmisor. La dirección MAC debe ser la del **segundo campo** de la cabecera 802.11 (dirección del transmisor).
> * Verifica que el canal configurado es correcto: `wl -i eth6 chanspec`.
> * Si el chanspec devuelto es `0x6863` (85/160), la interfaz no está correctamente activada.
>
</details>

<details>
<summary><strong>¿Cómo persisto el módulo dhd.ko después de reiniciar?</strong></summary>

> En routers Asus con firmware Merlin, puedes añadir un script en `/jffs/scripts/post-mount`:
> ```bash
> #!/bin/sh
> if [ "$1" = "/jffs" ]; then
>     /sbin/insmod /jffs/dhd.ko
> fi
> ```
> Asegúrate de que el script tenga permisos de ejecución: `chmod +x /jffs/scripts/post-mount`.
>
</details>

<details>
<summary><strong>¿Qué son los cores y spatial streams?</strong></summary>

> El bcm4366c0 dispone de **4 cores**, que se corresponden con las 4 antenas físicas del router (configuración 4×4 MIMO). Cada core puede recibir una o más spatial streams. En la configuración típica, se captura 1 spatial stream por core, obteniendo 4 vectores CSI independientes por trama recibida, uno por antena.
>
</details>

<details>
<summary><strong>¿Por qué algunas subportadoras muestran valores extraños?</strong></summary>

> Los datos CSI incluyen todas las subportadoras, incluyendo las **null carriers** y **guard carriers**, que no transportan datos y pueden contener valores arbitrarios. Para 20 MHz, las subportadoras a eliminar son los índices `-32..-29, 0, +29..+31`. Para 40 MHz: `-64..-59, -1..+1, +59..+63`. Para 80 MHz: `-128..-123, -1..+1, +123..+127`.
>
</details>

<details>
<summary><strong>¿Cómo controlar la tasa de extracción?</strong></summary>

> El extractor funciona por trama recibida. La tasa de extracción está determinada por el transmisor: a más tráfico WiFi, más paquetes CSI. Se puede usar `ping -f` o `iperf` para generar tráfico desde el transmisor.
>
</details>

<details>
<summary><strong>¿Puedo usar este fork para otros routers?</strong></summary>

> Este fork está adaptado exclusivamente para routers con chip **bcm4366c0** (RT-AC86U, RT-AC88U, RT-AC3100). Para otros chips, consulta el repositorio upstream de seemoo-lab.
>
</details>

<details>
<summary><strong>El visualizador csi_web no encuentra mis archivos</strong></summary>

> Por defecto, csi_web busca los PCAP en `utils/matlab/pcap_files/mydata/GOLD_DISK/`. Puedes sobrescribir esta ruta con la variable de entorno `GOLD_DISK_DIR`:
> ```bash
> export GOLD_DISK_DIR="/ruta/a/mis/datos"
> uvicorn app:app --reload --port 8000
> ```
> También puedes usar el modo "Subir carpeta" para cargar PCAPs desde cualquier ubicación.
>
</details>

<details>
<summary><strong>¿Qué tamaño de imagen esperan los modelos CNN?</strong></summary>

> Los modelos exportados de Edge Impulse esperan imágenes de **85×50 píxeles**. Las herramientas de exportación generan automáticamente imágenes con este tamaño.
>
</details>

---

## 8. Licencia y atribuciones

### 8.1 Licencia

El uso de este software está sujeto a los términos de la licencia MIT incluida en el repositorio original. Cualquier uso que resulte en una publicación académica debe incluir las citas indicadas en la sección 8.2.

### 8.2 Citas requeridas

a) **Nexmon: The C-based Firmware Patching Framework**
   Matthias Schulz, Daniel Wegemer and Matthias Hollick.
   https://nexmon.org

b) **Free Your CSI: A Channel State Information Extraction Platform For Modern Wi-Fi Chipsets**
   Francesco Gringoli, Matthias Schulz, Jakob Link, and Matthias Hollick.
   In Proceedings of the 13th Workshop on Wireless Network Testbeds, Experimental evaluation & CHaracterization (WiNTECH 2019), October 2019.
   https://doi.org/10.1145/3349623.3355477

```bibtex
@electronic{nexmon:project,
    author = {Schulz, Matthias and Wegemer, Daniel and Hollick, Matthias},
    title = {Nexmon: The C-based Firmware Patching Framework},
    url = {https://nexmon.org},
    year = {2017}
}

@inproceedings{10.1145/3349623.3355477,
    author = {Gringoli, Francesco and Schulz, Matthias and Link, Jakob and Hollick, Matthias},
    title = {Free Your CSI: A Channel State Information Extraction Platform For Modern Wi-Fi Chipsets},
    year = {2019},
    url = {https://doi.org/10.1145/3349623.3355477},
    booktitle = {Proceedings of the 13th International Workshop on Wireless Network Testbeds, Experimental Evaluation & Characterization},
    pages = {21–28},
    series = {WiNTECH '19}
}
```

### 8.3 Contacto original

- Francesco Gringoli <francesco.gringoli@unibs.it>
- Matthias Schulz <mschulz@seemoo.tu-darmstadt.de>
- Jakob Link <jlink@seemoo.tu-darmstadt.de>

### 8.4 Powered By

**Secure Mobile Networking Lab (SEEMOO)** — Technische Universität Darmstadt
**Multi-Mechanisms Adaptation for the Future Internet (MAKI)**
**LOEWE centre emergenCITY**
**University of Brescia**

---

*Este README corresponde al fork mantenido por [@adrialejo2702](https://github.com/adrialejo2702). Para el proyecto original, visita [seemoo-lab/nexmon_csi](https://github.com/seemoo-lab/nexmon_csi).*
