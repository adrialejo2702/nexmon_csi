
![NexMon logo](https://github.com/seemoo-lab/nexmon/raw/master/gfx/nexmon.png)

# Nexmon Channel State Information Extractor — Adaptación para Asus RT-AC86U

> **Fork mantenido por [@adrialejo2702](https://github.com/adrialejo2702)**

Este repositorio es un fork de [seemoo-lab/nexmon_csi](https://github.com/seemoo-lab/nexmon_csi) adaptado para su uso exclusivo en routers Asus con chipset Broadcom **bcm4366c0** (RT-AC86U, RT-AC88U, RT-AC3100). El proyecto original permite extraer Channel State Information (CSI) de tramas Wi-Fi OFDM (802.11a/g/n/ac) por trama individual con hasta 80 MHz de ancho de banda.

## Herramientas desarrolladas

Todo el código correspondiente a las herramientas web de visualización, etiquetado y clasificación se encuentra en la rama [`python_adaptation`](https://github.com/adrialejo2702/nexmon_csi/tree/python_adaptation):

- **`csi_web/`** — Visualizador web de capturas PCAP con mapas de calor, etiquetado y exportación a Edge Impulse
- **`CNN/`** — Clasificación multicore vía API de Edge Impulse
- **`CNNv2/`** — Clasificación local con modelos compilados C++ (sin conexión a internet)
- **`csireader_extended.py`** — Lector CSI con soporte para el formato UDP extendido (18 bytes, PR#256)
- **Scripts complementarios** — Exportación por ventanas, procesamiento por lotes, análisis de diferencias

Para la documentación detallada de las herramientas, instrucciones de instalación y ejemplos de uso, consulta el [`README.md` en la rama `python_adaptation`](https://github.com/adrialejo2702/nexmon_csi/blob/python_adaptation/README.md).

## Instalación base (firmware parcheado)

Las instrucciones para compilar e instalar el firmware parcheado en el router Asus RT-AC86U siguen los pasos descritos en el [repositorio original](https://github.com/seemoo-lab/nexmon_csi#bcm4366c0), adaptados para este fork.

## Licencia y atribuciones

Este trabajo se basa en el proyecto Nexmon de SEEMOO Lab (TU Darmstadt). Cualquier publicación académica debe incluir las citas correspondientes al proyecto original. Ver el `README.md` en la rama `python_adaptation` para los detalles completos de licencia y referencias.
