# Web UI para comparar clasificación por antena (core0..core3)

Esta interfaz permite evaluar un experimento de `GOLD_DISK` con 4 modelos de Edge Impulse (uno por core) y exportar una tabla horizontal para tu TFG.

> **Ubicación:** este directorio (`utils/matlab/CNN/`) contiene únicamente el código de la app. Los datos de los experimentos viven en `utils/matlab/pcap_files/mydata/GOLD_DISK/` (carpeta ignorada por git). Si tus datos están en otra ruta, exporta la variable de entorno `GOLD_DISK_DIR` antes de lanzar la app:
>
> ```bash
> export GOLD_DISK_DIR="/ruta/absoluta/a/GOLD_DISK"
> python3 app.py
> ```

## 1) Configuración (una vez)

1. Copia el ejemplo:

```bash
cp config/projects.local.example.json config/projects.local.json
```

2. Edita `config/projects.local.json` con tus datos reales:
   - `projectId` y `apiKey` para cada `core0..core3`
   - `impulseId` opcional (si no aplica, deja `null`)

## 2) Arranque

```bash
python3 -m pip install -r requirements.txt
python3 app.py
```

Abre en navegador: `http://127.0.0.1:5050`

## 3) Flujo de uso

1. Selecciona experimento (por ejemplo `20260420`).
2. Selecciona cualquier carpeta dentro del experimento (la que quieras procesar, por ejemplo una carpeta `..._edge_impulse`).
3. Selecciona la carpeta `OV` (por ejemplo `ov0`, `ov50`, etc.).
4. Pulsa "Ejecutar clasificación por lote".

## 4) Qué exporta

Los resultados se guardan en `outputs/`:

- `*_comparativa_horizontal.csv` (clave para comparar core0/core1/core2/core3 por imagen)
- `*_cores_con_diferencias.csv` (solo imágenes donde los cores no coinciden en decisión)
- `*_detalle_por_core.csv` (detalle completo por imagen y core)
- `*_resumen_metricas.json` (accuracy por core y score medio)

Notas de guardado:
- Si cancelas una ejecución, no se guarda ningún archivo nuevo.
- Si ya existen resultados para la misma selección (experimento + carpeta objetivo + subcarpeta), la app reutiliza los archivos existentes y no vuelve a generarlos.
