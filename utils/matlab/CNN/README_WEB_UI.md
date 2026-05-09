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

Los resultados se guardan en `outputs/<nombre_experimento>/`. Se generan cuatro ficheros por ejecución:

---

### `*_comparativa_horizontal.csv`

Una fila por imagen, con las predicciones de los cuatro cores en columnas. Es el fichero principal para comparar antenas.

| Columna | Descripción |
|---|---|
| `image_key` | Identificador de la imagen (nombre de fichero sin el prefijo de etiqueta) |
| `expected_label` | Etiqueta real extraída del nombre de fichero (ej. `vacio`, `movimiento`) |
| `core0_pred` … `core3_pred` | Etiqueta predicha por cada core |
| `core0_score` … `core3_score` | Probabilidad (0–1) de la etiqueta predicha por cada core |
| `core0_result_json` … `core3_result_json` | JSON con la distribución completa de probabilidades por clase para ese core (ej. `{"movimiento": 0.86, "vacio": 0.14}`) |
| `hard_vote` | Predicción por voto de mayoría entre los cuatro cores. Vale `uncertain` si hay empate (ej. 2 vs 2) |
| `soft_vote` | Predicción por media de probabilidades entre cores (soft voting). Vale `uncertain` si hay empate exacto en la media |

---

### `*_etiquetas_erroneas.csv`

Contiene las imágenes de la vista **Etiquetado Errores**: casos donde `hard_vote` o `soft_vote` no coinciden con la etiqueta esperada.

| Columna | Descripción |
|---|---|
| `image_key` | Identificador de la imagen |
| `expected_label` | Etiqueta real |
| `core0_pred` … `core3_pred` | Etiqueta predicha por cada core |
| `core0_result_json` … `core3_result_json` | JSON con probabilidades completas por clase en cada core |
| `mean_result_json` | JSON con la media de probabilidades entre cores (base de `soft_vote`) |
| `hard_vote` | Etiqueta final por voto mayoritario |
| `soft_vote` | Etiqueta final por media de probabilidades |

---

### `*_detalle_por_core.csv`

Una fila por imagen **y por core** (hasta 4× más filas que el horizontal). Contiene el resultado completo de cada llamada a la API.

| Columna | Descripción |
|---|---|
| `core` | Identificador del core (`core0`…`core3`) |
| `image_path` | Ruta absoluta al fichero de imagen |
| `image_key` | Identificador de la imagen |
| `expected_label` | Etiqueta real |
| `predicted_label` | Etiqueta predicha por la API |
| `score` | Probabilidad de la etiqueta predicha |
| `success` | `True` si la llamada a la API fue exitosa, `False` si hubo error |
| `error` | Mensaje de error si la llamada falló, vacío si fue correcta |
| `result_json` | JSON con la distribución completa de probabilidades por clase |

---

### `*_resumen_metricas.json`

Métricas agregadas por core en formato JSON.

```json
{
  "run_key": "experimento__carpeta__ov0",
  "generated_at": "2026-05-08T14:00:00",
  "summary_per_core": {
    "core0": {
      "total_images": 120,
      "successful_calls": 120,
      "accuracy_vs_filename_label": 0.875,
      "avg_top_score": 0.821
    },
    ...
  }
}
```

| Campo | Descripción |
|---|---|
| `total_images` | Total de imágenes procesadas por ese core |
| `successful_calls` | Llamadas a la API que devolvieron resultado válido |
| `accuracy_vs_filename_label` | Fracción de imágenes donde la predicción coincide con la etiqueta del nombre de fichero |
| `avg_top_score` | Media de la probabilidad de la clase predicha (confianza media del modelo) |

---

### Notas de guardado

- Los ficheros se guardan en `outputs/<nombre_experimento>/`.
- Si cancelas una ejecución, no se guarda ningún archivo.
- Si ya existen resultados para la misma selección (experimento + carpeta + subcarpeta OV), la app reutiliza los archivos existentes sin relanzar la clasificación.
