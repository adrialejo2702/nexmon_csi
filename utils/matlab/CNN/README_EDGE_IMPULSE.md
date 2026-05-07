# Probar modelo entrenado de Edge Impulse con datos locales

Este directorio incluye un flujo para probar un modelo ya entrenado usando API key y archivos de imagen locales.

## 1) Confirmar endpoint y autenticación

- Endpoint de inferencia de imagen en Studio:
  - `POST https://studio.edgeimpulse.com/v1/api/{projectId}/classify/image`
- Autenticación:
  - Header `x-api-key: <API_KEY>`
- Envío:
  - `multipart/form-data` con campo `image`

## 2) Prueba mínima con curl (una imagen)

```bash
curl -X POST "https://studio.edgeimpulse.com/v1/api/<PROJECT_ID>/classify/image" \
  -H "x-api-key: <API_KEY>" \
  -F "image=@/ruta/local/mi_imagen.jpg"
```

Opcionalmente puedes fijar `impulseId`:

```bash
curl -X POST "https://studio.edgeimpulse.com/v1/api/<PROJECT_ID>/classify/image?impulseId=<IMPULSE_ID>" \
  -H "x-api-key: <API_KEY>" \
  -F "image=@/ruta/local/mi_imagen.jpg"
```

## 3) Script Python (una imagen o lote)

Archivo: `edge_impulse_infer.py`

### 3.1 Una imagen

```bash
python3 edge_impulse_infer.py \
  --project-id "<PROJECT_ID>" \
  --api-key "<API_KEY>" \
  --image "/ruta/local/mi_imagen.jpg"
```

Con `impulseId` opcional:

```bash
python3 edge_impulse_infer.py \
  --project-id "<PROJECT_ID>" \
  --api-key "<API_KEY>" \
  --impulse-id "<IMPULSE_ID>" \
  --image "/ruta/local/mi_imagen.jpg"
```

### 3.2 Lote desde carpeta

```bash
python3 edge_impulse_infer.py \
  --project-id "<PROJECT_ID>" \
  --api-key "<API_KEY>" \
  --input-dir "/ruta/local/carpeta_imagenes" \
  --output-json "edge_impulse_results.json" \
  --output-csv "edge_impulse_results.csv"
```

El script detecta extensiones: `.jpg`, `.jpeg`, `.png`, `.bmp`, `.gif`, `.webp`.

## 4) Qué revisar en la respuesta

- `success`: indica si la inferencia fue correcta.
- `result`: probabilidades por etiqueta para clasificación.
- `boundingBoxes`: si el modelo devuelve detecciones de objetos.
- `error`: detalle del problema si falla la petición.

## 5) Recomendaciones de preprocesado

- Usa imágenes con condiciones similares a entrenamiento (iluminación, encuadre, distancia).
- Verifica formato y calidad de imagen para evitar ruido en predicción.
- Si hay múltiples impulses, prueba explícitamente con `impulseId`.
