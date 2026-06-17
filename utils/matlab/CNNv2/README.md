# CNNv2 - Clasificacion local por core

Este directorio contiene el setup para ejecutar en local las redes CNN entrenadas en Edge Impulse para los cuatro cores (`core0`, `core1`, `core2` y `core3`). La idea es poder clasificar lotes de imagenes ya generadas, comparar el rendimiento de cada core y estudiar metodos de combinacion entre antenas/cores.

## Estructura principal

- `app.py`: interfaz web local para lanzar clasificaciones por lote y visualizar resultados.
- `local_infer.py`: convierte cada imagen PNG a features y ejecuta el binario local del core correspondiente.
- `build_local_models.py`: compila los modelos C++ exportados desde Edge Impulse.
- `tools/local_runner.cpp`: wrapper C++ que carga las features, ejecuta `run_classifier` y devuelve JSON.
- `cnn-nexmon-core-*`: exportaciones C++ de Edge Impulse, una por core.
- `build/core*/app`: binarios locales generados tras compilar.
- `outputs/`: resultados exportados por experimento, carpeta y OV.

## Preparacion

Desde este directorio:

```bash
python3 build_local_models.py
```

Esto compila los cuatro modelos y genera:

```text
build/core0/app
build/core1/app
build/core2/app
build/core3/app
```

Tambien se puede compilar solo un core:

```bash
python3 build_local_models.py --core core0
```

O limpiar el build anterior antes de compilar:

```bash
python3 build_local_models.py --clean
```

## Ejecucion de la interfaz

Lanzar la aplicacion local:

```bash
python3 app.py
```

Despues abrir:

```text
http://127.0.0.1:5051
```

La interfaz permite seleccionar:

- Experimento.
- Carpeta del experimento.
- Carpeta OV.
- Timeout local por imagen.
- Opcion de forzar re-etiquetado.

## Formato de entrada

Las imagenes se toman desde la estructura de datos del proyecto bajo `pcap_files/mydata/GOLD_DISK`. Para cada seleccion, la aplicacion espera encontrar carpetas por core dentro de la carpeta OV:

```text
ovX/
  core0/
  core1/
  core2/
  core3/
```

Cada imagen debe ser PNG y tener el tamano esperado por el modelo:

```text
85 x 50
```

La etiqueta real se obtiene del nombre del fichero, usando la parte anterior al primer punto.

## Clasificacion por lote

Al ejecutar una clasificacion, la aplicacion:

1. Recorre las imagenes de cada core.
2. Ejecuta el binario local correspondiente.
3. Guarda la prediccion top-1, el score y el vector completo de probabilidades.
4. Construye una tabla horizontal por imagen para comparar los cuatro cores.
5. Calcula metodos ensemble.
6. Exporta CSV y JSON de resumen.

## Reutilizacion y re-etiquetado

Por defecto, si ya existen resultados exportados para una seleccion, la aplicacion los reutiliza para evitar repetir la inferencia.

Si se marca `Forzar re-etiquetado`, la aplicacion ignora los resultados existentes y vuelve a ejecutar la clasificacion completa por lote. Al terminar, los archivos de salida de esa seleccion se vuelven a escribir con los nuevos resultados.

## Metodos de combinacion

### Hard Vote

Cada core aporta una etiqueta. Gana la clase con mas votos.

Si hay empate, el resultado se marca como:

```text
uncertain
```

### Soft Vote

Se promedian las probabilidades de cada clase entre los cores disponibles:

```text
prob_final(clase) = media(prob_core0, prob_core1, prob_core2, prob_core3)
```

Gana la clase con mayor probabilidad media.

### Weighted Soft Vote

Es una variante del soft vote donde no todos los cores pesan igual. Primero se calcula la accuracy individual de cada core frente a la etiqueta real. Luego esa accuracy se normaliza para obtener un peso:

```text
peso_core = accuracy_core / suma_accuracies
```

Despues se combinan las probabilidades:

```text
prob_final(clase) = suma(peso_core * prob_core(clase))
```

Este metodo reduce la influencia de cores que, en ese conjunto, han sido menos fiables.

Nota: en este setup los pesos se calculan sobre el propio conjunto procesado, por lo que el resultado sirve principalmente como analisis interno. Para una validacion mas estricta, los pesos deberian calcularse en un conjunto de validacion separado y aplicarse despues sobre un conjunto de test.

### Adaptive Weighted Soft Vote

Es una extension temporal del voto ponderado. Para cada imagen se miran las cinco imagenes anteriores, ordenadas por el identificador de la imagen, y se calcula la fiabilidad reciente de cada core como la probabilidad media que asigno a la etiqueta correcta:

```text
fiabilidad_reciente_core = media(prob_core(etiqueta_real)) en las ultimas 5 imagenes
```

Despues se mezcla el peso global con el peso reciente:

```text
peso_final_core = beta * peso_global_core + (1 - beta) * peso_reciente_core
```

En esta implementacion:

```text
ventana = 5
beta = 0.6
```

Esto significa que el metodo conserva un 60% de la fiabilidad global del core y usa un 40% de memoria reciente. El resultado se exporta junto con los pesos adaptativos usados en cada imagen para poder analizar cuando la memoria ayuda o perjudica.

## Resultados exportados

Los resultados se guardan bajo:

```text
outputs/<experimento>/<carpeta>/
```

Archivos principales:

- `*_detalle_por_core.csv`: una fila por imagen y core, con prediccion, score, estado y probabilidades.
- `*_comparativa_horizontal.csv`: una fila por imagen, con predicciones de todos los cores y metodos ensemble.
- `*_etiquetas_erroneas.csv`: casos donde al menos un metodo ensemble falla.
- `*_resumen_metricas.json`: resumen por core y metadatos de ejecucion.

## Interpretacion en la interfaz

La interfaz muestra:

- Resumen por core: total de imagenes, llamadas correctas, accuracy y peso usado por `Weighted Soft Vote`.
- Comparativa de metodos: accuracy de cada core, `Hard Vote`, `Soft Vote`, `Weighted Soft Vote` y `Adaptive Weighted Soft Vote`.
- Metricas por clase: precision, recall, F1, macro F1 y numero de muestras.
- Matrices de confusion: errores por clase para cada core y metodo ensemble.
- Tabla principal: predicciones por imagen y resultado de cada metodo.
- Vista de errores: imagenes donde falla algun metodo ensemble, con probabilidades consultables por clase.

## Notas

- Si falta un binario local, ejecutar `python3 build_local_models.py`.
- Si se cambian modelos exportados desde Edge Impulse, recompilar antes de lanzar nuevas pruebas.
- Si se quieren regenerar resultados ya existentes, marcar `Forzar re-etiquetado`.
