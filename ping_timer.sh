#!/usr/bin/env bash

IP="192.168.8.1"

# Pedir tiempo total en segundos
read -p "Introduce el tiempo total en segundos: " TIEMPO

# Pedir intervalo entre pings en segundos (por ejemplo 0.01)
read -p "Introduce el intervalo entre pings en segundos (por ejemplo 0.01): " INTERVALO

# Validar que TIEMPO es un entero
if ! [[ "$TIEMPO" =~ ^[0-9]+$ ]]; then
  echo "El tiempo debe ser un número entero de segundos."
  exit 1
fi

# Validar que INTERVALO es número (entero o decimal simple)
if ! [[ "$INTERVALO" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  echo "El intervalo debe ser un número (por ejemplo 1 o 0.01)."
  exit 1
fi

echo "Enviando pings a $IP durante $TIEMPO segundos con intervalo $INTERVALO s..."

START=$(date +%s)

OUT_FILE="$(mktemp -t ping_timer.XXXXXX)"

# Un único proceso ping a alta frecuencia; al finalizar lo interrumpimos con SIGINT
# para que imprima el resumen ("packets transmitted").
# En macOS el resumen sale por stdout, así que capturamos stdout+stderr.
ping -i "$INTERVALO" "$IP" >"$OUT_FILE" 2>&1 &
PING_PID=$!

for ((TRANSCURRIDO=0; TRANSCURRIDO<TIEMPO; TRANSCURRIDO++)); do
  printf "\rTiempo transcurrido: %ss" "$TRANSCURRIDO"
  sleep 1
done
printf "\rTiempo transcurrido: %ss\n" "$TIEMPO"

kill -INT "$PING_PID" >/dev/null 2>&1 || true
wait "$PING_PID" >/dev/null 2>&1 || true

END=$(date +%s)
REAL_TIME=$((END - START))

# Extraer el número de "packets transmitted" del resumen (macOS/Linux)
TX="$(awk '
  /packets transmitted/ {
    for (i=1; i<=NF; i++) if ($i=="packets") { print $(i-1); exit }
  }
' "$OUT_FILE")"

rm -f "$OUT_FILE" >/dev/null 2>&1 || true

echo "Paquetes transmitidos: ${TX:-0}"
echo "Tiempo total: ${REAL_TIME}s"
echo "Envío de pings finalizado."