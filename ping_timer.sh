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
FIN=$(( START + TIEMPO ))
COUNT=0

while [ "$(date +%s)" -lt "$FIN" ]; do
  # Enviar 1 paquete, sin mostrar salida
  ping -c 1 "$IP" > /dev/null 2>&1
  COUNT=$((COUNT + 1))
  sleep "$INTERVALO"
done

END=$(date +%s)
REAL_TIME=$((END - START))

echo "Paquetes transmitidos: $COUNT"
echo "Tiempo total: ${REAL_TIME}s"
echo "Envío de pings finalizado."