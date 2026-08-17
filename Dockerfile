# meshtastic-reticulum-bridge -- Meshtastic MQTT -> Reticulum/LXMF, one-way v1.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip install --no-cache-dir \
    fastapi==0.115.5 "uvicorn[standard]==0.32.1" pydantic==2.10.3 \
    rns lxmf "paho-mqtt==2.1.0" "cryptography>=42" "meshtastic==2.7.11"
COPY app.py /app/
EXPOSE 8212
CMD ["python", "app.py"]
