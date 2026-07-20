FROM python:3.12-slim

WORKDIR /app

# system deps for building eth-hash pycryptodome wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cassandra ./cassandra
COPY web ./web

ENV HOST=0.0.0.0 PORT=8000
EXPOSE 8000

CMD ["uvicorn", "cassandra.server:app", "--host", "0.0.0.0", "--port", "8000"]
