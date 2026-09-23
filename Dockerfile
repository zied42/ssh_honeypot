FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

# Create unprivileged honeypot user
RUN groupadd -g 10001 honeypot && \
    useradd -u 10001 -g honeypot -s /bin/false honeypot

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Create data directory and set permissions
RUN mkdir -p /app/data/logs && \
    chown -R honeypot:honeypot /app

USER honeypot:honeypot

EXPOSE 2222

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import socket; s = socket.socket(); s.connect(('127.0.0.1', 2222)); s.close()" || exit 1

VOLUME ["/app/data"]

CMD ["python", "main.py"]
