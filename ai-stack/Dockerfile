## Dockerfile  —  Larkspur Alert Dashboard (Streamlit + Ollama client)
## Student: Syed Hadi Hussain  |  Module: B9CY110  |  CA1
##
## Minimal Python image; runs the Streamlit dashboard as a non-root user.
## The container has NO execution capability — it only reads alerts.json
## and calls the Ollama API for text generation.

FROM python:3.11-slim

LABEL maintainer="Syed Hadi Hussain"
LABEL description="Larkspur AI Security Alert Dashboard"

# Create a non-root user for least-privilege operation
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Install Python dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app.py .

# Create a writable temp directory for Streamlit
RUN mkdir -p /tmp/streamlit && chown appuser:appuser /tmp/streamlit

# Switch to non-root user
USER appuser

EXPOSE 8501

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')"

ENTRYPOINT ["streamlit", "run", "app.py", \
  "--server.address=0.0.0.0", \
  "--server.port=8501", \
  "--server.headless=true", \
  "--server.fileWatcherType=none", \
  "--browser.gatherUsageStats=false"]
