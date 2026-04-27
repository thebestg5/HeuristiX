# HeuristiX Security Scanner - Isolated Docker Environment
# This container provides a sandboxed environment for scanning potentially malicious websites
# If a scanned site attempts to exploit the scanner, it will only affect this container

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Initialize tldextract database (pre-downloads TLD list for faster scans)
RUN python -c "import tldextract; tldextract.TLDExtract().extract('example.com')"

# Copy application code
COPY . .

# Create reports directory with restricted permissions
RUN mkdir -p /app/reports && chmod 700 /app/reports

# Create non-root user for security
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Expose Flask port
EXPOSE 5000

# Health check to ensure the container is responsive
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/api/scans', timeout=5)" || exit 1

# Run the web application
CMD ["python", "app.py"]
