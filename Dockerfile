FROM python:3.11-slim

LABEL maintainer="Vligai"
LABEL description="SecOps Helper - Security Operations Toolkit"
LABEL version="2.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
# libpcap-dev: Required for scapy (PCAP analysis)
# gcc, python3-dev: Required for building some Python packages
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install SecOps Helper as package
RUN pip install -e .

# Create directories for data and output
RUN mkdir -p /data /output

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Volume for input data
VOLUME ["/data", "/output"]

# Default command shows help
ENTRYPOINT ["secops-helper"]
CMD ["--help"]

# Examples of usage:
# docker run --rm secops-helper --help
# docker run --rm -v $(pwd)/data:/data secops-helper ioc /data/report.txt
# docker run --rm -v $(pwd)/data:/data secops-helper hash --file /data/hashes.txt
# docker run --rm --env-file .env -v $(pwd)/data:/data secops-helper eml /data/email.eml --vt
