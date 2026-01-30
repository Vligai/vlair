FROM python:3.11-slim

LABEL maintainer="Vligai"
LABEL description="vlair - Security Operations Toolkit"
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

# Install vlair as package
RUN pip install -e .

# Create directories for data and output
RUN mkdir -p /data /output

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Volume for input data
VOLUME ["/data", "/output"]

# Default command shows help
ENTRYPOINT ["vlair"]
CMD ["--help"]

# Examples of usage:
# docker run --rm vlair --help
# docker run --rm -v $(pwd)/data:/data vlair ioc /data/report.txt
# docker run --rm -v $(pwd)/data:/data vlair hash --file /data/hashes.txt
# docker run --rm --env-file .env -v $(pwd)/data:/data vlair eml /data/email.eml --vt
