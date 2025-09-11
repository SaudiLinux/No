# Multi-stage Dockerfile for Saudi Cyber Security Tool
FROM python:3.11-slim as base

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Gunicorn for production
RUN pip install gunicorn

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs exports reports results

# Create non-root user for security
RUN useradd -m -u 1000 saudi-cyber && \
    chown -R saudi-cyber:saudi-cyber /app

# Switch to non-root user
USER saudi-cyber

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Run with Gunicorn
CMD ["gunicorn", "--config", "gunicorn_config.py", "wsgi:application"]