"""
Gunicorn Configuration for Production Deployment
Optimized for Saudi Cyber Security Tool
"""

import multiprocessing
import os

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50

# Timeout settings
timeout = 30
keepalive = 2

# Logging
accesslog = "-"  # Log to stdout
errorlog = "-"   # Log to stderr
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "saudi-cyber-tool"

# Security
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# Preload application
preload_app = True

# User and group (change according to your system)
# user = "www-data"
# group = "www-data"

# Environment variables
raw_env = [
    "FLASK_ENV=production",
    "FLASK_DEBUG=False"
]