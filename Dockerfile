FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p instance static/uploads

# Expose port
EXPOSE 3005

# Run with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:3005", "--workers", "4", "--timeout", "120", "app:app"]
