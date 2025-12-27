# Use a slim Python image for a smaller, faster container
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies (including libpq-dev for database drivers)
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /var/www/homework-website

# Install Python dependencies first (better for Docker caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy the rest of your project files
COPY . .

# Set permissions
RUN chown -R www-data:www-data /var/www/homework-website

# Gunicorn runs on port 8000 internally (mapped in docker-compose)
EXPOSE 8000

# Start Gunicorn
# Replace 'mywebsite.wsgi:application' with your actual path if it differs
CMD ["sh", "-c", "python manage.py collectstatic --noinput --clear && gunicorn --bind 0.0.0.0:8000 --workers 2 mywebsite.wsgi:application"]
