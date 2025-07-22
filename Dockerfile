# Use an official Ubuntu base image
FROM ubuntu:22.04

# Set environment variables to prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt update && apt install -y \
    apache2 \
    libapache2-mod-wsgi-py3 \
    python3 \
    python3-pip \
    python3-venv \
    libpq-dev \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /var/www/homework-website

# Copy Django project files
COPY . /var/www/homework-website

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Collect static files and migrate
RUN python3 manage.py collectstatic --noinput

# Set correct permissions
RUN chown -R www-data:www-data /var/www/homework-website

# Copy and enable Apache configuration
COPY homework-website.conf /etc/apache2/sites-available/homework-website.conf
RUN a2enmod wsgi ssl rewrite headers && \
    a2ensite homework-website.conf

# Expose port 80 for Apache
EXPOSE 80
EXPOSE 443

# Start Apache
CMD ["apache2ctl", "-D", "FOREGROUND"]