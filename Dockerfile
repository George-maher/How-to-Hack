# Application image for the Pentest Toolkit API.
#
# Hardening notes:
#  - the process runs as an unprivileged user (www-data), never root;
#  - no Docker CLI and no Docker socket are installed or mounted: this container
#    has no ability to start a scanner. That is the Runner's job;
#  - composer runs with --no-dev and without scripts that could execute
#    arbitrary code at build time.
FROM php:8.2-fpm

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    libssl-dev \
    libpq-dev \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install pdo_pgsql mbstring exif pcntl bcmath gd sockets \
    && pecl install redis && docker-php-ext-enable redis

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www

COPY backend/ .

# The repository ships a stub composer.lock (it cannot be regenerated in this
# environment). Remove it only so the image can build; see docs/security.md for
# why a real lock file should be committed before any production use.
RUN rm -f composer.lock \
    && composer install --no-dev --no-scripts --no-interaction --prefer-dist \
    && rm -f bootstrap/cache/*.php

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

RUN mkdir -p storage/logs storage/framework/cache/data \
      storage/framework/sessions storage/framework/views \
      storage/app/public \
    && chown -R www-data:www-data storage bootstrap/cache \
    && chmod -R 775 storage bootstrap/cache

USER www-data

EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8000"]
