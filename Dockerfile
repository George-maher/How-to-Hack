FROM php:8.2-fpm

RUN apt-get update && apt-get install -y \
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
    && docker-php-ext-install pdo_mysql pdo_pgsql mbstring exif pcntl bcmath gd sockets \
    && docker-php-ext-enable pdo_pgsql \
    && pecl install redis && docker-php-ext-enable redis

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /var/www

COPY backend/ .

RUN rm -f bootstrap/cache/*.php

RUN cp .env.example .env

RUN rm -f composer.lock && composer install --no-dev --no-scripts \
    && php -r "file_put_contents('.env', preg_replace('/^APP_KEY=(.*)$/m', 'APP_KEY=base64:'.base64_encode(random_bytes(32)), file_get_contents('.env')));" \
    && php artisan package:discover --ansi \
    && php artisan config:clear \
    && php artisan route:clear \
    && php artisan view:clear

RUN mkdir -p storage/logs storage/framework/cache/data \
      storage/framework/sessions storage/framework/views \
      storage/app/public \
    && chmod -R 775 storage bootstrap/cache \
    && chown -R www-data:www-data storage bootstrap/cache

EXPOSE 8000

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD php artisan serve --host=0.0.0.0 --port=8000
