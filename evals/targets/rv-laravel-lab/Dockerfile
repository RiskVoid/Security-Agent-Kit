# Ledgerly: RiskVoid's Laravel reference lab (multi-tenant invoicing). Lab use only: seeded flaws.
#   FIXED=0  the vulnerable build (lab-laravel, 10.250.0.16:8000)
#   FIXED=1  the same app with the fixed/ overlay (lab-laravel-fixed, 10.250.0.17:8000), for retests
# The source digest (BUILD) is computed the way the kit's app map computes it from the source tree
# (rvkit source digest v1), so a deployment can be matched to the source it was built from.
FROM composer:2.8 AS build
WORKDIR /app
COPY src/composer.json src/composer.lock ./
RUN composer install --no-dev --no-scripts --no-autoloader --no-interaction --prefer-dist
COPY src/ ./
COPY fixed/ /fixed/
ARG FIXED=0
RUN set -e; if [ "$FIXED" = 1 ]; then cp -R /fixed/. ./; fi; \
    find app bootstrap/app.php bootstrap/providers.php config database resources routes composer.json composer.lock \
      -type f ! -name .gitignore | LC_ALL=C sort | xargs sha256sum | sha256sum | cut -c1-64 > BUILD; \
    composer dump-autoload --optimize --no-dev --no-scripts; \
    mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views storage/logs storage/app/private

FROM php:8.4-cli-alpine
COPY --from=build /app /app
WORKDIR /app
ARG FIXED=0
# artisan serve passes only .env settings to its PHP workers, so everything is in .env
RUN set -e; { echo "APP_NAME=Ledgerly"; echo "APP_ENV=lab"; echo "APP_KEY=base64:cnZsYWItbGVkZ2VybHktbGFiLWtleS0wMDAwMDAwMDA="; \
      echo "APP_URL=http://localhost:8000"; echo "DB_CONNECTION=sqlite"; echo "DB_DATABASE=/app/database/lab.sqlite"; \
      echo "SESSION_DRIVER=file"; echo "CACHE_STORE=file"; echo "QUEUE_CONNECTION=sync"; echo "MAIL_MAILER=log"; \
      echo "LOG_CHANNEL=stderr"; echo "LOG_LEVEL=info"; \
      if [ "$FIXED" = 1 ]; then echo "APP_DEBUG=false"; echo "LAB_VARIANT=fixed"; \
      else echo "APP_DEBUG=true"; echo "LAB_VARIANT=vulnerable"; fi; } > .env; \
    chown -R www-data:www-data storage database bootstrap/cache
ENV PHP_CLI_SERVER_WORKERS=4
USER www-data
EXPOSE 8000
# a fresh database on every start: restarting the container is the lab's reset
CMD ["sh", "-c", "rm -f database/lab.sqlite && touch database/lab.sqlite && php artisan migrate:fresh --seed --force -q && exec php artisan serve --no-reload --host=0.0.0.0 --port=8000"]
