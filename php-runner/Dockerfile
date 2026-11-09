# The optional PHP profile (RW-013): PHP 8.4 and Composer, for parse checks and a runtime route export of a Laravel
# application. Not part of the default toolbox: `./rvkit php` builds it on first use. It runs with no network, a
# read-only root, no capabilities, as the engagement's user, on a throwaway copy of the code (the /src mount stays
# read-only and untouched). Booting the application (routes) runs the client's code: ./rvkit asks first.
FROM composer@sha256:5248900ab8b5f7f880c2d62180e40960cd87f60149ec9a1abfd62ac72a02577c AS composer

FROM php@sha256:b58f9a66fe9734250fc42818edc77d679a071a83cefdcda87b21b668a91094b1
# php:8.4-cli-alpine (PHP 8.4.27), composer:2.8
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
COPY rv-php.php /opt/rv-php/rv-php.php
RUN chmod -R a+rX /opt/rv-php
ENV COMPOSER_HOME=/tmp/composer COMPOSER_DISABLE_NETWORK=1 COMPOSER_NO_INTERACTION=1
WORKDIR /tmp
ENTRYPOINT ["php", "/opt/rv-php/rv-php.php"]
