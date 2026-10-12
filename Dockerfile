FROM php:8.3-apache
RUN a2enmod headers rewrite
COPY licenca/ /var/www/html/licenca/
COPY index.php /var/www/html/index.php
RUN mkdir -p /var/www/html/licenca/data && chown -R www-data:www-data /var/www/html/licenca/data && chmod 750 /var/www/html/licenca/data
