FROM php:8.3-apache
RUN a2enmod headers rewrite
COPY licenca/ /var/www/html/licenca/
COPY index.php /var/www/html/index.php
RUN mkdir -p /var/www/html/licenca/data && chown -R www-data:www-data /var/www/html/licenca/data && chmod 750 /var/www/html/licenca/data
# O disco do Render e montado somente ao iniciar o container; ajustar no build nao basta.
# Preparar o volume antes de iniciar Apache, sem apagar arquivos existentes.
RUN printf '%s\n' '#!/bin/sh' 'set -eu' 'if [ -d /var/data ]; then' '  chown -R www-data:www-data /var/data' '  chmod 750 /var/data' 'fi' 'exec apache2-foreground' > /usr/local/bin/unigestor-start && chmod 755 /usr/local/bin/unigestor-start
CMD ["unigestor-start"]
