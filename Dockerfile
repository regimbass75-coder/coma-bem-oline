FROM php:8.3-apache
RUN a2enmod headers rewrite
RUN apt-get update \
    && apt-get install -y --no-install-recommends libzip-dev \
    && docker-php-ext-install zip \
    && rm -rf /var/lib/apt/lists/*
COPY licenca/ /var/www/html/licenca/
COPY index.php /var/www/html/index.php
COPY atualizar.php /var/www/html/atualizar.php
RUN mkdir -p /var/www/html/licenca/data && chown -R www-data:www-data /var/www/html/licenca/data && chmod 750 /var/www/html/licenca/data
# Corrigir permissoes no volume montado em tempo de execucao, preservando conteudo.
RUN printf '%s\n' '#!/bin/sh' 'set -eu' 'if [ -d /var/data ]; then' '  chown -R www-data:www-data /var/data' '  chmod 750 /var/data' '  echo "[UniGestor] Disco montado; verificando inicializacao PHP como www-data"' '  if ! runuser -u www-data -- php -r '\''require "/var/www/html/licenca/lib.php"; echo "[UniGestor] Inicializacao de dados OK\\n";'\''; then' '    echo "[UniGestor] ERRO: inicializacao de dados falhou; verificando apenas nomes e permissoes"' '    ls -ld /var/data' '    ls -la /var/data | sed -E "s/([0-9]{4,})/[numero]/g" | head -25' '  fi' 'else' '  echo "[UniGestor] ERRO: disco /var/data nao montado"' 'fi' 'exec apache2-foreground' > /usr/local/bin/unigestor-start && chmod 755 /usr/local/bin/unigestor-start
CMD ["unigestor-start"]
