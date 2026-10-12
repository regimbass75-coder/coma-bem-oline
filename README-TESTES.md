# UniGestor — ambiente de homologação PHP isolado

Pacote de preparação, NÃO publicar diretamente.

- Servidor PHP Apache em Docker; código de Painel Master em /licenca/.
- Dados reais e backups não incluídos.
- Não apontar para o PostgreSQL de produção.
- O armazenamento local do Render é efêmero: testes persistentes exigem volume/banco próprio.
- ATENÇÃO: a rota setup.php de inicialização do Master não pode ser exposta publicamente antes de adicionar controle de acesso por rede/senha.
- Não é release de produção; exige revisão de segurança e testes funcionais antes da publicação.
