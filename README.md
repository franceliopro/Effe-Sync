# Bot Control Multiempresa — MVP para Coolify

Painel e serviço para fechar sessões Typebot (`paused` → `closed`) ao receber `conversation_status_changed` / `resolved` de múltiplas contas/caixas do Chatwoot em uma mesma instalação da Evolution API.

## Instalação

1. Envie esta pasta para um repositório Git privado.
2. No Coolify, crie **New Resource → Docker Compose** usando o repositório e `docker-compose.yml`. Se usar interface com cola de YAML, cole o conteúdo do Compose e defina as variáveis no Coolify.
3. Copie `.env.example` para as variáveis do Coolify, preenchendo senhas fortes e URLs. `SESSION_SECRET` precisa de pelo menos 32 caracteres aleatórios. Use domínio HTTPS no proxy do Coolify apontando para a porta 3000 da aplicação. A porta 3000 fica exposta somente à rede Docker (`expose`), e o acesso público deve ser feito pelo proxy HTTPS do Coolify.
4. Inicie e verifique `https://seu-dominio/health` → `{"ok":true}`.
5. Entre em `https://seu-dominio/login` usando `ADMIN_EMAIL` e `ADMIN_PASSWORD`.
6. Cadastre uma empresa, depois cada instância informando nome exato na Evolution, account ID e inbox ID.
7. Em cada **conta Chatwoot**, configure um webhook em Configurações → Integrações → Webhooks, habilitando `conversation_status_changed`. Registre o segredo real daquele webhook no cadastro de cada instância dessa conta (se várias instâncias receberem a mesma assinatura, reutilize o mesmo segredo em cada registro). Copie uma das URLs geradas para cada conta; para várias caixas da mesma conta, uma URL por caixa funciona, mas é mais eficiente cadastrar apenas o webhook da primeira caixa, pois o evento de conta inclui `inbox.id` e este MVP aceita eventos somente se houver um registro para o caminho utilizado. **Portanto, para múltiplas caixas de uma mesma conta, cadastre um webhook por instância/caixa** e use as URLs individuais. Eventos enviados para outras caixas são ignorados.
8. Resolva uma conversa de teste e veja o registro em Eventos. Teste uma mensagem nova e confirme se o Typebot reinicia. `closed` não garante sozinho recomeço em toda configuração.

### Importante

- `EVOLUTION_URL` deve ser a URL alcançável pelo container (pode ser URL HTTPS do próprio Coolify).
- `EVOLUTION_API_KEY` é a chave global com acesso às instâncias cadastradas.
- O sistema faz correspondência **exata** de JID ou telefone para sessão `@s.whatsapp.net`; nunca inventa um mapeamento de `@lid`. Se o Chatwoot não fornecer um JID exato para `@lid`, o evento ficará como `skipped` e exigirá uma estratégia de mapeamento adicional.
- Compatibilidade com formatos retornados por `fetchSessions` na Evolution 2.3.7 precisa ser validada em instância real.
- O painel fornece um único login administrativo. Não há RBAC nem autosserviço de clientes nesta versão.
- Eventos e segredos estão armazenados no PostgreSQL. Proteja backups, credenciais, o domínio HTTPS e os acessos de administração.
- Rode apenas **uma réplica** do serviço (worker embutido). Para alta disponibilidade e paralelismo, separe a fila em um worker com controle transacional.
- Esta versão é MVP para homologação. Teste e revise segurança, retenção de dados, observabilidade e backups antes de produção ampla.

## Fluxo interno

Webhook autenticado por HMAC-SHA256 + timestamp → valida conta/inbox → grava evento idempotente no PostgreSQL → worker consulta `/typebot/fetchSessions/{instance}` → associa **uma única sessão pausada** → POST `/typebot/changeStatus/{instance}` com `{remoteJid,status:"closed"}` → exibe resultado.

## Testes locais

```sh
npm install
npm test
npm run check
```

## Variáveis

Ver `.env.example`. Não faça commit de `.env` com senhas reais.
