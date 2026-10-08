# EFFE Sync — Excluir sessão ao resolver

Esta versão deriva de `server-effe-sync-corrigido.js` e preserva o painel de edição existente.

## Antes de publicar
- Faça backup do PostgreSQL da Evolution e do banco `effe_sync`.
- Preserve o commit anterior para rollback.
- Execute primeiro em contato de teste; a exclusão de sessão é irreversível para aquele registro.
- No painel, desative a integração Rastreabem até terminar a configuração; lembre-se de que eventos pendentes podem permanecer na fila. Eventos acima de 120 segundos serão ignorados.

## 1. Criar acesso limitado no PostgreSQL da Evolution

Use pgAdmin conectado ao banco **da Evolution**, com seu usuário administrador, e rode (substitua a senha placeholder por senha longa):

```sql
CREATE ROLE effe_sync_evolution LOGIN PASSWORD 'SUBSTITUA_POR_SENHA_FORTE';
GRANT CONNECT ON DATABASE nome_real_do_banco_evolution TO effe_sync_evolution;
GRANT USAGE ON SCHEMA public TO effe_sync_evolution;
GRANT SELECT, DELETE ON TABLE public."IntegrationSession" TO effe_sync_evolution;
```

Se o usuário já existir, adapte usando `ALTER ROLE`; não cole senhas em conversas ou prints.
Não conceda CREATE, UPDATE, TRUNCATE nem acesso global ao banco da Evolution.

## 2. Identificar UUID interno da instância

Execute no banco Evolution:

```sql
SELECT "instanceId", "botId", type, count(*) AS total
FROM public."IntegrationSession"
WHERE type='typebot' AND "botId"='cmuwc9dk201xyp95aab9kd34d'
GROUP BY "instanceId", "botId", type;
```

Copie o `instanceId` completo correspondente à Rastreabem.
Se não houver sessão armazenada, obtenha o UUID com consulta read-only da tabela de instâncias da Evolution. Não adivinhe IDs.

## 3. Variáveis de ambiente no Coolify (aplicação EFFE Sync)

`EVOLUTION_DATABASE_URL=postgresql://effe_sync_evolution:<senha_url_encoded>@<host_postgres>:5432/<nome_banco_evolution>`

Use hostname da rede interna do Coolify, porta e database reais. Preserve `DATABASE_URL` apontando para `effe_sync`.
Se necessário, `EVOLUTION_DATABASE_SSL=true` apenas quando certificado TLS válido estiver configurado.

## 4. Implantação

Atualize os arquivos do repositório usando os arquivos deste pacote, sem apagar `.env` nem a base de dados; faça commit e deploy no Coolify.
No painel EFFE Sync -> Instâncias -> Rastreabem -> Editar:
- Informe o UUID interno Evolution;
- Escolha `Excluir sessão após Resolver`;
- Marque `Remover agente e time após Resolver`;
- Habilite a integração somente para o teste da Rastreabem.

## 5. Teste de ponta a ponta

1. Cliente entra no Typebot -> transferência Financeiro -> Raiane atende; a sessão deve ficar `paused`.
2. Cliente manda mensagem durante atendimento humano -> bot não responde.
3. Raiane clica Resolver -> o EFFE Sync confirma `resolved`, limpa atribuições, consulta a sessão exata e exclui **somente** a sessão pausada identificada por `id`, `botId`, `instanceId`, `remoteJid`, `type` e `status`.
4. Próximo 'Oi' -> Typebot deve voltar às boas-vindas e Chatwoot não deve herdar Raiane.
5. Verifique /events no painel: evento `completed` com razão `delete_session_*`.

## Limitações e proteções

- A operação não chama `/typebot/changeStatus` no modo delete_session.
- Rejeita sessão que não esteja `paused`, novo ciclo mais recente que o evento, evento com mais de 120 segundos, conversa reaberta ou IDs divergentes.
- A exclusão no banco foi demonstrada manualmente no seu ambiente, mas o fluxo automatizado requer validação real.
- Ainda há uma janela de corrida entre verificar `resolved` via HTTP e executar o DELETE. Para alta concorrência, o ideal é registrar explicitamente o ciclo de transferência e correlacioná-lo com o evento de resolução.
- O pool de conexão ao banco da Evolution é independente do banco `effe_sync`.
- Outros modos de operação de instâncias existentes são preservados.
