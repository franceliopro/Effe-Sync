# EFFE Sync — Correção de sessão `closed` após Resolver

Esta versão parte do pacote **Automações Multiempresa** existente e corrige o evento `skipped / no_unique_paused_session` quando a Evolution já alterou a sessão para `closed` antes do webhook `resolved`.

## Atualizar
1. Faça backup do banco Evolution e do `effe_sync` e registre o commit anterior.
2. Envie os arquivos do ZIP para o GitHub, mantendo a estrutura do repositório, inclusive o **novo** `session-policy.js` e `tests/session-policy.test.js`.
3. Faça commit e deploy no Coolify. Confirme que `EVOLUTION_DATABASE_URL` já existe e que o usuário possui SELECT na tabela `Instance`, SELECT e DELETE na `IntegrationSession`.
4. Na aba **Automações** da Rastreabem, selecione **Excluir sessão exata**. Não mantenha regras paralelas que fecham a mesma sessão.
5. Faça um teste completo com novo ciclo de atendimento: bot -> humano -> resolver -> novo Oi.
6. Em **Eventos**, resultado esperado: `completed`, motivo `session_deleted_from_closed` (ou `session_deleted_from_paused`).

## Proteções
- No modo exclusão, pesquisa diretamente no PostgreSQL da Evolution e não depende de `fetchSessions` retornar `paused`.
- Identifica automaticamente a instância pelo nome em `Instance`, mais `botId` e JID do webhook autenticado.
- Só remove um registro `paused` ou um `closed` cuja última alteração esteja dentro dos 120 segundos anteriores ao recebimento do evento `resolved`.
- Rejeita candidatos múltiplos, sessões mais novas, contatos sem identificador confiável e conversas que foram reabertas.
- Revalida a conversa no Chatwoot antes do DELETE e verifica a quantidade de linhas excluídas.

**Limitação importante:** o evento do Chatwoot não informa diretamente o ID da sessão do Typebot. A correlação é inferida de instância, bot, JID e tempo. Havendo ambiguidade, a regra falha fechada e não exclui. Para garantia completa contra eventos atrasados, registrar o ID da sessão no momento da transferência humana é uma evolução posterior necessária.

Os testes locais não provam o funcionamento em produção; só o teste real integra Chatwoot, Evolution e PostgreSQL.
