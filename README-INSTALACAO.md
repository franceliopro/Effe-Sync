# EFFE Sync — Automações multiempresa (primeira etapa)

## Implementado
- Nova aba **Automações** e ações configuráveis por instância, para o gatilho `conversation.resolved`.
- Ação padrão para NOVAS integrações: `chatwoot.clear_assignment` + `typebot.delete_session`.
- Contas existentes não sofrem migração silenciosa: acesse **Automações → Gerenciar ações → Salvar automação** em cada uma após validação.
- Suporte a exceções por instância: nenhuma alteração, retomar ou fechar (legado, não recomendado para a Rastreabem).
- UUID identificado automaticamente no banco da Evolution; exclusão apenas por ID exato, bot, instância e número.
- Histórico em **Eventos** e validações já presentes no serviço.

## Limites
- Ainda não implementa outros gatilhos (`message.created`, `conversation.assigned`), envios de mensagens programadas, editor arbitrário de workflows ou integrações Evolution distintas por empresa. As integrações atualmente compartilham `EVOLUTION_URL`, `EVOLUTION_API_KEY` e `CHATWOOT_URL` do Coolify.
- Configuração de múltiplas Evolution URLs/segredos e execução de novas ações exigirão autenticação de credenciais por integração, validação de destinos e tarefas assíncronas.
- O fluxo automático ainda precisa ser validado com Chatwoot/Evolution em execução; testes locais cobrem apenas a biblioteca de matching.

## Preparar e publicar
1. Faça backup dos databases `effe_sync` e Evolution, preserve o commit anterior.
2. Mantenha `DATABASE_URL` e `EVOLUTION_DATABASE_URL` apontando aos databases já existentes.
3. O usuário do banco Evolution precisa `SELECT` em `public."Instance"` e `SELECT,DELETE` em `public."IntegrationSession"`.
4. Atualize arquivos no GitHub, faça commit e Deploy no Coolify; não sobrescreva variáveis secretas.
5. Abra **Automações**, selecione Rastreabem e marque **Remover agente e time** com **Excluir sessão exata**. Salve. Não habilite em massa antes da homologação.
6. Teste uma conversa sem atendimento ativo, handoff humano, pausa, Resolver, exclusão e boas-vindas na próxima mensagem. Verifique `completed` com motivo `delete_session_*`.

## Segurança
Webhooks continuam verificados por assinatura, painel exige login e origem, exclusão verifica ciclo e sessão específica. Regra por evento não executa código arbitrário nem SQL editável. A tabela `automation_rules` é criada automaticamente no `init()`; não exige database novo.
