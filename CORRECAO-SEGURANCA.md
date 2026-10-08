# EFFE Sync — correção conservadora de transferência e retorno

## Alterações
- Confirma conversa resolvida e inbox antes de processar.
- Limpa agente/time antes de alterar status de sessão Typebot.
- Descarta webhook de resolução antigo (>120 segundos desde registro no banco).
- Não altera sessão cuja `createdAt` seja posterior ao evento; requer data válida.
- Não repete a chamada `changeStatus` quando ela pode ter sido enviada.
- Permite `manual` para não mudar a sessão pela integração.

## Implantação segura
1. Faça backup do banco e preserve o commit anterior.
2. Mantenha a integração Rastreabem desativada e os atendimentos de teste finalizados.
3. Substitua `server.js` e mantenha `matching.js` e demais arquivos do repositório.
4. Faça o deploy no Coolify.
5. Antes de habilitar a Rastreabem, escolha ação `manual` e `Remover agente e time após Resolver` ATIVADO. Assim o EFFE Sync não pode encerrar sessões Typebot nesta fase.
6. Habilite apenas Rastreabem em ambiente controlado e teste: transferência, conversa humana, resolução, novo Oi.
7. Em `manual`, a sessão permanece `paused` após Resolver; o retorno automático ao bot ainda não estará pronto. É um modo seguro para isolar a limpeza de atribuição.
8. Não habilite `opened` nem `closed` até validar o ciclo completo de reinicialização, e não processe eventos antigos intencionalmente.

## Atenção
- Esta versão NÃO implementa a supressão de mensagens na Evolution independentemente do status Typebot.
- Não é uma prova de funcionamento com o Chatwoot/Evolution da produção; os testes existentes cobrem somente matching.
- Requer variáveis CHATWOOT_URL e CHATWOOT_API_TOKEN para limpeza.
- Eventual `processing` deixado por crash requer revisão humana; nenhum retry automático foi adicionado.
