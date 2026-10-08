# EFFE Sync — atualização do painel e da limpeza de atribuição

## Instalação segura no Coolify

1. Faça um backup do banco `effe_sync` e mantenha uma cópia do commit atual do GitHub.
2. Substitua `server.js` no repositório por este arquivo e preserve os demais arquivos (`matching.js`, `Dockerfile`, `package.json`). Se o projeto já recebeu outras alterações de código além das discutidas, faça o merge das diferenças antes de substituir.
3. Confirme que as variáveis de Runtime incluem `CHATWOOT_URL` e `CHATWOOT_API_TOKEN` (token com permissão para ler conversas e editar atribuições), além das variáveis já utilizadas.
4. Faça commit, deploy no Coolify e confira `/health` e o login.
5. Em **Empresas**, edite nomes. Em **Instâncias → Editar**, altere empresa, rótulo, instância, conta, caixa de entrada, segredo do webhook (campo vazio preserva o atual), status de habilitação, ação Typebot e opção de limpar atribuição.
6. Ative **Remover agente e time após Resolver** somente para a Rastreabem em homologação; deixe desativado para os demais clientes.
7. Faça o teste de fluxo completo: cliente -> Typebot -> transferência -> atendente -> Resolver -> novo Oi; confira status no Chatwoot e na Evolution.

## Migração de banco

A aplicação executa automaticamente uma migração não destrutiva, criando as colunas abaixo se não existirem:

```sql
ALTER TABLE integrations ADD COLUMN IF NOT EXISTS clear_assignment_on_resolve BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE integrations ADD COLUMN IF NOT EXISTS bot_resolve_status TEXT NOT NULL DEFAULT 'opened';
```

Os registros de empresas, integrações, caminhos e segredos de webhooks não são recriados.

## Comportamento da limpeza

Ao receber `conversation_status_changed` com `resolved`, o worker identifica a instância e uma sessão `paused`, aplica o status configurado (`opened` por padrão) e, **somente para integrações com a opção habilitada**, consulta a conversa no Chatwoot. Se a conversa ainda estiver `resolved` e na inbox correta, remove agente e time por meio de duas chamadas à API de assignments. Não altera o status da conversa e não apaga histórico.

A limpeza é tentada após o comando de status Typebot. Se ocorrer erro, ele aparece na aba Eventos. É recomendado testar com uma única conversa. O Chatwoot customizado pode responder em formato diferente do Chatwoot padrão.

## Campos sensíveis e limites

- Credenciais globais, `DATABASE_URL`, `EVOLUTION_API_KEY`, `CHATWOOT_API_TOKEN`, `SESSION_SECRET`, `ADMIN_EMAIL` e `ADMIN_PASSWORD` **continuam no Coolify**, não no painel. Não é seguro exibi-las ou editá-las como dados comuns de integração.
- O painel não inclui gerenciamento de usuários ou permissões por empresa; permanece com um administrador global.
- Não há exclusão de empresas/instâncias no painel para evitar perda acidental de vínculos e histórico. O caminho do webhook permanece estável na edição.
- Uma réplica apenas. Migração e efeitos em conversas devem ser homologados antes do deploy em todas as empresas.
- `opened` reabre a sessão antiga; `closed` encerra a sessão. A escolha certa para recomeçar o bot depende de teste com sua Evolution.
- As respostas de sessão da Evolution podem conter chaves secretas: jamais publique JSON completo em chats ou logs.
