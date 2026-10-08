// Não excluir sessão nova, ambígua, sem timestamps ou anterior ao ciclo atual.
export function chooseSessionForDeletion(rows, eventTime) {
 const t=new Date(eventTime).getTime();
 if(!Number.isFinite(t))return {reason:'evento_sem_data_valida'};
 const sessions=rows.map(s=>({...s,createdMs:new Date(s.createdAt).getTime(),updatedMs:new Date(s.updatedAt).getTime()}));
 if(sessions.some(s=>!s.id||!Number.isFinite(s.createdMs)||!Number.isFinite(s.updatedMs)))return {reason:'sessao_sem_data_valida'};
 // Inclui tolerância pequena para relógios dessíncronos; nunca tocar sessão nova.
 if(sessions.some(s=>s.createdMs>t+2000))return {reason:'sessao_posterior_ao_evento'};
 const eligible=sessions.filter(s=>s.createdMs<=t+2000 && (
    s.status==='paused' || (s.status==='closed' && s.updatedMs>=t-120000 && s.updatedMs<=t+2000)
  ));
 if(eligible.length!==1)return {reason:eligible.length?'sessoes_elegiveis_ambiguas':'no_unique_paused_or_recent_closed_session'};
 const target=eligible[0];
 // Qualquer outro registro mais novo do mesmo contato/bot impede remover ciclo antigo.
 if(sessions.some(s=>s.id!==target.id && s.createdMs>=target.createdMs))return {reason:'outra_sessao_mais_recente_ou_ambigua'};
 return {session:target};
}
