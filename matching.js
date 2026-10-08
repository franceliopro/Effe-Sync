export const digits = v => String(v||'').replace(/\D/g,'');
export const jid = v => typeof v === 'string' && /^(\d{6,20})@(s\.whatsapp\.net|lid)$/.test(v) ? v : null;
export function collectSessions(data){
 const out=[]; const seen=new Set();
 function walk(o,depth=0){if(depth>9||!o||typeof o!=='object'||seen.has(o))return;seen.add(o);
  if(Array.isArray(o)){for(const x of o)walk(x,depth+1);return;}
  if(typeof o.remoteJid==='string'&&typeof o.status==='string')out.push({remoteJid:o.remoteJid,status:o.status});
  for(const [k,v] of Object.entries(o)){if(k!=='prefilledVariables'&&typeof v==='object')walk(v,depth+1)}
 } walk(data);return out;
}
export function identifiers(payload){
 const values=[
 payload?.remoteJid,
 payload?.jid,
 payload?.phone,
 payload?.meta?.sender?.identifier,
 payload?.meta?.sender?.phone_number,
 payload?.meta?.sender?.additional_attributes?.remoteJid,
 payload?.meta?.sender?.custom_attributes?.remoteJid,
 payload?.sender?.identifier,
 payload?.sender?.phone_number,
 payload?.sender?.additional_attributes?.remoteJid,
 payload?.sender?.custom_attributes?.remoteJid,
 payload?.contact?.phone_number,
 payload?.contact?.identifier,
 payload?.conversation?.meta?.sender?.phone_number,
 payload?.conversation?.meta?.sender?.identifier,
 payload?.additional_attributes?.remoteJid,
 payload?.custom_attributes?.remoteJid,
 payload?.meta?.sender?.additional_attributes?.wa_id
];
 const jids=new Set(values.map(jid).filter(Boolean));
 const phones=new Set(values.filter(x=>typeof x==='string' && !jid(x)).map(digits).filter(x=>x.length>=10&&x.length<=15));
 return {jids,phones};
}
export function matchPausedSession(payload,rawSessions){
 const {jids,phones}=identifiers(payload);
 const paused=collectSessions(rawSessions).filter(x=>x.status==='paused'&&jid(x.remoteJid));
 const direct=[...new Set(paused.filter(x=>jids.has(x.remoteJid)).map(x=>x.remoteJid))];
 if(direct.length===1)return {remoteJid:direct[0],reason:'exact'};
 if(direct.length>1)return {reason:'ambiguous_exact'};
 // Never guess or transform @lid IDs to telephone numbers.
 const matching=[...new Set(paused.filter(x=>x.remoteJid.endsWith('@s.whatsapp.net') && phones.has(x.remoteJid.split('@')[0])).map(x=>x.remoteJid))];
 if(matching.length===1)return {remoteJid:matching[0],reason:'phone'};
 return {reason:matching.length?'ambiguous_phone':'no_unique_paused_session'};
}
export function accountInbox(payload){
 const account=Number(payload?.account?.id ?? payload?.account_id ?? payload?.conversation?.account_id);
 const inbox=Number(payload?.inbox?.id ?? payload?.inbox_id ?? payload?.conversation?.inbox_id);
 return {account,inbox};
}
