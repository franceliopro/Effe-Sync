import express from 'express';
import helmet from 'helmet';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { matchPausedSession, accountInbox, identifiers } from './matching.js';
import { chooseSessionForDeletion } from './session-policy.js';

const required=['DATABASE_URL','SESSION_SECRET','ADMIN_EMAIL','ADMIN_PASSWORD','EVOLUTION_URL','EVOLUTION_API_KEY','PUBLIC_URL'];
for(const k of required)if(!process.env[k])throw Error(`Missing ${k}`);
if(process.env.SESSION_SECRET.length<32)throw Error('SESSION_SECRET must be at least 32 characters');
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_SSL==='true'?{rejectUnauthorized:true}:false});
// Conexão independente e restrita ao banco da Evolution, ativada somente no modo delete_session.
const evolutionDb=process.env.EVOLUTION_DATABASE_URL ? new pg.Pool({connectionString:process.env.EVOLUTION_DATABASE_URL,ssl:process.env.EVOLUTION_DATABASE_SSL==='true'?{rejectUnauthorized:true}:false,max:3}) : null;
const app=express(); app.disable('x-powered-by'); app.set('trust proxy',1);app.use(helmet({contentSecurityPolicy:false,referrerPolicy:{policy:'strict-origin-when-cross-origin'}}));
app.use(express.urlencoded({extended:false,limit:'12kb'}));app.use(express.json({limit:'128kb',verify:(req,res,buf)=>{req.rawBody=Buffer.from(buf)}}));
const url=process.env.PUBLIC_URL.replace(/\/$/,'');
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const token=()=>crypto.randomBytes(24).toString('hex');
const sign=v=>crypto.createHmac('sha256',process.env.SESSION_SECRET).update(v).digest('hex');
const secure=process.env.NODE_ENV==='production'?'; Secure':'';
const cookie=(res,name,value,maxAge)=>res.setHeader('Set-Cookie',`${name}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}`);
function current(req){const raw=String(req.headers.cookie||'').split('; ').find(x=>x.startsWith('bc_session='))?.slice(11);if(!raw)return false;const [exp,sig]=raw.split('.');if(!/^\d+$/.test(exp)||Number(exp)<Date.now())return false;const h=sign(exp);return sig?.length===h.length&&crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(h));}
function admin(req,res,next){if(!current(req))return res.redirect('/login');next()}
function csrf(req,res,next){
  // CSRF defense without accepting Origin: null.
  const expected=new URL(process.env.PUBLIC_URL.trim()).origin;
  const raw=req.get('origin');
  if(!raw || raw==='null')return res.status(403).send('Origem não autorizada');
  try{if(new URL(raw).origin!==expected)return res.status(403).send('Origem não autorizada')}
  catch{return res.status(403).send('Origem inválida')}
  next();
}
async function getBranding(companyId){

if(!companyId) return {};

const r=await pool.query(`
SELECT *
FROM company_branding
WHERE company_id=$1
`,
[companyId]);

return r.rows[0]||{};

}
async function getCompanyBranding(companyId){

if(!companyId) return {};

const r = await pool.query(`
SELECT
 c.name AS company_name,
 b.logo_url,
 b.primary_color,
 b.secondary_color
FROM companies c
LEFT JOIN company_branding b
ON b.company_id=c.id
WHERE c.id=$1
`,
[companyId]);

return r.rows[0] || {};

}
function page(title,inner,brand={}){

const brandName=brand.company_name||'EFFE Sync';

const primary=brand.primary_color||'#215fca';

const secondary=brand.secondary_color||'#13233e';

const logo=brand.logo_url||'';

return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} • EFFE Sync</title>

<style>
body{
margin:0;
background:#f4f7fb;
color:#172033;
font:15px system-ui,sans-serif;
}

nav{
background:#101c35;
color:white;
padding:18px 24px;
}

nav a{
color:white;
margin-right:20px;
text-decoration:none;
}

.top-nav{
background:${secondary};
color:white;
padding:18px 28px;
display:flex;
align-items:center;
gap:30px;
}

.brand{
font-size:20px;
font-weight:800;
}

.brand span{
color:#4da3ff;
}

.menu-links{
display:flex;
gap:20px;
align-items:center;
}

.menu-links a{
color:white;
text-decoration:none;
font-size:15px;
}

.menu-toggle{
display:none;
margin-left:auto;
background:rgba(255,255,255,.08);
color:white;
font-size:24px;
width:42px;
height:42px;
border-radius:10px;
align-items:center;
justify-content:center;
}


@media(max-width:700px){

.top-nav{
position:relative;
}

.menu-toggle{
display:flex;
}


.menu-links{
display:none;
position:absolute;
top:65px;
left:0;
right:0;
background:#101c35;
padding:20px;
flex-direction:column;
align-items:flex-start;
z-index:10;
}


.menu-open .menu-links{
display:flex;
}

}

}

main{
max-width:1100px;
margin:30px auto;
padding:0 18px;
}

section{
background:white;
border:1px solid #dfe6ef;
border-radius:16px;
padding:28px;
margin:18px 0;
}

.card-grid{
display:grid;
grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
gap:20px;
margin:20px 0;
}

.card{
background:white;
border:1px solid #dfe6ef;
border-radius:16px;
padding:24px;
box-shadow:0 8px 25px rgba(15,30,60,.05);
}

.card h3{
margin:0;
font-size:15px;
color:#667085;
font-weight:600;
}

.card strong{
display:block;
font-size:42px;
margin-top:14px;
color:#101828;
}

.card small{
display:block;
margin-top:10px;
font-size:13px;
color:#667085;
}

h1{
font-size:28px;
}

button{
background:#2167e8;
color:white;
border:0;
padding:10px 18px;
border-radius:8px;
}

input,select{
width:100%;
max-width:480px;
padding:12px;
margin-top:6px;
margin-bottom:18px;
border-radius:10px;
border:1px solid #ccd5e1;
background:#fff;
}

label{
display:block;
font-weight:600;
margin-bottom:6px;
color:#24324a;
}

table{
width:100%;
border-collapse:collapse;
min-width:700px;
}

section{
overflow-x:auto;
}

td,th{
padding:12px;
border-bottom:1px solid #eee;
text-align:left;
}

@media(max-width:700px){

nav{
padding:16px;
}

nav a{
display:block;
margin:12px 0;
font-size:16px;
}

main{
padding:0 12px;
}

section{
padding:18px;
}

.card-grid{
grid-template-columns:1fr;
}

.card{
 padding:18px;
}

.card strong{
 font-size:28px;
}

section{
 margin-bottom:15px;
}

table{
font-size:14px;
}

}
</style>

</head>

<body>

<nav class="top-nav">

<div class="brand">

${logo ? `<img src="${esc(logo)}" style="height:28px;vertical-align:middle;border-radius:6px;margin-right:8px">` : '⚡'}

${esc(brandName)}

</div>

<button class="menu-toggle" onclick="document.body.classList.toggle('menu-open')">
☰
</button>

<div class="menu-links">

<a href="/">🏠 Painel</a>
<a href="/companies">🏢 Empresas</a>
<a href="/integrations">🔌 Instâncias</a>
<a href="/automations">🤖 Automações</a>
<a href="/events">📊 Eventos</a>
<a href="/logout">🚪 Sair</a>

</div>

</nav>

<main>
${inner}
</main>

</body>
</html>`;
}
const fail=(res,e)=>res.status(400).send(page('Erro',`<section><h2>Não foi possível concluir</h2><p>${esc(e.message||e)}</p><a href="/">Voltar</a></section>`));
async function init(){await pool.query(`CREATE TABLE IF NOT EXISTS companies(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL UNIQUE,created_at TIMESTAMPTZ DEFAULT now());CREATE TABLE IF NOT EXISTS integrations(id BIGSERIAL PRIMARY KEY,company_id BIGINT NOT NULL REFERENCES companies(id),label TEXT NOT NULL,instance TEXT NOT NULL,account_id INTEGER NOT NULL CHECK(account_id>0),inbox_id INTEGER NOT NULL CHECK(inbox_id>0),webhook_path TEXT NOT NULL UNIQUE,webhook_secret TEXT NOT NULL,enabled BOOLEAN NOT NULL DEFAULT true,created_at TIMESTAMPTZ DEFAULT now(),UNIQUE(account_id,inbox_id));CREATE TABLE IF NOT EXISTS events(id BIGSERIAL PRIMARY KEY,integration_id BIGINT NOT NULL REFERENCES integrations(id),delivery_key TEXT NOT NULL,conversation_id TEXT,status TEXT NOT NULL DEFAULT 'pending',reason TEXT,payload JSONB,remote_jid TEXT,attempts INT NOT NULL DEFAULT 0,created_at TIMESTAMPTZ DEFAULT now(),processed_at TIMESTAMPTZ,UNIQUE(integration_id,delivery_key));CREATE INDEX IF NOT EXISTS events_pending_idx ON events(status,created_at);ALTER TABLE integrations ADD COLUMN IF NOT EXISTS clear_assignment_on_resolve BOOLEAN NOT NULL DEFAULT false;ALTER TABLE integrations ADD COLUMN IF NOT EXISTS bot_resolve_status TEXT NOT NULL DEFAULT 'opened';ALTER TABLE integrations ADD COLUMN IF NOT EXISTS evolution_instance_id TEXT;CREATE TABLE IF NOT EXISTS automation_rules(id BIGSERIAL PRIMARY KEY,integration_id BIGINT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,event TEXT NOT NULL CHECK(event='conversation.resolved'),action TEXT NOT NULL CHECK(action IN ('chatwoot.clear_assignment','typebot.delete_session','typebot.open_session','typebot.close_session','audit.only')),enabled BOOLEAN NOT NULL DEFAULT true,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),UNIQUE(integration_id,event,action));CREATE TABLE IF NOT EXISTS company_branding(
id BIGSERIAL PRIMARY KEY,
company_id BIGINT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
logo_url TEXT,
primary_color TEXT DEFAULT '#215fca',
secondary_color TEXT DEFAULT '#13233e',
created_at TIMESTAMPTZ DEFAULT now(),
UNIQUE(company_id)
);`)}
app.get('/health',async(req,res)=>{try{await pool.query('SELECT 1');res.json({ok:true})}catch{res.status(503).json({ok:false})}});
let attempts=new Map();
app.get('/login',(req,res)=>res.send(page('Entrar','<section><h1>Acesso administrativo</h1><form method="POST" action="/login"><label>Email</label><input name="email" type="email" required><label>Senha</label><input name="password" type="password" required><button>Entrar</button></form></section>')));
const passwordHash=bcrypt.hashSync(process.env.ADMIN_PASSWORD,12);
app.post('/login',csrf,async(req,res)=>{const ip=req.ip||'unknown';let a=attempts.get(ip)||{n:0,until:0};if(a.until>Date.now())return res.status(429).send('Tente novamente mais tarde');const correctEmail=String(req.body.email||'').toLowerCase()===process.env.ADMIN_EMAIL.toLowerCase();const correctPass=await bcrypt.compare(String(req.body.password||''),passwordHash);if(!correctEmail||!correctPass){a.n++;if(a.n>=5){a.n=0;a.until=Date.now()+15*60*1000}attempts.set(ip,a);return res.status(401).send(page('Acesso negado','<section>Credenciais inválidas. <a href="/login">Tentar novamente</a></section>'))}attempts.delete(ip);const exp=String(Date.now()+8*3600*1000);cookie(res,'bc_session',`${exp}.${sign(exp)}`,28800);res.redirect('/')});
app.get('/logout',(req,res)=>{cookie(res,'bc_session','',0);res.redirect('/login')});
app.get('/',admin,async(req,res)=>{

const [
 companies,
 integrations,
 events,
 recent
]=await Promise.all([

pool.query(`
 SELECT count(*)::int n
 FROM companies
`),

pool.query(`
 SELECT count(*)::int n
 FROM integrations
 WHERE enabled=true
`),

pool.query(`
 SELECT 
 status,
 count(*)::int n
 FROM events
 GROUP BY status
`),

pool.query(`
 SELECT 
 e.status,
 e.reason,
 e.created_at,
 i.label
 FROM events e
 JOIN integrations i ON i.id=e.integration_id
 ORDER BY e.id DESC
 LIMIT 8
`)

]);


const stats={};

events.rows.forEach(x=>{
 stats[x.status]=x.n;
});


res.send(page('Dashboard',`

<section>

<h1>⚡ Painel EFFE Sync</h1>

<p class="muted">
Central inteligente de automações WhatsApp
</p>

</section>


<div class="card-grid">


<div class="card">
<h3>🏢 Empresas</h3>
<strong>${companies.rows[0].n}</strong>
<small>Clientes cadastrados</small>
</div>


<div class="card">
<h3>🔌 Instâncias ativas</h3>
<strong>${integrations.rows[0].n}</strong>
<small>Conexões operando</small>
</div>


<div class="card">
<h3>✅ Finalizados</h3>
<strong>${stats.completed||0}</strong>
<small>Fluxos concluídos</small>
</div>


<div class="card">
<h3>⚠️ Falhas</h3>
<strong>${stats.failed||0}</strong>
<small>Eventos que precisam atenção</small>
</div>


</div>



<section>

<h2>Últimos eventos</h2>

<table>

<tr>
<th>Status</th>
<th>Instância</th>
<th>Motivo</th>
<th>Data</th>
</tr>


${recent.rows.map(x=>`

<tr>

<td>
${
x.status==='completed'
?'🟢 Concluído'
:x.status==='failed'
?'🔴 Falhou'
:'🟡 Pendente'
}
</td>

<td>
${esc(x.label)}
</td>

<td>
${
x.reason?.includes('finish_command')
?'Fluxo Typebot finalizado automaticamente'
:esc(x.reason||'-')
}
</td>

<td>
${esc(x.created_at.toISOString())}
</td>

</tr>

`).join('')}


</table>

</section>


`));

});app.get('/companies',admin,async(req,res)=>{const r=await pool.query('SELECT * FROM companies ORDER BY id DESC');res.send(page('Empresas',`<h1>Empresas</h1><section><form method="POST"><label>Nome da empresa</label><input name="name" maxlength="120" required><button>Cadastrar empresa</button></form></section><section><table><tr><th>ID</th><th>Nome</th></tr>${r.rows.map(x=>`<tr><td>${x.id}</td><td>${esc(x.name)} <a href="/companies/${x.id}/edit">Editar</a>
<a href="/companies/${x.id}/branding">🎨 Identidade Visual</a></td></tr>`).join('')}</table></section>`))});
app.get('/companies/:id/edit',admin,async(req,res)=>{
 const r=await pool.query('SELECT id,name FROM companies WHERE id=$1',[req.params.id]);
 if(!r.rowCount)return res.status(404).send('Empresa não encontrada');
 const c=r.rows[0];const brand = await getCompanyBranding(req.params.id);
  res.send(page('Editar empresa',`<h1>Editar empresa</h1><section><form method="POST"><label>Nome</label><input name="name" required maxlength="120" value="${esc(c.name)}"><button>Salvar empresa</button></form></section>`,brand));
});
app.post('/companies/:id/edit',admin,csrf,async(req,res)=>{
 try{const name=String(req.body.name||'').trim();if(!name||name.length>120)throw Error('Nome inválido');const r=await pool.query('UPDATE companies SET name=$1 WHERE id=$2 RETURNING id',[name,req.params.id]);if(!r.rowCount)throw Error('Empresa não encontrada');res.redirect('/companies')}
 catch(e){fail(res,e)}
});

app.get('/companies/:id/branding',admin,async(req,res)=>{

const company=await pool.query(
'SELECT * FROM companies WHERE id=$1',
[req.params.id]
);

if(!company.rowCount)
 return res.status(404).send('Empresa não encontrada');


const brand=await pool.query(
'SELECT * FROM company_branding WHERE company_id=$1',
[req.params.id]
);


const b=brand.rows[0]||{};


res.send(page('Identidade Visual',`

<section>

<h1>🎨 Identidade Visual</h1>

<p class="muted">
Personalize a experiência desta empresa no EFFE Sync.
</p>


<form method="POST">


<label>
Logo URL
</label>

<input
name="logo_url"
value="${esc(b.logo_url||'')}"
placeholder="https://..."
>


<label>
Cor principal
</label>

<input
name="primary_color"
value="${esc(b.primary_color||'#2167e8')}"
>


<label>
Cor do menu
</label>

<input
name="secondary_color"
value="${esc(b.secondary_color||'#101c35')}"
>


<button>
Salvar identidade
</button>


</form>

</section>


`));

});
app.post('/companies/:id/branding',admin,csrf,async(req,res)=>{

await pool.query(`
INSERT INTO company_branding
(company_id,logo_url,primary_color,secondary_color)
VALUES($1,$2,$3,$4)

ON CONFLICT(company_id)
DO UPDATE SET
logo_url=$2,
primary_color=$3,
secondary_color=$4,
updated_at=now()
`,
[
req.params.id,
req.body.logo_url||null,
req.body.primary_color||'#2167e8',
req.body.secondary_color||'#101c35'
]);


res.redirect(`/companies/${req.params.id}/branding`);

});


app.post('/companies',admin,csrf,async(req,res)=>{try{if(!String(req.body.name||'').trim())throw Error('Nome obrigatório');await pool.query('INSERT INTO companies(name) VALUES($1)',[String(req.body.name).trim()]);res.redirect('/companies')}catch(e){fail(res,e)}});
app.get('/integrations',admin,async(req,res)=>{const [c,i]=await Promise.all([pool.query('SELECT * FROM companies ORDER BY name'),pool.query('SELECT i.*,c.name company FROM integrations i JOIN companies c ON c.id=i.company_id ORDER BY i.id DESC')]);res.send(page('Instâncias',`<h1>Instâncias e roteamento</h1><section><p class="warning">Cada par Conta + Caixa de entrada só pode pertencer a uma instância. Use o segredo de assinatura do webhook real do Chatwoot. Ele não será exibido novamente neste painel.</p><form method="POST"><label>Empresa</label><select name="company_id" required>${c.rows.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`)}</select><label>Nome interno</label><input name="label" required placeholder="Comercial - Empresa A"><label>Nome exato da instância Evolution</label><input name="instance" required><label>ID da conta no Chatwoot</label><input name="account_id" type="number" min="1" required><label>ID da caixa de entrada no Chatwoot</label><input name="inbox_id" type="number" min="1" required><label>Segredo da assinatura do webhook no Chatwoot</label><input name="webhook_secret" required minlength="8" placeholder="Copie o segredo real do webhook Chatwoot"><button>Adicionar instância</button></form></section><section><h2>Integrações</h2><table><tr><th>Empresa / Instância</th><th>Conta / Inbox</th><th>Webhook</th><th>Ação</th></tr>${i.rows.map(x=>`<tr><td>${esc(x.company)}<br><b>${esc(x.label)}</b><br><small>${esc(x.instance)}</small></td><td>${x.account_id} / ${x.inbox_id}</td><td><code>${esc(url+'/webhook/'+x.webhook_path)}</code><br><small>${x.enabled?'Ativa':'Desativada'}</small></td><td><a href="/integrations/${x.id}/edit">Editar</a>　<a href="/automations/${x.id}">Automações</a>　<form method="POST" action="/integrations/${x.id}/toggle" class="inline"><button>${x.enabled?'Desativar':'Ativar'}</button></form></td></tr>`).join('')}</table></section>`))});
app.post('/integrations',admin,csrf,async(req,res)=>{try{const b=req.body; if(!/^[\w.-]{1,120}$/.test(String(b.instance||'')))throw Error('Instância inválida');if(!Number.isSafeInteger(+b.account_id)||+b.account_id<1||!Number.isSafeInteger(+b.inbox_id)||+b.inbox_id<1)throw Error('Conta/inbox inválidas');if(String(b.webhook_secret||'').length<8)throw Error('Segredo inválido');const client=await pool.connect();try{await client.query('BEGIN');const inserted=await client.query('INSERT INTO integrations(company_id,label,instance,account_id,inbox_id,webhook_path,webhook_secret,bot_resolve_status,clear_assignment_on_resolve) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true) RETURNING id',[b.company_id,String(b.label).slice(0,120),b.instance,b.account_id,b.inbox_id,token(),b.webhook_secret,'delete_session']);for(const action of ['chatwoot.clear_assignment','typebot.delete_session'])await client.query('INSERT INTO automation_rules(integration_id,event,action) VALUES($1,$2,$3)',[inserted.rows[0].id,'conversation.resolved',action]);await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}res.redirect('/integrations')}catch(e){fail(res,e)}});
app.get('/integrations/:id/edit',admin,async(req,res)=>{
 const [r,c]=await Promise.all([
  pool.query('SELECT * FROM integrations WHERE id=$1',[req.params.id]),
  pool.query('SELECT id,name FROM companies ORDER BY name')
 ]);
 if(!r.rowCount)return res.status(404).send('Integração não encontrada');
 const i=r.rows[0];
 res.send(page('Editar integração',`<h1>Editar instância #${i.id}</h1><section>
 <p class="warning">O segredo atual não será exibido. Deixe o campo vazio para preservá-lo. O endereço do webhook não muda ao editar.</p>
 <form method="POST">
 <label>Empresa</label><select name="company_id">${c.rows.map(x=>`<option value="${x.id}" ${x.id===i.company_id?'selected':''}>${esc(x.name)}</option>`).join('')}</select>
 <label>Nome interno</label><input name="label" maxlength="120" required value="${esc(i.label)}">
 <label>Instância Evolution</label><input name="instance" required value="${esc(i.instance)}">
 <label>ID da conta Chatwoot</label><input name="account_id" type="number" min="1" required value="${i.account_id}">
 <label>ID da inbox Chatwoot</label><input name="inbox_id" type="number" min="1" required value="${i.inbox_id}">
  <p class="warning">O identificador interno da Evolution será detectado automaticamente pelo nome exato da instância no momento do encerramento. Não é necessário preencher UUID.</p>
 <label>Novo segredo webhook (opcional)</label><input type="password" name="webhook_secret" autocomplete="new-password" placeholder="Vazio = manter atual">
 <label>Ao resolver, ação na sessão Typebot</label><select name="bot_resolve_status">
 <option value="opened" ${i.bot_resolve_status==='opened'?'selected':''}>opened — retomar sessão</option>
 <option value="closed" ${i.bot_resolve_status==='closed'?'selected':''}>closed — encerrar sessão</option>
  <option value="manual" ${i.bot_resolve_status==='manual'?'selected':''}>manual — não modificar sessão Typebot</option>
  <option value="delete_session" ${i.bot_resolve_status==='delete_session'?'selected':''}>Excluir sessão após Resolver (nova execução no próximo Oi)</option></select>
 <label><input type="checkbox" name="clear_assignment_on_resolve" value="1" style="width:auto" ${i.clear_assignment_on_resolve?'checked':''}> Remover agente e time após Resolver</label>
 <label><input type="checkbox" name="enabled" value="1" style="width:auto" ${i.enabled?'checked':''}> Integração ativa</label>
 <p>Webhook atual: <code>${esc(url+'/webhook/'+i.webhook_path)}</code></p>
 <button>Salvar alterações</button></form></section>`));
});
app.post('/integrations/:id/edit',admin,csrf,async(req,res)=>{
 try{
  const b=req.body;
  const instance=String(b.instance||'');const label=String(b.label||'').trim();
  const companyId=Number(b.company_id),accountId=Number(b.account_id),inboxId=Number(b.inbox_id);
  if(!/^[\w.-]{1,120}$/.test(instance)||!label||label.length>120)throw Error('Nome ou instância inválida');
  if(![companyId,accountId,inboxId].every(v=>Number.isSafeInteger(v)&&v>0))throw Error('IDs inválidos');
  const secret=String(b.webhook_secret||'');if(secret&&secret.length<8)throw Error('Novo segredo muito curto');
  if(!['opened','closed','manual','delete_session'].includes(b.bot_resolve_status))throw Error('Ação Typebot inválida');
  const r=await pool.query(`UPDATE integrations SET company_id=$1,label=$2,instance=$3,account_id=$4,inbox_id=$5,
    webhook_secret=COALESCE(NULLIF($6,''),webhook_secret),enabled=$7,clear_assignment_on_resolve=$8,
    bot_resolve_status=$9 WHERE id=$10 RETURNING id`,[
    companyId,label,instance,accountId,inboxId,secret,b.enabled==='1',b.clear_assignment_on_resolve==='1',b.bot_resolve_status,req.params.id
  ]);
  if(!r.rowCount)throw Error('Integração não encontrada');
  // A tela de edição continua funcional; sincroniza políticas explícitas existentes.
  const existing=await pool.query('SELECT 1 FROM automation_rules WHERE integration_id=$1 LIMIT 1',[req.params.id]);
  if(existing.rowCount){
   const client=await pool.connect();try{await client.query('BEGIN');await client.query('DELETE FROM automation_rules WHERE integration_id=$1',[req.params.id]);
    const actions=[...(b.clear_assignment_on_resolve==='1'?['chatwoot.clear_assignment']:[]),...({'delete_session':'typebot.delete_session','opened':'typebot.open_session','closed':'typebot.close_session'}[b.bot_resolve_status]?[{'delete_session':'typebot.delete_session','opened':'typebot.open_session','closed':'typebot.close_session'}[b.bot_resolve_status]]:['audit.only'])];
    for(const a of actions)await client.query('INSERT INTO automation_rules(integration_id,event,action) VALUES($1,$2,$3)',[req.params.id,'conversation.resolved',a]);await client.query('COMMIT');
   }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
  }
  res.redirect('/integrations');
 }catch(e){fail(res,e)}
});
app.post('/integrations/:id/toggle',admin,csrf,async(req,res)=>{await pool.query('UPDATE integrations SET enabled=NOT enabled WHERE id=$1',[req.params.id]);res.redirect('/integrations')});
// Catálogo conservador: ações destrutivas só no evento de resolução confirmado.
const RULE_CATALOG=[
 ['chatwoot.clear_assignment','Remover agente e time (primeira ação)'],
 ['typebot.delete_session','Excluir sessão exata Typebot (padrão)'],
 ['typebot.open_session','Retomar sessão Typebot (legado)'],
 ['typebot.close_session','Fechar sessão Typebot (legado)'],
 ['audit.only','Registrar evento sem modificar atendimento']
];
app.get('/automations',admin,async(req,res)=>{
 const r=await pool.query('SELECT i.id,i.label,i.instance,c.name AS company FROM integrations i JOIN companies c ON c.id=i.company_id ORDER BY c.name,i.label');
 res.send(page('Automações',`<h1>Automações por instância</h1><section><p>Fluxo padrão: Chatwoot resolvido → remover atribuições → excluir somente a sessão pausada correspondente. Não há exclusão no handoff humano.</p><table><tr><th>Empresa / Instância</th><th>Configurar</th></tr>${r.rows.map(x=>`<tr><td>${esc(x.company)} / ${esc(x.label)}<br><small>${esc(x.instance)}</small></td><td><a href="/automations/${x.id}">Gerenciar ações</a></td></tr>`).join('')}</table></section>`))
});
app.get('/automations/:id',admin,async(req,res)=>{
 const [r,rules]=await Promise.all([pool.query('SELECT i.*,c.name AS company FROM integrations i JOIN companies c ON c.id=i.company_id WHERE i.id=$1',[req.params.id]),pool.query('SELECT action FROM automation_rules WHERE integration_id=$1 AND event=$2 AND enabled=true',[req.params.id,'conversation.resolved'])]);
 if(!r.rowCount)return res.status(404).send('Integração não encontrada');
 const i=r.rows[0], configured=rules.rows.length>0;
 const actions=new Set(rules.rows.map(x=>x.action));
 const legacyStatus={'delete_session':'typebot.delete_session','opened':'typebot.open_session','closed':'typebot.close_session'}[i.bot_resolve_status]||'audit.only';
 const selected=configured?[...actions]:[...(i.clear_assignment_on_resolve?['chatwoot.clear_assignment']:[]),legacyStatus];
 res.send(page('Regras de automação',`<h1>Automações — ${esc(i.company)} / ${esc(i.label)}</h1><section><p class="warning">Regras deste atendimento aplicam-se apenas a <b>conversation.resolved</b>. Uma única ação de sessão Typebot é permitida. Alterações passam a valer para novos eventos; não reprocessam eventos finalizados.</p><form method="POST"><label>Gatilho</label><input value="Chatwoot: conversa resolvida (conversation.resolved)" disabled><label><input type="checkbox" style="width:auto" name="clear" value="1" ${selected.includes('chatwoot.clear_assignment')?'checked':''}> Remover agente e time após Resolver</label><label>Ação na sessão Typebot</label><select name="typebot_action"><option value="typebot.delete_session" ${selected.includes('typebot.delete_session')?'selected':''}>Excluir sessão exata (padrão)</option><option value="audit.only" ${selected.includes('audit.only')?'selected':''}>Nenhuma alteração — apenas registrar</option><option value="typebot.open_session" ${selected.includes('typebot.open_session')?'selected':''}>Retomar sessão (legado)</option><option value="typebot.close_session" ${selected.includes('typebot.close_session')?'selected':''}>Fechar sessão (legado)</option></select><button>Salvar automação</button></form></section><section><h2>Proteções</h2><p>Ao excluir, confirma-se a conversa resolvida, o bot, a instância detectada por nome, o WhatsApp e o ID específico da sessão pausada. Se qualquer comparação falhar, nenhuma sessão será excluída.</p><p><a href="/events">Ver histórico de eventos</a></p></section>`));
});
app.post('/automations/:id',admin,csrf,async(req,res)=>{
 try{
  const integration=await pool.query('SELECT id FROM integrations WHERE id=$1',[req.params.id]);if(!integration.rowCount)return res.status(404).send('Integração não encontrada');
  const action=String(req.body.typebot_action||'');
  if(!['typebot.delete_session','typebot.open_session','typebot.close_session','audit.only'].includes(action))throw Error('Ação não permitida');
  const clear=req.body.clear==='1';
  const client=await pool.connect();
  try{
   await client.query('BEGIN');
   await client.query('DELETE FROM automation_rules WHERE integration_id=$1 AND event=$2',[req.params.id,'conversation.resolved']);
   const actions=[...(clear?['chatwoot.clear_assignment']:[]),action];
   for(const a of actions)await client.query('INSERT INTO automation_rules(integration_id,event,action) VALUES($1,$2,$3)',[req.params.id,'conversation.resolved',a]);
   const legacy={'typebot.delete_session':'delete_session','typebot.open_session':'opened','typebot.close_session':'closed','audit.only':'manual'}[action];
   await client.query('UPDATE integrations SET bot_resolve_status=$2,clear_assignment_on_resolve=$3 WHERE id=$1',[req.params.id,legacy,clear]);
   await client.query('COMMIT');
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
  res.redirect('/automations/'+req.params.id);
 }catch(e){fail(res,e)}
});
app.get('/events',admin,async(req,res)=>{const r=await pool.query('SELECT e.*,i.label,c.name company FROM events e JOIN integrations i ON i.id=e.integration_id JOIN companies c ON c.id=i.company_id ORDER BY e.id DESC LIMIT 150');res.send(page('Eventos',`<h1>Últimos eventos</h1><section><table><tr><th>Data</th><th>Empresa / Instância</th><th>Conversa</th><th>Status</th><th>Motivo / JID</th></tr>${r.rows.map(x=>`<tr><td>${esc(x.created_at.toISOString())}</td><td>${esc(x.company)} / ${esc(x.label)}</td><td>${esc(x.conversation_id)}</td><td>${
x.status==='completed'
?'🟢 Concluído'
:x.status==='failed'
?'🔴 Falhou'
:'🟡 Pendente'
}</td><td>${
x.reason?.includes('finish_command')
?'Fluxo Typebot finalizado automaticamente'
:esc(x.reason||'-')
}<br><small>${esc(x.remote_jid)}</small></td></tr>`).join('')}</table></section>`))});
function validSignature(req,secret){const timestamp=req.get('x-chatwoot-timestamp')||'';const signature=req.get('x-chatwoot-signature')||'';if(!/^\d+$/.test(timestamp)||Math.abs(Date.now()/1000-Number(timestamp))>300)return false;if(!/^sha256=[a-f\d]{64}$/i.test(signature))return false;const expected='sha256='+crypto.createHmac('sha256',secret).update(Buffer.concat([Buffer.from(timestamp+'.'),req.rawBody||Buffer.alloc(0)])).digest('hex');return crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(signature));}
// Webhook interno do EFFE Sync para comandos do Typebot
app.post('/webhook/effe/:path', async(req,res)=>{
 try{
  const r=await pool.query(
   'SELECT * FROM integrations WHERE webhook_path=$1 AND enabled=true',
   [req.params.path]
  );

  const i=r.rows[0];

  if(!i)
    return res.status(404).json({error:'integration not found'});

  const payload=req.body||{};

  if(payload.command!=='EFFE_FINISH')
    return res.json({ignored:true});

  await pool.query(`
    INSERT INTO events(
      integration_id,
      delivery_key,
      conversation_id,
      status,
      payload
    )
    VALUES($1,$2,$3,$4,$5)
  `,
  [
    i.id,
    crypto.randomUUID(),
    String(payload.conversation_id||'0'),
    'pending',
    JSON.stringify(payload)
  ]);

  res.json({accepted:true});

 }catch(e){
  console.error('EFFE_FINISH webhook:',e.message);
  res.status(500).json({error:'internal error'});
 }
});
app.post('/webhook/:path',async(req,res)=>{const r=await pool.query('SELECT * FROM integrations WHERE webhook_path=$1 AND enabled=true',[req.params.path]);const i=r.rows[0];if(!i)return res.status(404).json({error:'not found'});if(!validSignature(req,i.webhook_secret))return res.status(401).json({error:'invalid signature'});const p=req.body||{};if(p.event!=='conversation_status_changed'||p.status!=='resolved')return res.json({ignored:true});const {account,inbox}=accountInbox(p);if(account!==i.account_id||inbox!==i.inbox_id)return res.json({ignored:true,reason:'different inbox'});const conversationId=String(p.id??p.conversation?.id??'');if(!/^\d+$/.test(conversationId))return res.status(422).json({error:'missing conversation id'});const delivery=req.get('x-chatwoot-delivery');const key=delivery&&delivery.length<=150?delivery:crypto.createHash('sha256').update(req.rawBody).digest('hex');await pool.query('INSERT INTO events(integration_id,delivery_key,conversation_id,status,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',[i.id,key,conversationId,'pending',JSON.stringify(p)]);res.status(202).json({accepted:true})});
async function evolution(path,options={}){const ctrl=new AbortController();const t=setTimeout(()=>ctrl.abort(),12000);try{const u=process.env.EVOLUTION_URL.replace(/\/$/,'')+path;const response=await fetch(u,{...options,signal:ctrl.signal,headers:{apikey:process.env.EVOLUTION_API_KEY,...options.headers}});const txt=await response.text();if(!response.ok)throw Error(`Evolution HTTP ${response.status}: ${txt.slice(0,160)}`);if(!txt.trim())return {};try{return JSON.parse(txt)}catch{throw Error('Evolution returned non-JSON response')}}finally{clearTimeout(t)}}
async function chatwoot(path,options={}){
 if(!process.env.CHATWOOT_URL||!process.env.CHATWOOT_API_TOKEN)throw Error('CHATWOOT_URL e CHATWOOT_API_TOKEN são necessários para limpeza de atribuição');
 const ctrl=new AbortController();const t=setTimeout(()=>ctrl.abort(),12000);
 try{
  const response=await fetch(process.env.CHATWOOT_URL.replace(/\/$/,'')+path,{
   ...options,signal:ctrl.signal,headers:{api_access_token:process.env.CHATWOOT_API_TOKEN,...options.headers}
  });
  const txt=await response.text();
  if(!response.ok)throw Error(`Chatwoot HTTP ${response.status}: ${txt.slice(0,180)}`);
  return txt?JSON.parse(txt):{};
 }finally{clearTimeout(t)}
}
async function getResolvedConversation(event){
  const path=`/api/v1/accounts/${Number(event.account_id)}/conversations/${String(event.conversation_id)}`;
  const data=await chatwoot(path);const conv=data.payload||data;
  if(String(conv.status)!=='resolved')return null;
  if(Number(conv.inbox_id??conv.inbox?.id)!==Number(event.inbox_id))throw Error('Inbox não confere');
  return conv;
}
async function clearResolvedAssignment(event){
 // Keep the same conversation and its history. Never change the status.
 const account=Number(event.account_id),inbox=Number(event.inbox_id);
 const convId=String(event.conversation_id);
 if(!/^\d+$/.test(convId))throw Error('ID de conversa inválido');
 const path=`/api/v1/accounts/${account}/conversations/${convId}`;
 const conv=await getResolvedConversation(event);
 if(!conv)throw Error('Conversa não está resolvida');
 const assignPath=path+'/assignments';
 // Chatwoot legacy API: separate requests; sending both can ignore team_id.
 await chatwoot(assignPath,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({assignee_id:null})});
 await chatwoot(assignPath,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({team_id:null})});
 const after=await chatwoot(path);
 const checked=after.payload||after;
 if(checked.assignee_id!=null || checked.meta?.assignee?.id!=null || checked.team_id!=null || checked.meta?.team?.id!=null){
  throw Error('Não foi possível confirmar remoção de agente e time');
 }
}
// Resolve o nome público da instância por correspondência exata no cadastro da Evolution.
// Se o nome for ausente ou ambíguo, interrompe a operação sem excluir registros.
async function resolveInstanceUuid(client, instanceName){
 if(!/^[\w.-]{1,120}$/.test(instanceName||''))throw Error('Nome da instância inválido');
 const found=await client.query('SELECT id FROM public."Instance" WHERE name=$1 LIMIT 2',[instanceName]);
 if(found.rowCount!==1 || !found.rows[0].id)throw Error('Instância Evolution ausente ou ambígua: '+instanceName);
 return String(found.rows[0].id);
}
// Exclui somente o registro exato, do bot, instância e contato do evento.
// Não usa DELETE por telefone isolado. Um evento antigo jamais deve atingir sessão nova.
// Exclusão direta para comando interno EFFE_FINISH.
// O Typebot confirmou o encerramento do fluxo.
// Não usa regras de conversa resolvida nem janela de segurança.
async function deleteFinishSession(event, botId){

 if(!evolutionDb)
   throw Error('Configure EVOLUTION_DATABASE_URL no Coolify');

 const remoteJid = event.payload?.remoteJid;

 if(!remoteJid)
   throw Error('EFFE_FINISH sem remoteJid');

 const client = await evolutionDb.connect();

 try{

  await client.query('BEGIN');

  const instanceUuid = await resolveInstanceUuid(client,event.instance);

  const deleted = await client.query(`
    DELETE FROM public."IntegrationSession"
    WHERE "botId"=$1
      AND "instanceId"=$2
      AND "remoteJid"=$3
      AND type='typebot'
    RETURNING id,status,"remoteJid"
  `,
  [
    botId,
    instanceUuid,
    remoteJid
  ]);

  await client.query('COMMIT');

  if(deleted.rowCount!==1){
    return {
      deleted:false,
      reason:'nenhuma_sessao_encontrada_para_finish'
    };
  }

  return {
    deleted:true,
    remoteJid:deleted.rows[0].remoteJid,
    previousStatus:deleted.rows[0].status
  };


 }catch(e){

  await client.query('ROLLBACK');
  throw e;

 }finally{

  client.release();

 }

}


// Exclusão segura para eventos Chatwoot resolvidos.
async function deleteExactSession(event, botId){
 if(!evolutionDb)throw Error('Configure EVOLUTION_DATABASE_URL no Coolify');
 const {jids,phones}=identifiers(event.payload);
 const remoteJids=[...new Set([...jids,...[...phones].map(x=>x+'@s.whatsapp.net')])];
 if(!remoteJids.length)throw Error('Contato sem JID/telefone confiável no webhook');
 const client=await evolutionDb.connect();
 try{
  await client.query('BEGIN');
  const instanceUuid=await resolveInstanceUuid(client,event.instance);
  // Trava apenas sessões exatas do bot, da instância e do contato envolvidos.
  const rows=await client.query(`SELECT id,"remoteJid",status,"createdAt","updatedAt"
    FROM public."IntegrationSession"
    WHERE "botId"=$1 AND "instanceId"=$2 AND "remoteJid"=ANY($3::varchar[])
      AND type='typebot' AND status IN ('paused','closed','opened')
    FOR UPDATE`,[botId,instanceUuid,remoteJids]);
  const choice=chooseSessionForDeletion(rows.rows, new Date(event.created_at));
  if(!choice.session){await client.query('ROLLBACK');return {deleted:false,reason:choice.reason};}
  // Revalidar a conversa antes de qualquer DELETE.
  if(!await getResolvedConversation(event)){
   await client.query('ROLLBACK');return {deleted:false,reason:'conversa_reaberta_antes_da_exclusao'};
  }
  const target=choice.session;
  const deleted=await client.query(`DELETE FROM public."IntegrationSession"
    WHERE id=$1 AND "botId"=$2 AND "instanceId"=$3 AND "remoteJid"=$4
      AND type='typebot' AND status=$5 RETURNING id`,
   [target.id,botId,instanceUuid,target.remoteJid,target.status]);
  if(deleted.rowCount!==1)throw Error('Exclusão não confirmada');
  await client.query('COMMIT');
  return {deleted:true,remoteJid:target.remoteJid,previousStatus:target.status};
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
// State machine conservadora: nunca reiniciar uma sessão humana por evento antigo.
const EVENT_MAX_AGE_MS=120000;
let working=false;
async function work(){
 if(working)return;working=true;
 try{
  const rows=await pool.query(`SELECT e.id,e.integration_id,e.payload,e.conversation_id,e.created_at,e.attempts,
    i.instance,i.account_id,i.inbox_id,i.bot_resolve_status,i.clear_assignment_on_resolve
    FROM events e JOIN integrations i ON i.id=e.integration_id
    WHERE e.status='pending' AND i.enabled=true ORDER BY e.id LIMIT 10`);
  for(const event of rows.rows){
    // Comando interno Typebot - não passa pelo Chatwoot
if(event.payload?.command === 'EFFE_FINISH'){

  const config = await evolution(`/typebot/find/${encodeURIComponent(event.instance)}`);
  const bots = Array.isArray(config) ? config : [config];

  const enabled = bots.filter(x => x?.enabled && typeof x.id === 'string');

  if(enabled.length !== 1){
    throw Error('É necessário exatamente um Typebot ativo por instância');
  }

  const deletion = await deleteFinishSession(event, enabled[0].id);

  await pool.query(`
 UPDATE events
 SET status=$1,
     reason=$2,
     remote_jid=$3,
     processed_at=now()
 WHERE id=$4
`,
[
 deletion.deleted ? 'completed' : 'skipped',
 deletion.deleted
   ? 'session_deleted_from_finish_command'
   : deletion.reason,
 deletion.remoteJid || null,
 event.id
]);

  continue;
}
   const locked=await pool.query("UPDATE events SET status='processing',attempts=attempts+1 WHERE id=$1 AND status='pending' RETURNING id,attempts",[event.id]);
   if(!locked.rowCount)continue;
   // Política por instância: regras explícitas prevalecem sobre campos legados.
   const configured=await pool.query('SELECT action,enabled FROM automation_rules WHERE integration_id=$1 AND event=$2',[event.integration_id,'conversation.resolved']);
   if(configured.rowCount){
    const actions=new Set(configured.rows.filter(x=>x.enabled).map(x=>x.action));
    event.clear_assignment_on_resolve=actions.has('chatwoot.clear_assignment');
    const typebot=Array.from(actions).filter(x=>x.startsWith('typebot.'));
    if(typebot.length>1){
     await pool.query('UPDATE events SET status=$2,reason=$3,processed_at=now() WHERE id=$1',[event.id,'failed','Regras Typebot conflitantes']);
     continue;
    }
    event.bot_resolve_status=typebot.length?{'typebot.delete_session':'delete_session','typebot.open_session':'opened','typebot.close_session':'closed'}[typebot[0]]:'manual';
   }
   let result='failed',reason='',remoteJid=null;
   // Nunca fazer retry após uma mutação remota de sessão; evita fechar a sessão seguinte.
   let sessionChangeAttempted=false;
   try{
     // Comando interno do Typebot: EFFE_FINISH
// Não consulta Chatwoot. Usa o mesmo motor seguro de exclusão.
if(event.payload?.command==='EFFE_FINISH'){

 const config=await evolution(`/typebot/find/${encodeURIComponent(event.instance)}`);
 const bots=Array.isArray(config)?config:[config];

 const enabled=bots.filter(x=>x?.enabled&&typeof x.id==='string');

 if(enabled.length!==1)
   throw Error('É necessário exatamente um Typebot ativo por instância');

 sessionChangeAttempted=true;

 const deletion=await deleteExactSession(event,enabled[0].id);

 if(deletion.deleted){
   remoteJid=deletion.remoteJid;
   result='completed';
   reason='session_deleted_from_finish_command';
 }else{
   result='skipped';
   reason=deletion.reason;
 }

 continue;
}
    const eventTime=new Date(event.created_at).getTime();
    if(!Number.isFinite(eventTime)||Date.now()-eventTime>EVENT_MAX_AGE_MS){
     result='skipped';reason='evento_antigo_mais_de_120s';
    }else{
     const conv=await getResolvedConversation(event);
     if(!conv){result='skipped';reason='conversa_nao_esta_resolvida';}
     else{
      // Limpar agente/time PRIMEIRO. Se falhar, manter o Typebot pausado.
      // Nunca é permitido que erro de limpeza volte a executar changeStatus.
      if(event.clear_assignment_on_resolve){
       await clearResolvedAssignment(event);
      }
      if(event.bot_resolve_status==='manual'){
       result='completed';reason='somente_limpeza_sem_alterar_typebot';
      }else{
       const instance=encodeURIComponent(event.instance);
       const config=await evolution(`/typebot/find/${instance}`);
       const bots=Array.isArray(config)?config:[config];
       const enabled=bots.filter(x=>x?.enabled&&typeof x.id==='string');
       if(enabled.length!==1)throw Error('É necessário exatamente um Typebot ativo por instância');
       // O modo exclusão consulta o banco diretamente: a Evolution pode já ter
       // mudado paused -> closed antes da chegada do webhook resolved.
       if(event.bot_resolve_status==='delete_session'){
        sessionChangeAttempted=true; // nenhuma repetição automática de DELETE após tentativa
        const deletion=await deleteExactSession(event,enabled[0].id);
        if(deletion.deleted){remoteJid=deletion.remoteJid;result='completed';reason=`session_deleted_from_${deletion.previousStatus}`;}
        else{result='skipped';reason=deletion.reason;}
       }else{
       const raw=await evolution(`/typebot/fetchSessions/${encodeURIComponent(enabled[0].id)}/${instance}`);
       const matched=matchPausedSession(event.payload,raw);
       reason=matched.reason;
       if(!matched.remoteJid){result='skipped';}
       else{
        remoteJid=matched.remoteJid;
        // Sessão iniciada depois do evento resolved é um novo ciclo; nunca modificar.
        const sessions=[];
        const seen=new Set();
        const walk=(obj,depth=0)=>{
         if(!obj||typeof obj!=='object'||depth>9||seen.has(obj))return;
         seen.add(obj);
         if(Array.isArray(obj)){obj.forEach(x=>walk(x,depth+1));return;}
         if(obj.remoteJid===remoteJid&&obj.status==='paused')sessions.push(obj);
         Object.values(obj).forEach(x=>{if(x&&typeof x==='object')walk(x,depth+1)});
        };walk(raw);
        if(sessions.length!==1){result='skipped';reason='sessao_nao_unica';}
        else if(!sessions[0].createdAt||!Number.isFinite(new Date(sessions[0].createdAt).getTime())){
         result='skipped';reason='sessao_sem_data_validavel';
        }else if(new Date(sessions[0].createdAt).getTime()>eventTime){
         result='skipped';reason='sessao_mais_nova_que_evento';
        }else{
         // Checar novamente o status da conversa imediatamente antes da mudança.
         const stillResolved=await getResolvedConversation(event);
         if(!stillResolved){result='skipped';reason='conversa_reaberta_antes_do_changeStatus';}
         else{
          sessionChangeAttempted=true;
          await evolution(`/typebot/changeStatus/${instance}`,{
           method:'POST',headers:{'Content-Type':'application/json'},
           body:JSON.stringify({remoteJid,status:event.bot_resolve_status})
          });
          result='completed';reason=`${event.bot_resolve_status}_${matched.reason}`;
         }
        }
       }
       }
      }
     }
    }
    }catch(e){
    reason=String(e.message).slice(0,300);
    // Se a requisição changeStatus pode ter chegado ao servidor, não repetir.
    if(!sessionChangeAttempted&&locked.rows[0].attempts<3&&Date.now()-new Date(event.created_at).getTime()<EVENT_MAX_AGE_MS)result='retry';
    else result='failed';
   }
   await pool.query('UPDATE events SET status=$2,reason=$3,remote_jid=$4,processed_at=now() WHERE id=$1',[
    event.id,result==='retry'?'pending':result,reason,remoteJid
   ]);
  }
 }catch(e){console.error('Worker:',e.message)}finally{working=false}
}

await init();setInterval(work,4000).unref();app.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('EFFE Sync listening'));
