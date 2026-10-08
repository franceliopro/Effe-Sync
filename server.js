import express from 'express';
import helmet from 'helmet';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { matchPausedSession, accountInbox } from './matching.js'; 

const required=['DATABASE_URL','SESSION_SECRET','ADMIN_EMAIL','ADMIN_PASSWORD','EVOLUTION_URL','EVOLUTION_API_KEY','PUBLIC_URL'];
for(const k of required)if(!process.env[k])throw Error(`Missing ${k}`);
if(process.env.SESSION_SECRET.length<32)throw Error('SESSION_SECRET must be at least 32 characters');
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_SSL==='true'?{rejectUnauthorized:true}:false});

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  }
}));

app.use(express.urlencoded({extended:false,limit:'12kb'}));app.use(express.json({limit:'128kb',verify:(req,res,buf)=>{req.rawBody=Buffer.from(buf)}}));
const url=process.env.PUBLIC_URL.replace(/\/$/,'');
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const token=()=>crypto.randomBytes(24).toString('hex');
const sign=v=>crypto.createHmac('sha256',process.env.SESSION_SECRET).update(v).digest('hex');
const secure=process.env.NODE_ENV==='production'?'; Secure':'';
const cookie=(res,name,value,maxAge)=>res.setHeader('Set-Cookie',`${name}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}`);
function current(req){const raw=String(req.headers.cookie||'').split('; ').find(x=>x.startsWith('bc_session='))?.slice(11);if(!raw)return false;const [exp,sig]=raw.split('.');if(!/^\d+$/.test(exp)||Number(exp)<Date.now())return false;const h=sign(exp);return sig?.length===h.length&&crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(h));}
function admin(req,res,next){if(!current(req))return res.redirect('/login');next()}


function csrf(req, res, next) {
  const origin = req.get('origin');
  const expected = new URL(process.env.PUBLIC_URL.trim()).origin;

  let received = null;

  try {
    if (origin) {
      received = new URL(origin).origin;
    }
  } catch {
    console.error('[EFFE SYNC] Origin inválida', {
      origin,
      expected
    });

    return res.status(403).send('Origem inválida');
  }

  console.log('[EFFE SYNC] Verificação de origem:', {
    received,
    expected,
    fetchSite: req.get('sec-fetch-site')
  });

  if (!received || received !== expected) {
    console.error('[EFFE SYNC] Origem bloqueada');

    return res.status(403).send(
      'Origem não autorizada'
    );
  }

  next();
}


function page(title,inner){return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} • Bot Control</title><style>body{margin:0;background:#f5f7fb;color:#1a2739;font:15px system-ui,sans-serif}main{max-width:1080px;margin:30px auto;padding:0 18px}nav{background:#13233e;color:white;padding:18px 24px}nav a{color:white;margin-right:22px}a{color:#245ec0}h1{font-size:28px}section{background:white;border:1px solid #dae2ec;border-radius:12px;padding:20px;margin:18px 0;overflow:auto}input,select{width:100%;max-width:480px;padding:10px;margin:6px 0 16px;box-sizing:border-box;border:1px solid #cbd5e1;border-radius:7px}label{display:block;font-weight:600}button{border:0;background:#215fca;color:white;padding:11px 18px;border-radius:8px;cursor:pointer}table{border-collapse:collapse;width:100%}td,th{text-align:left;border-bottom:1px solid #e6ebf0;padding:12px}small,.muted{color:#5f6f83}code{word-break:break-all}pre{white-space:pre-wrap}form.inline{display:inline}form.inline button{background:#9f3c3c} .pill{background:#e1f5e6;color:#15703d;padding:4px 9px;border-radius:12px} .warning{background:#fff4d8;padding:12px;border-radius:8px}</style></head><body><nav><strong>Bot Control Multiempresa</strong>　 <a href="/">Painel</a><a href="/companies">Empresas</a><a href="/integrations">Instâncias</a><a href="/events">Eventos</a><a href="/logout">Sair</a></nav><main>${inner}</main></body></html>`}
const fail=(res,e)=>res.status(400).send(page('Erro',`<section><h2>Não foi possível concluir</h2><p>${esc(e.message||e)}</p><a href="/">Voltar</a></section>`));
async function init(){await pool.query(`CREATE TABLE IF NOT EXISTS companies(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL UNIQUE,created_at TIMESTAMPTZ DEFAULT now());CREATE TABLE IF NOT EXISTS integrations(id BIGSERIAL PRIMARY KEY,company_id BIGINT NOT NULL REFERENCES companies(id),label TEXT NOT NULL,instance TEXT NOT NULL,account_id INTEGER NOT NULL CHECK(account_id>0),inbox_id INTEGER NOT NULL CHECK(inbox_id>0),webhook_path TEXT NOT NULL UNIQUE,webhook_secret TEXT NOT NULL,enabled BOOLEAN NOT NULL DEFAULT true,created_at TIMESTAMPTZ DEFAULT now(),UNIQUE(account_id,inbox_id));CREATE TABLE IF NOT EXISTS events(id BIGSERIAL PRIMARY KEY,integration_id BIGINT NOT NULL REFERENCES integrations(id),delivery_key TEXT NOT NULL,conversation_id TEXT,status TEXT NOT NULL DEFAULT 'pending',reason TEXT,payload JSONB,remote_jid TEXT,attempts INT NOT NULL DEFAULT 0,created_at TIMESTAMPTZ DEFAULT now(),processed_at TIMESTAMPTZ,UNIQUE(integration_id,delivery_key));CREATE INDEX IF NOT EXISTS events_pending_idx ON events(status,created_at);`)}
app.get('/health',async(req,res)=>{try{await pool.query('SELECT 1');res.json({ok:true})}catch{res.status(503).json({ok:false})}});
let attempts=new Map();
app.get('/login',(req,res)=>res.send(page('Entrar','<section><h1>Acesso administrativo</h1><form method="POST" action="/login"><label>Email</label><input name="email" type="email" required><label>Senha</label><input name="password" type="password" required><button>Entrar</button></form></section>')));
const passwordHash=bcrypt.hashSync(process.env.ADMIN_PASSWORD,12);
app.post('/login',csrf,async(req,res)=>{const ip=req.ip||'unknown';let a=attempts.get(ip)||{n:0,until:0};if(a.until>Date.now())return res.status(429).send('Tente novamente mais tarde');const correctEmail=String(req.body.email||'').toLowerCase()===process.env.ADMIN_EMAIL.toLowerCase();const correctPass=await bcrypt.compare(String(req.body.password||''),passwordHash);if(!correctEmail||!correctPass){a.n++;if(a.n>=5){a.n=0;a.until=Date.now()+15*60*1000}attempts.set(ip,a);return res.status(401).send(page('Acesso negado','<section>Credenciais inválidas. <a href="/login">Tentar novamente</a></section>'))}attempts.delete(ip);const exp=String(Date.now()+8*3600*1000);cookie(res,'bc_session',`${exp}.${sign(exp)}`,28800);res.redirect('/')});
app.get('/logout',(req,res)=>{cookie(res,'bc_session','',0);res.redirect('/login')});
app.get('/',admin,async(req,res)=>{const [c,i,e]=await Promise.all([pool.query('SELECT count(*)::int AS n FROM companies'),pool.query('SELECT count(*)::int AS n FROM integrations WHERE enabled'),pool.query("SELECT status,count(*)::int n FROM events GROUP BY status")]);res.send(page('Painel',`<h1>Visão geral</h1><section><h2>${c.rows[0].n} empresas • ${i.rows[0].n} instâncias ativas</h2>${e.rows.map(x=>`<p>${esc(x.status)}: <b>${x.n}</b></p>`).join('')||'<p>Nenhum evento ainda.</p>'}</section><section><h2>Próximos passos</h2><p>1. Cadastre empresa. 2. Cadastre instância vinculada a conta e inbox Chatwoot. 3. Configure o webhook gerado no Chatwoot. 4. Resolva uma conversa e confira o histórico.</p></section>`))});
app.get('/companies',admin,async(req,res)=>{const r=await pool.query('SELECT * FROM companies ORDER BY id DESC');res.send(page('Empresas',`<h1>Empresas</h1><section><form method="POST"><label>Nome da empresa</label><input name="name" maxlength="120" required><button>Cadastrar empresa</button></form></section><section><table><tr><th>ID</th><th>Nome</th></tr>${r.rows.map(x=>`<tr><td>${x.id}</td><td>${esc(x.name)}</td></tr>`).join('')}</table></section>`))});
app.post('/companies',admin,csrf,async(req,res)=>{try{if(!String(req.body.name||'').trim())throw Error('Nome obrigatório');await pool.query('INSERT INTO companies(name) VALUES($1)',[String(req.body.name).trim()]);res.redirect('/companies')}catch(e){fail(res,e)}});
app.get('/integrations',admin,async(req,res)=>{const [c,i]=await Promise.all([pool.query('SELECT * FROM companies ORDER BY name'),pool.query('SELECT i.*,c.name company FROM integrations i JOIN companies c ON c.id=i.company_id ORDER BY i.id DESC')]);res.send(page('Instâncias',`<h1>Instâncias e roteamento</h1><section><p class="warning">Cada par Conta + Caixa de entrada só pode pertencer a uma instância. Use o segredo de assinatura do webhook real do Chatwoot. Ele não será exibido novamente neste painel.</p><form method="POST"><label>Empresa</label><select name="company_id" required>${c.rows.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`)}</select><label>Nome interno</label><input name="label" required placeholder="Comercial - Empresa A"><label>Nome exato da instância Evolution</label><input name="instance" required><label>ID da conta no Chatwoot</label><input name="account_id" type="number" min="1" required><label>ID da caixa de entrada no Chatwoot</label><input name="inbox_id" type="number" min="1" required><label>Segredo da assinatura do webhook no Chatwoot</label><input name="webhook_secret" required minlength="8" placeholder="Copie o segredo real do webhook Chatwoot"><button>Adicionar instância</button></form></section><section><h2>Integrações</h2><table><tr><th>Empresa / Instância</th><th>Conta / Inbox</th><th>Webhook</th><th>Ação</th></tr>${i.rows.map(x=>`<tr><td>${esc(x.company)}<br><b>${esc(x.label)}</b><br><small>${esc(x.instance)}</small></td><td>${x.account_id} / ${x.inbox_id}</td><td><code>${esc(url+'/webhook/'+x.webhook_path)}</code><br><small>${x.enabled?'Ativa':'Desativada'}</small></td><td><form method="POST" action="/integrations/${x.id}/toggle" class="inline"><button>${x.enabled?'Desativar':'Ativar'}</button></form></td></tr>`).join('')}</table></section>`))});
app.post('/integrations',admin,csrf,async(req,res)=>{try{const b=req.body; if(!/^[\w.-]{1,120}$/.test(String(b.instance||'')))throw Error('Instância inválida');if(!Number.isSafeInteger(+b.account_id)||+b.account_id<1||!Number.isSafeInteger(+b.inbox_id)||+b.inbox_id<1)throw Error('Conta/inbox inválidas');if(String(b.webhook_secret||'').length<8)throw Error('Segredo inválido');await pool.query('INSERT INTO integrations(company_id,label,instance,account_id,inbox_id,webhook_path,webhook_secret) VALUES ($1,$2,$3,$4,$5,$6,$7)',[b.company_id,String(b.label).slice(0,120),b.instance,b.account_id,b.inbox_id,token(),b.webhook_secret]);res.redirect('/integrations')}catch(e){fail(res,e)}});
app.post('/integrations/:id/toggle',admin,csrf,async(req,res)=>{await pool.query('UPDATE integrations SET enabled=NOT enabled WHERE id=$1',[req.params.id]);res.redirect('/integrations')});
app.get('/events',admin,async(req,res)=>{const r=await pool.query('SELECT e.*,i.label,c.name company FROM events e JOIN integrations i ON i.id=e.integration_id JOIN companies c ON c.id=i.company_id ORDER BY e.id DESC LIMIT 150');res.send(page('Eventos',`<h1>Últimos eventos</h1><section><table><tr><th>Data</th><th>Empresa / Instância</th><th>Conversa</th><th>Status</th><th>Motivo / JID</th></tr>${r.rows.map(x=>`<tr><td>${esc(x.created_at.toISOString())}</td><td>${esc(x.company)} / ${esc(x.label)}</td><td>${esc(x.conversation_id)}</td><td>${esc(x.status)}</td><td>${esc(x.reason)}<br><small>${esc(x.remote_jid)}</small></td></tr>`).join('')}</table></section>`))});
function validSignature(req,secret){const timestamp=req.get('x-chatwoot-timestamp')||'';const signature=req.get('x-chatwoot-signature')||'';if(!/^\d+$/.test(timestamp)||Math.abs(Date.now()/1000-Number(timestamp))>300)return false;if(!/^sha256=[a-f\d]{64}$/i.test(signature))return false;const expected='sha256='+crypto.createHmac('sha256',secret).update(Buffer.concat([Buffer.from(timestamp+'.'),req.rawBody||Buffer.alloc(0)])).digest('hex');return crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(signature));}
app.post('/webhook/:path',async(req,res)=>{const r=await pool.query('SELECT * FROM integrations WHERE webhook_path=$1 AND enabled=true',[req.params.path]);const i=r.rows[0];if(!i)return res.status(404).json({error:'not found'});if(!validSignature(req,i.webhook_secret))return res.status(401).json({error:'invalid signature'});const p=req.body||{};if(p.event!=='conversation_status_changed'||p.status!=='resolved')return res.json({ignored:true});const {account,inbox}=accountInbox(p);if(account!==i.account_id||inbox!==i.inbox_id)return res.json({ignored:true,reason:'different inbox'});const conversationId=String(p.id??p.conversation?.id??'');if(!/^\d+$/.test(conversationId))return res.status(422).json({error:'missing conversation id'});const delivery=req.get('x-chatwoot-delivery');const key=delivery&&delivery.length<=150?delivery:crypto.createHash('sha256').update(req.rawBody).digest('hex');await pool.query('INSERT INTO events(integration_id,delivery_key,conversation_id,status,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',[i.id,key,conversationId,'pending',JSON.stringify(p)]);res.status(202).json({accepted:true})});
async function evolution(path,options={}){const ctrl=new AbortController();const t=setTimeout(()=>ctrl.abort(),12000);try{const u=process.env.EVOLUTION_URL.replace(/\/$/,'')+path;const response=await fetch(u,{...options,signal:ctrl.signal,headers:{apikey:process.env.EVOLUTION_API_KEY,...options.headers}});const txt=await response.text();if(!response.ok)throw Error(`Evolution HTTP ${response.status}: ${txt.slice(0,160)}`);if(!txt.trim())return {};try{return JSON.parse(txt)}catch{throw Error('Evolution returned non-JSON response')}}finally{clearTimeout(t)}}
let working=false;

async function work() {
  if (working) return;
  working = true;

  try {
    const rows = await pool.query(`
      SELECT e.id, e.payload, i.instance
      FROM events e
      JOIN integrations i
        ON i.id = e.integration_id
      WHERE e.status = 'pending'
        AND i.enabled = true
      ORDER BY e.id
      LIMIT 10
    `);

    for (const event of rows.rows) {
      const locked = await pool.query(`
        UPDATE events
        SET status = 'processing',
            attempts = attempts + 1
        WHERE id = $1 AND status = 'pending'
        RETURNING id, attempts
      `, [event.id]);

      if (!locked.rowCount) continue;

      let status = 'failed';
      let reason = '';
      let remoteJid = null;

      try {
        const instance = encodeURIComponent(event.instance);

        // Descobre o Typebot desta instância
        const config = await evolution(
          `/typebot/find/${instance}`
        );

        const bots = Array.isArray(config) ? config : [config];
        const enabledBots = bots.filter(
          bot => bot?.enabled && typeof bot.id === 'string'
        );

        if (enabledBots.length !== 1) {
          throw new Error(
            `Expected one enabled Typebot, found ${enabledBots.length}`
          );
        }

        const typebotId = encodeURIComponent(enabledBots[0].id);

        // Busca as sessões do Typebot correto
        const sessions = await evolution(
          `/typebot/fetchSessions/${typebotId}/${instance}`
        );

        // Identifica somente a sessão do contato correto
        const matched = matchPausedSession(
          event.payload,
          sessions
        );

        reason = matched.reason;

        if (matched.remoteJid) {
          remoteJid = matched.remoteJid;

          // Solicita o encerramento da sessão pausada
          await evolution(
            `/typebot/changeStatus/${instance}`,
            {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                remoteJid,
                status: 'opened'
              })
            }
          );

          status = 'completed';
          reason = 'closed_' + matched.reason;
        } else {
          status = 'skipped';
        }
      } catch (e) {
        reason = String(e.message).slice(0, 300);

        if (locked.rows[0].attempts < 3) {
          status = 'retry';
        }
      }

      await pool.query(`
        UPDATE events
        SET status = $2,
            reason = $3,
            remote_jid = $4,
            processed_at = now()
        WHERE id = $1
      `, [
        event.id,
        status === 'retry' ? 'pending' : status,
        reason,
        remoteJid
      ]);
    }
  } catch (e) {
    console.error('Worker:', e.message);
  } finally {
    working = false;
  }
}
await init();setInterval(work,4000).unref();app.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('Bot Control listening'));
