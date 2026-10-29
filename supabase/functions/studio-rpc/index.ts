import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const db = createClient(SUPABASE_URL, SERVICE_ROLE, { auth: { persistSession: false } });
const VERSION = "v1.8.1";
const SESSION_HOURS = 6;

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
};

function ok(value: unknown) {
  return new Response(JSON.stringify({ ok: true, value }), { status: 200, headers: cors });
}
function fail(message: string, status = 400) {
  return new Response(JSON.stringify({ ok: false, error: message }), { status, headers: cors });
}
function normalize(v: unknown) { return String(v ?? "").trim().toLowerCase(); }
async function sha256(text: string) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}
function publicUser(u: any) {
  const admin = String(u?.perfil || "").toUpperCase() === "ADMIN";
  return {
    id: u.id, nome: u.nome, identificador: u.identificador, perfil: u.perfil,
    ativo: !!u.ativo, ultimo_login: u.ultimo_login || "",
    primeiro_acesso_pendente: !!u.primeiro_acesso_pendente,
    codigo_temporario_ate: u.codigo_ativacao_expira_em || "",
    visualizar_atendimentos_dias: admin ? 99999 : Number(u.visualizar_atendimentos_dias ?? 5),
    editar_atendimentos_dias: admin ? 99999 : Number(u.editar_atendimentos_dias ?? 1),
    cancelar_atendimentos_dias: admin ? 99999 : Number(u.cancelar_atendimentos_dias ?? 1),
  };
}

function activationCodeV181(){
  const a=new Uint32Array(1);
  crypto.getRandomValues(a);
  return String(100000+(a[0]%900000));
}
async function activationHashV181(userId:any,code:any){
  return await sha256("studio-activation|"+String(userId||"")+"|"+String(code||"").trim());
}
async function generateTemporaryAccessV181(admin:any,userId:any){
  const id=String(userId||"");
  const {data:user,error}=await db.from("usuarios").select("*").eq("id",id).maybeSingle();
  if(error||!user)throw new Error("Usuário não encontrado.");
  if(!user.ativo)throw new Error("Reative o usuário antes de gerar um acesso temporário.");
  if(String(user.id)===String(admin.id))throw new Error("Para o seu próprio usuário, utilize a alteração de PIN. Outro administrador pode gerar um acesso temporário para você.");
  const code=activationCodeV181();
  const now=new Date();
  const expires=new Date(now.getTime()+30*60_000).toISOString();
  const patch={
    primeiro_acesso_pendente:true,
    codigo_ativacao_hash:await activationHashV181(user.id,code),
    codigo_ativacao_expira_em:expires,
    codigo_ativacao_criado_em:now.toISOString(),
    codigo_ativacao_criado_por:String(admin.id||""),
    codigo_ativacao_usado_em:null,
    ativacao_tentativas:0,
    ativacao_bloqueado_ate:null,
    atualizado_em:now.toISOString()
  };
  const {error:ue}=await db.from("usuarios").update(patch).eq("id",user.id);
  if(ue)throw new Error(ue.message);
  await db.from("migration_sessions").delete().eq("usuario_id",user.id);
  await auditV181(admin,"GERAR_ACESSO_TEMPORARIO","USUARIO",user.id,{usuario:user.identificador,expira_em:expires});
  return {ok:true,user_id:user.id,user_name:user.nome,identificador:user.identificador,code,expires_at:expires};
}
async function activateMigratedUserV181(payload:any){
  payload=payload||{};
  const ident=normalize(payload.identificador);
  const code=String(payload.codigo||payload.code||"").trim();
  const next=validatePinV181(payload.novo_pin||payload.new_pin||"");
  const confirm=String(payload.confirmar_pin||payload.confirm_pin||"").trim();
  if(!ident||!code)throw new Error("Informe usuário e código temporário.");
  if(next!==confirm)throw new Error("A confirmação do novo PIN não confere.");
  const {data:user,error}=await db.from("usuarios").select("*").eq("identificador",ident).eq("ativo",true).maybeSingle();
  if(error||!user)throw new Error("Usuário ou código temporário inválido.");
  if(!user.primeiro_acesso_pendente)throw new Error("Este usuário já possui acesso ativo ao novo sistema.");
  const now=new Date();
  if(user.ativacao_bloqueado_ate&&new Date(user.ativacao_bloqueado_ate).getTime()>now.getTime())
    throw new Error("Muitas tentativas inválidas. Solicite um novo código temporário ao administrador.");
  if(!user.codigo_ativacao_hash||!user.codigo_ativacao_expira_em||new Date(user.codigo_ativacao_expira_em).getTime()<now.getTime())
    throw new Error("Código temporário expirado ou ainda não gerado. Solicite um novo código ao administrador.");
  const expected=await activationHashV181(user.id,code);
  if(expected!==String(user.codigo_ativacao_hash||"")){
    const attempts=Number(user.ativacao_tentativas||0)+1;
    const locked=attempts>=5?new Date(now.getTime()+15*60_000).toISOString():null;
    await db.from("usuarios").update({ativacao_tentativas:attempts,ativacao_bloqueado_ate:locked,atualizado_em:now.toISOString()}).eq("id",user.id);
    throw new Error(attempts>=5?"Muitas tentativas inválidas. Solicite um novo código temporário ao administrador.":"Usuário ou código temporário inválido.");
  }
  const pinHash=await sha256("studio-essence|"+next);
  const patch={
    pin_hash:pinHash,
    primeiro_acesso_pendente:false,
    codigo_ativacao_hash:null,
    codigo_ativacao_expira_em:null,
    codigo_ativacao_usado_em:now.toISOString(),
    ativacao_tentativas:0,
    ativacao_bloqueado_ate:null,
    atualizado_em:now.toISOString(),
    ultimo_login:now.toISOString()
  };
  const {error:ue}=await db.from("usuarios").update(patch).eq("id",user.id);
  if(ue)throw new Error(ue.message);
  const activated={...user,...patch};
  await auditV181(activated,"ATIVAR_PRIMEIRO_ACESSO","USUARIO",user.id,{identificador:user.identificador});
  const token=crypto.randomUUID()+crypto.randomUUID();
  const expires=new Date(Date.now()+SESSION_HOURS*3600_000).toISOString();
  const {error:se}=await db.from("migration_sessions").insert({token,usuario_id:user.id,expires_at:expires});
  if(se)throw new Error(se.message);
  return JSON.stringify({ok:true,token,user:publicUser(activated)});
}

async function requireAuth(token: string, adminOnly = false) {
  if (!token) throw new Error("Sessão expirada. Entre novamente.");
  const { data: sess, error: se } = await db.from("migration_sessions")
    .select("token,usuario_id,expires_at").eq("token", token).maybeSingle();
  if (se || !sess || new Date(sess.expires_at).getTime() <= Date.now()) {
    if (sess?.token) await db.from("migration_sessions").delete().eq("token", sess.token);
    throw new Error("Sessão expirada. Entre novamente.");
  }
  const { data: user, error: ue } = await db.from("usuarios").select("*").eq("id", sess.usuario_id).maybeSingle();
  if (ue || !user || !user.ativo) throw new Error("Usuário inativo.");
  if (adminOnly && String(user.perfil || "").toUpperCase() !== "ADMIN") throw new Error("Ação permitida somente para administrador.");
  const expires = new Date(Date.now() + SESSION_HOURS * 3600_000).toISOString();
  await db.from("migration_sessions").update({ expires_at: expires }).eq("token", token);
  return user;
}
function emptyBootstrap(user: any) {
  return {
    version: VERSION, user: publicUser(user),
    professionals: [], clients: [], services: [], legacyServices: [],
    paymentMethods: [], products: [], categories: [], serviceCategories: [],
    productCategories: [], campaigns: [],
    allProfessionals: [], allSpecialties: [], allClients: [], allServices: [],
    allPaymentMethods: [], allProducts: [], allCategories: [],
    allServiceCategories: [], allProductCategories: [], allCampaigns: [],
    users: [], rates: [], feeRules: [], performanceMode: "MIGRATION_PREVIEW"
  };
}
function emptyDashboard(admin: boolean) {
  return admin ? {
    admin: true, gross: 0, expensesPaid: 0, commissionGenerated: 0,
    studioAfterCommission: 0, cashResult: 0, balance: 0, balanceCurrentV180: 0,
    commissionPayableV180: 0, availableBalanceV180: 0, thirdPartyPayableV180: 0,
    cardPayableB4: 0, cardPayableDetailB4: { total: 0, items: [] },
    futurePackageCommissionV180: 0,
    futurePackageCommissionDetailV180: { base: 0, rate: .45, estimated: 0, remainingServices: 0, packages: 0 },
    consignmentPayableV180: 0,
    consignmentPayableDetailV180: { total: 0, items: 0, suppliers: 0 },
    expenseVsRevenueV180: [], expenseVsRevenueV170: [], expenseCompositionV159: [],
    paymentMix: [], byProfessional: [], timeline: [], stockAlerts: [], latestAppointments: []
  } : { admin: false, appointments: 0, sales: 0, packages: 0, stockAlerts: [], latestAppointments: [] };
}


function nowIsoV181(){ return new Date().toISOString(); }
function todayV181(){ return new Intl.DateTimeFormat("en-CA",{timeZone:"America/Sao_Paulo",year:"numeric",month:"2-digit",day:"2-digit"}).format(new Date()); }
function dateOnlyV181(v){ if(!v)return ""; const s=String(v); return /^\d{4}-\d{2}-\d{2}/.test(s)?s.slice(0,10):s.slice(0,10); }
function numV181(v){ if(typeof v==="number")return Number.isFinite(v)?v:0; if(v===null||v===undefined||v==="")return 0; const s=String(v).trim(); const n=Number(s.includes(",")?s.replace(/\./g,"").replace(",",".").replace(/[^\d.-]/g,""):s.replace(/[^\d.-]/g,"")); return Number.isFinite(n)?n:0; }
function round2V181(v){ return Math.round((numV181(v)+Number.EPSILON)*100)/100; }
function isActiveV181(v){ if(typeof v==="boolean")return v; const s=String(v??"").toUpperCase(); return !["FALSE","0","INATIVO","EXCLUIDO"].includes(s); }
function normalizeTextV181(v){ return String(v??"").normalize("NFD").replace(/[\u0300-\u036f]/g,"").toLowerCase().trim().replace(/\s+/g," "); }
function titleV181(v,lowerFirstConnector=false){ const raw=String(v??"").trim().replace(/\s+/g," "); if(!raw)return ""; const lowers={da:1,de:1,do:1,das:1,dos:1,e:1,em:1,na:1,no:1,nas:1,nos:1,por:1,para:1}; let idx=0; return raw.split(/(\s+|\+)/).map(p=>{if(!p||/^\s+$/.test(p)||p==="+")return p;const l=p.toLocaleLowerCase("pt-BR");const keep=(idx>0||lowerFirstConnector)&&lowers[normalizeTextV181(l)];idx++;return keep?l:l.charAt(0).toLocaleUpperCase("pt-BR")+l.slice(1);}).join("").replace(/\s*\+\s*/g," + ").replace(/\s+/g," ").trim(); }
function phoneV181(v){ let d=String(v??"").replace(/\D/g,""); if(!d)return ""; if(d.startsWith("55")&&(d.length===12||d.length===13))return d; if(d.length===10||d.length===11)return "55"+d; if(d.length>13&&d.startsWith("55"))d=d.slice(0,13); return d; }
function clientNameV181(c){ return [String(c?.nome||"").trim(),String(c?.sobrenome||"").trim()].filter(Boolean).join(" ").replace(/\s+/g," ").trim(); }
function uidV181(prefix){ return String(prefix||"ID")+"-"+crypto.randomUUID().split("-")[0].toUpperCase(); }
function catalogStatusV181(s){ return String(s?.catalogo_status||"ATUAL").toUpperCase().trim()||"ATUAL"; }
function professionalDeletedV181(p){ const s=String(p?.excluido??"").toUpperCase(); return ["TRUE","1","SIM","YES"].includes(s); }
function productDeletedV181(p){ const s=String(p?.excluido??"").toUpperCase(); return ["TRUE","1","SIM","YES"].includes(s); }
function birthdayV181(day,month){ const d=Math.floor(numV181(day)),m=Math.floor(numV181(month)); if(m<1||m>12||d<1||d>31)throw new Error("Informe dia e mês válidos para o aniversário."); const max=[31,29,31,30,31,30,31,31,30,31,30,31][m-1]; if(d>max)throw new Error("Dia inválido para o mês informado."); return {day:d,month:m}; }
function cpfNormV181(v){ return String(v??"").replace(/\D/g,"").slice(0,11); }
function cpfValidV181(v){ const cpf=cpfNormV181(v); if(!cpf)return true; if(cpf.length!==11||/^(\d)\1{10}$/.test(cpf))return false; let sum=0;for(let i=0;i<9;i++)sum+=Number(cpf[i])*(10-i);let d=(sum*10)%11;if(d===10)d=0;if(d!==Number(cpf[9]))return false;sum=0;for(let i=0;i<10;i++)sum+=Number(cpf[i])*(11-i);d=(sum*10)%11;if(d===10)d=0;return d===Number(cpf[10]); }

async function allRowsV181(table){ const {data,error}=await db.from(table).select("*"); if(error)throw new Error(error.message); return data||[]; }
async function rowByIdV181(table,id){ if(!id)return null; const {data,error}=await db.from(table).select("*").eq("id",String(id)).maybeSingle(); if(error)throw new Error(error.message); return data||null; }
async function insertV181(table,row){ const {error}=await db.from(table).insert(row); if(error)throw new Error(error.message); return row; }
async function updateV181(table,id,patch){ const {error}=await db.from(table).update(patch).eq("id",String(id)); if(error)throw new Error(error.message); return true; }
async function deleteV181(table,id){ const {error}=await db.from(table).delete().eq("id",String(id)); if(error)throw new Error(error.message); return true; }
async function auditV181(user,action,entity,entityId,details){ await insertV181("auditoria",{id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user?.id||"SYSTEM",usuario_nome:user?.nome||"Sistema",acao:String(action||""),entidade:String(entity||""),entidade_id:String(entityId||""),detalhes:JSON.stringify(details??{})}); }

async function productsSnapshotV181(user){
  const admin=String(user?.perfil||"").toUpperCase()==="ADMIN";
  const [products,cats]=await Promise.all([allRowsV181("produtos"),allRowsV181("categorias_produtos")]);
  const cm={};cats.forEach(c=>cm[String(c.id)]=c);
  const all=products.filter(p=>!productDeletedV181(p)).map(p=>({id:p.id,categoria_produto_id:p.categoria_produto_id||"",categoria:(cm[String(p.categoria_produto_id||"")]||{}).nome||p.categoria||"Outros",produto:p.produto,marca:p.marca||"",fornecedor:p.fornecedor||"",representante_fornecedor:p.representante_fornecedor||"",conteudo:p.conteudo||"",unidade:p.unidade||"unidade",estoque_atual:numV181(p.estoque_atual),estoque_minimo:numV181(p.estoque_minimo),custo_unitario:numV181(p.custo_unitario),preco_venda:numV181(p.preco_venda),comissao_venda:numV181(p.comissao_venda),finalidade:String(p.finalidade||"OPERACIONAL").toUpperCase(),modelo_comercial:String(p.modelo_comercial||(String(p.finalidade||"OPERACIONAL").toUpperCase()==="VENDA"?"NORMAL":"")).toUpperCase(),valor_repasse_fornecedor:numV181(p.valor_repasse_fornecedor),produto_operacional_vinculado_id:p.produto_operacional_vinculado_id||"",ativo:isActiveV181(p.ativo),excluido:false})).sort((a,b)=>String(a.produto).localeCompare(String(b.produto),"pt-BR"));
  return {products:all.filter(x=>x.ativo),allProducts:admin?all:[]};
}

async function referenceDataV181(user,full=false){
  const admin=String(user?.perfil||"").toUpperCase()==="ADMIN";
  const [svcCats,prodCats,services,profLinks,professionals,clients,payments,expCats,expSubs,campaigns,specialties,users,rates,feeRules]=await Promise.all([
    allRowsV181("categorias_servicos"),allRowsV181("categorias_produtos"),allRowsV181("servicos"),allRowsV181("profissional_servicos"),allRowsV181("profissionais"),allRowsV181("clientes"),allRowsV181("formas_pagamento"),allRowsV181("categorias_despesas"),allRowsV181("subcategorias_despesas"),allRowsV181("campanhas"),allRowsV181("especialidades"),allRowsV181("usuarios"),allRowsV181("taxas_pagamento"),allRowsV181("profissional_regras_taxa")
  ]);
  const sc={};svcCats.forEach(c=>sc[String(c.id)]=c); const sn={};services.forEach(s=>sn[String(s.id)]=s.nome);
  const links={};profLinks.filter(x=>isActiveV181(x.ativo)).forEach(r=>{const srv=services.find(s=>String(s.id)===String(r.servico_id));if(!srv)return;(links[String(r.profissional_id)]??=[]).push({id:srv.id,nome:srv.nome,categoria_id:srv.categoria_servico_id||srv.categoria_id||"",categoria:(sc[String(srv.categoria_servico_id||srv.categoria_id||"")]||{}).nome||srv.categoria||"",ativo:isActiveV181(srv.ativo),catalogo_status:catalogStatusV181(srv)});});
  const profAll=professionals.filter(p=>!professionalDeletedV181(p)).map(p=>{const ss=(links[String(p.id)]||[]).filter(s=>s.ativo&&s.catalogo_status==="ATUAL").sort((a,b)=>String(a.categoria).localeCompare(String(b.categoria),"pt-BR")||String(a.nome).localeCompare(String(b.nome),"pt-BR"));const seen=new Set(),cats=[];ss.forEach(s=>{const k=normalizeTextV181(s.categoria);if(s.categoria&&!seen.has(k)){seen.add(k);cats.push({id:s.categoria_id||"",nome:s.categoria});}});cats.sort((a,b)=>String(a.nome).localeCompare(String(b.nome),"pt-BR"));return {id:p.id,nome:p.nome,telefone:p.telefone||"",cpf:admin?(p.cpf||""):"",data_nascimento:admin?dateOnlyV181(p.data_nascimento):"",pix:p.pix||"",especialidade:cats.map(x=>x.nome).join(", "),categorias:cats,categoria_ids:cats.map(x=>x.id).filter(Boolean),servicos:ss,servico_ids:ss.map(x=>x.id),comissao_padrao:numV181(p.comissao_padrao),ativo:isActiveV181(p.ativo),excluido:false,observacoes:p.observacoes||""};}).sort((a,b)=>String(a.nome).localeCompare(String(b.nome),"pt-BR"));
  const cliAll=clients.map(c=>({id:c.id,nome:c.nome,sobrenome:c.sobrenome||"",nome_completo:clientNameV181(c),telefone:c.telefone||"",aniversario_dia:Number(c.aniversario_dia||0),aniversario_mes:Number(c.aniversario_mes||0),data_cadastro:dateOnlyV181(c.data_cadastro)||dateOnlyV181(c.criado_em),observacoes:c.observacoes||"",ativo:isActiveV181(c.ativo)})).sort((a,b)=>String(a.nome_completo).localeCompare(String(b.nome_completo),"pt-BR"));
  const srvAll=services.map(s=>({id:s.id,categoria_id:s.categoria_servico_id||s.categoria_id||"",categoria_servico_id:s.categoria_servico_id||"",categoria:(sc[String(s.categoria_servico_id||s.categoria_id||"")]||{}).nome||s.categoria||"",nome:s.nome,duracao_minutos:Math.max(0,Math.round(numV181(s.duracao_minutos))),preco_padrao:numV181(s.preco_padrao),custo_servico:numV181(s.custo_servico),catalogo_status:catalogStatusV181(s),equivalente_atual_id:s.equivalente_atual_id||"",equivalente_atual_nome:s.equivalente_atual_id?(sn[String(s.equivalente_atual_id)]||""):"",origem:s.origem||"",ativo:isActiveV181(s.ativo)})).sort((a,b)=>String(a.nome).localeCompare(String(b.nome),"pt-BR"));
  const payAll=payments.map(p=>({id:p.id,nome:p.nome,ativo:isActiveV181(p.ativo)})).sort((a,b)=>String(a.nome).localeCompare(String(b.nome),"pt-BR"));
  const serviceCategories=svcCats.map(c=>({id:c.id,tipo:"SERVICO",categoria:c.nome,subcategoria:"",ativo:isActiveV181(c.ativo)})).sort((a,b)=>String(a.categoria).localeCompare(String(b.categoria),"pt-BR"));
  const productCategories=prodCats.map(c=>({id:c.id,categoria:c.nome,ativo:isActiveV181(c.ativo)})).sort((a,b)=>String(a.categoria).localeCompare(String(b.categoria),"pt-BR"));
  const categories=[];expCats.forEach(c=>{categories.push({id:c.id,tipo:"DESPESA",categoria:c.nome,subcategoria:"",subcategoria_id:"",ativo:isActiveV181(c.ativo)});expSubs.filter(s=>String(s.categoria_despesa_id)===String(c.id)).forEach(s=>categories.push({id:c.id,tipo:"DESPESA",categoria:c.nome,subcategoria:s.nome,subcategoria_id:s.id,ativo:isActiveV181(c.ativo)&&isActiveV181(s.ativo)}));});categories.sort((a,b)=>(String(a.categoria)+" "+String(a.subcategoria||"")).localeCompare(String(b.categoria)+" "+String(b.subcategoria||""),"pt-BR"));
  const campAll=campaigns.map(c=>({id:c.id,nome:c.nome,descricao:c.descricao||"",data_inicio:dateOnlyV181(c.data_inicio),data_fim:dateOnlyV181(c.data_fim),ativo:isActiveV181(c.ativo)})).sort((a,b)=>String(a.nome).localeCompare(String(b.nome),"pt-BR"));
  const base={version:"1.8.1",user:publicUser(user),professionals:profAll.filter(x=>x.ativo),specialties:specialties.filter(x=>isActiveV181(x.ativo)).map(x=>({id:x.id,nome:x.nome,ativo:true})),clients:cliAll.filter(x=>x.ativo),services:srvAll.filter(x=>x.ativo&&x.catalogo_status==="ATUAL"),legacyServices:admin?srvAll.filter(x=>x.catalogo_status==="LEGADO"):[],paymentMethods:payAll.filter(x=>x.ativo),categories:categories.filter(x=>x.ativo),serviceCategories:serviceCategories.filter(x=>x.ativo),productCategories:productCategories.filter(x=>x.ativo),campaigns:campAll.filter(x=>x.ativo)};
  if(full){
    const prod=await productsSnapshotV181(user);
    Object.assign(base,{products:prod.products,allProfessionals:admin?profAll:[],allSpecialties:admin?specialties.map(x=>({id:x.id,nome:x.nome,ativo:isActiveV181(x.ativo)})):[],allClients:admin?cliAll:[],allServices:admin?srvAll:[],allPaymentMethods:admin?payAll:[],allProducts:admin?prod.allProducts:[],allCategories:admin?categories:[],allServiceCategories:admin?serviceCategories:[],allProductCategories:admin?productCategories:[],allCampaigns:admin?campAll:[],users:admin?users.map(publicUser).sort((a,b)=>String(a.nome).localeCompare(String(b.nome),"pt-BR")):[],rates:rates.map(r=>({id:r.id,forma_id:r.forma_id,forma_nome:r.forma_nome,bandeira:r.bandeira||"",condicao:String(r.condicao||"QUALQUER").toUpperCase(),percentual:numV181(r.percentual),taxa_fixa:numV181(r.taxa_fixa),vigencia_inicio:dateOnlyV181(r.vigencia_inicio),vigencia_fim:dateOnlyV181(r.vigencia_fim),ativo:isActiveV181(r.ativo),versao_anterior_id:r.versao_anterior_id||""})),feeRules:admin?feeRules.map(r=>({id:r.id,profissional_id:r.profissional_id,profissional_nome:r.profissional_nome,forma_id:r.forma_id,forma_nome:r.forma_nome,desconta_taxa:!!r.desconta_taxa,vigencia_inicio:dateOnlyV181(r.vigencia_inicio),vigencia_fim:dateOnlyV181(r.vigencia_fim),ativo:isActiveV181(r.ativo),versao_anterior_id:r.versao_anterior_id||""})):[]});
  }
  return base;
}

async function saveClientV181(user,p){
  p=p||{}; const existing=p.id?await rowByIdV181("clientes",p.id):null; const nome=titleV181(p.nome),sobrenome=titleV181(p.sobrenome,true),telefone=phoneV181(p.telefone); if(!nome)throw new Error("Informe o nome da cliente.");if(!sobrenome)throw new Error("Informe o sobrenome da cliente.");if(!telefone)throw new Error("Informe o telefone / WhatsApp da cliente."); const bd=birthdayV181(p.aniversario_dia,p.aniversario_mes); const all=await allRowsV181("clientes"); const dup=all.find(x=>(!existing||String(x.id)!==String(existing.id))&&isActiveV181(x.ativo)&&normalizeTextV181(clientNameV181(x))===normalizeTextV181(nome+" "+sobrenome)&&phoneV181(x.telefone)===telefone);if(dup)throw new Error("Já existe uma cliente com este nome e telefone."); const patch={nome,sobrenome,telefone,aniversario_dia:bd.day,aniversario_mes:bd.month,observacoes:String(p.observacoes||""),atualizado_em:nowIsoV181()}; if(existing){await updateV181("clientes",existing.id,patch);await auditV181(user,"ALTERAR","CLIENTE",existing.id,{antes:existing,depois:patch});return existing.id;} const row={id:uidV181("CLI"),...patch,data_cadastro:todayV181(),ativo:true,criado_em:nowIsoV181()};await insertV181("clientes",row);await auditV181(user,"CRIAR","CLIENTE",row.id,{nome_completo:clientNameV181(row),telefone:row.telefone});return row.id;
}

async function saveSimpleCategoryV181(user,table,prefix,entity,p){
  const name=titleV181(p?.nome);if(!name)throw new Error("Informe o nome.");const all=await allRowsV181(table),existing=p?.id?all.find(x=>String(x.id)===String(p.id)):null,dupe=all.find(x=>(!existing||String(x.id)!==String(existing.id))&&normalizeTextV181(x.nome)===normalizeTextV181(name));if(dupe&&isActiveV181(dupe.ativo))throw new Error("Este cadastro já existe.");if(existing){await updateV181(table,existing.id,{nome:name,atualizado_em:nowIsoV181()});await auditV181(user,"ALTERAR",entity,existing.id,{antes:existing,nome:name});return existing.id;}if(dupe){await updateV181(table,dupe.id,{nome:name,ativo:true,atualizado_em:nowIsoV181()});return dupe.id;}const row={id:uidV181(prefix),nome:name,ativo:true,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};await insertV181(table,row);await auditV181(user,"CRIAR",entity,row.id,row);return row.id;
}

async function saveServiceV181(user,p){
  p=p||{};const existing=p.id?await rowByIdV181("servicos",p.id):null;if(existing&&catalogStatusV181(existing)==="LEGADO")throw new Error("Serviços legados não são editados como catálogo atual. Use “Equivalente atual”.");if(!p.nome)throw new Error("Informe o serviço.");if(!p.categoria&&!p.categoria_id)throw new Error("Informe a categoria.");if(numV181(p.duracao_minutos)<=0)throw new Error("Informe a duração do serviço.");if(p.preco_padrao===undefined||p.preco_padrao===null||p.preco_padrao==="")throw new Error("Informe o preço padrão.");
  let cat=p.categoria_id?await rowByIdV181("categorias_servicos",p.categoria_id):null;if(!cat||!isActiveV181(cat.ativo)){const all=await allRowsV181("categorias_servicos");cat=all.find(x=>normalizeTextV181(x.nome)===normalizeTextV181(p.categoria));if(!cat){cat={id:uidV181("CSV"),nome:titleV181(p.categoria),ativo:true,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};await insertV181("categorias_servicos",cat);}else if(!isActiveV181(cat.ativo)){await updateV181("categorias_servicos",cat.id,{ativo:true,atualizado_em:nowIsoV181()});cat={...cat,ativo:true};}}
  const category=cat.nome,name=titleV181(p.nome),all=await allRowsV181("servicos"),dup=all.find(x=>(!existing||String(x.id)!==String(existing.id))&&catalogStatusV181(x)==="ATUAL"&&isActiveV181(x.ativo)&&normalizeTextV181(x.categoria)===normalizeTextV181(category)&&normalizeTextV181(x.nome)===normalizeTextV181(name));if(dup)throw new Error("O serviço “"+dup.nome+"” já está cadastrado no catálogo atual em "+dup.categoria+".");
  const patch={categoria_id:"",categoria_servico_id:cat.id,categoria:category,nome,duracao_minutos:Math.max(1,Math.round(numV181(p.duracao_minutos))),preco_padrao:round2V181(p.preco_padrao),custo_servico:round2V181(p.custo_servico||0),catalogo_status:"ATUAL",origem:existing?(existing.origem||"SISTEMA"):"SISTEMA",atualizado_em:nowIsoV181()};if(existing){await updateV181("servicos",existing.id,patch);await auditV181(user,"ALTERAR","SERVICO",existing.id,{antes:existing,depois:patch});return existing.id;}const row={id:uidV181("SRV"),...patch,equivalente_atual_id:"",ativo:true,criado_em:nowIsoV181()};await insertV181("servicos",row);await auditV181(user,"CRIAR","SERVICO",row.id,row);return row.id;
}

async function saveProfessionalV181(user,p){
  p=p||{};if(!p.nome)throw new Error("Informe o nome.");const existing=p.id?await rowByIdV181("profissionais",p.id):null;if(existing&&professionalDeletedV181(existing))throw new Error("Profissional excluída não pode ser editada.");const cpf=cpfNormV181(p.cpf);if(cpf&&!cpfValidV181(cpf))throw new Error("CPF inválido.");const profs=await allRowsV181("profissionais");if(cpf&&profs.find(x=>!professionalDeletedV181(x)&&String(x.id)!==String(existing?.id||"")&&cpfNormV181(x.cpf)===cpf))throw new Error("Este CPF já está cadastrado para outra profissional.");const birth=dateOnlyV181(p.data_nascimento||"");if(birth&&birth>todayV181())throw new Error("Data de nascimento não pode estar no futuro.");const ids=[...new Set((p.servico_ids||[]).map(String).filter(Boolean))],services=(await allRowsV181("servicos")).filter(s=>ids.includes(String(s.id)));if(services.length!==ids.length)throw new Error("Um dos serviços selecionados não foi encontrado.");services.forEach(s=>{if(!isActiveV181(s.ativo)||catalogStatusV181(s)!=="ATUAL")throw new Error("Somente serviços atuais e ativos podem ser vinculados à profissional.");});const cats=[...new Set(services.map(s=>String(s.categoria||"").trim()).filter(Boolean))].sort((a,b)=>a.localeCompare(b,"pt-BR"));const patch={nome:titleV181(p.nome),telefone:phoneV181(p.telefone),cpf,data_nascimento:birth||null,pix:String(p.pix||""),especialidade:cats.join(", "),comissao_padrao:numV181(p.comissao_padrao),observacoes:String(p.observacoes||""),atualizado_em:nowIsoV181()};let id;if(existing){id=existing.id;await updateV181("profissionais",id,patch);await auditV181(user,"ALTERAR","PROFISSIONAL",id,{antes:existing,depois:patch,servico_ids:ids,categorias:cats});}else{const row={id:uidV181("PRO"),...patch,ativo:true,excluido:false,criado_em:nowIsoV181()};await insertV181("profissionais",row);id=row.id;await auditV181(user,"CRIAR","PROFISSIONAL",id,{...row,servico_ids:ids,categorias:cats});}
  const links=await allRowsV181("profissional_servicos");for(const r of links.filter(x=>String(x.profissional_id)===String(id)&&isActiveV181(x.ativo)))await updateV181("profissional_servicos",r.id,{ativo:false,atualizado_em:nowIsoV181()});for(const s of services){const rel=links.find(r=>String(r.profissional_id)===String(id)&&String(r.servico_id)===String(s.id));const rp={especialidade_id:"",servico_nome:s.nome,categoria_id:"",categoria_servico_id:s.categoria_servico_id||s.categoria_id||"",categoria:s.categoria||"",ativo:true,atualizado_em:nowIsoV181()};if(rel)await updateV181("profissional_servicos",rel.id,rp);else await insertV181("profissional_servicos",{id:uidV181("PFS"),profissional_id:id,servico_id:s.id,criado_em:nowIsoV181(),...rp});}return id;
}

async function saveProductV181(user,p){
  p=p||{};if(!p.produto)throw new Error("Informe o produto.");const existing=p.id?await rowByIdV181("produtos",p.id):null;if(existing&&productDeletedV181(existing))throw new Error("Produto excluído não pode ser editado.");let cat=p.categoria_produto_id?await rowByIdV181("categorias_produtos",p.categoria_produto_id):null;if(!cat||!isActiveV181(cat.ativo)){const all=await allRowsV181("categorias_produtos"),name=titleV181(p.categoria||"Outros");cat=all.find(x=>normalizeTextV181(x.nome)===normalizeTextV181(name));if(!cat){cat={id:uidV181("CPR"),nome:name,ativo:true,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};await insertV181("categorias_produtos",cat);}}
  const finalidade=String(p.finalidade||"OPERACIONAL").toUpperCase()==="VENDA"?"VENDA":"OPERACIONAL",modelo=finalidade==="VENDA"&&String(p.modelo_comercial||"NORMAL").toUpperCase()==="CONSIGNADO"?"CONSIGNADO":(finalidade==="VENDA"?"NORMAL":""),supplier=titleV181(p.fornecedor||""),representative=titleV181(p.representante_fornecedor||""),cost=round2V181(p.custo_unitario),price=round2V181(p.preco_venda),repasse=modelo==="CONSIGNADO"?round2V181(p.valor_repasse_fornecedor):0;if(finalidade==="VENDA"&&price<=0)throw new Error("Informe o preço de venda do produto.");if(finalidade==="VENDA"&&modelo==="CONSIGNADO"&&!supplier)throw new Error("Produto consignado precisa ter fornecedor informado.");if(finalidade==="VENDA"&&modelo==="CONSIGNADO"&&repasse<=0)throw new Error("Informe o valor de repasse ao fornecedor por unidade.");
  const patch={categoria_produto_id:cat.id,categoria:cat.nome,produto:titleV181(p.produto),marca:titleV181(p.marca||""),fornecedor:supplier,representante_fornecedor:representative,conteudo:String(p.conteudo||""),unidade:String(p.unidade||"unidade"),estoque_minimo:numV181(p.estoque_minimo),custo_unitario:cost,preco_venda:price,comissao_venda:numV181(p.comissao_venda),finalidade,modelo_comercial:modelo,valor_repasse_fornecedor:repasse,atualizado_em:nowIsoV181()};let id;if(existing){id=existing.id;await updateV181("produtos",id,{...patch,produto_operacional_vinculado_id:existing.produto_operacional_vinculado_id||""});await auditV181(user,"ALTERAR","PRODUTO",id,{antes:existing,depois:patch});}else{const initial=numV181(p.estoque_atual),row={id:uidV181("PROD"),...patch,estoque_atual:initial,custo_total_referencia:round2V181(initial*cost),ativo:true,excluido:false,origem:"SISTEMA",criado_em:nowIsoV181(),produto_operacional_vinculado_id:""};await insertV181("produtos",row);id=row.id;if(initial!==0)await insertV181("estoque_movimentos",{id:uidV181("EST"),data:todayV181(),produto_id:row.id,produto_nome:row.produto,tipo:"ENTRADA_INICIAL",quantidade:initial,profissional_id:"",profissional_nome:"",custo_total:round2V181(initial*cost),observacoes:"Estoque inicial do cadastro",usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),referencia_tipo:"CADASTRO",referencia_id:row.id,status:"ATIVO"});await auditV181(user,"CRIAR","PRODUTO",row.id,{produto:row.produto,finalidade,modelo_comercial:modelo});}return {ok:true,id,regularization:await productHistoryPreviewV181(id)};
}


async function saveSpecialtyV181(user,p){
  p=p||{};if(!p.nome)throw new Error("Informe a função.");const name=titleV181(p.nome),all=await allRowsV181("especialidades"),existing=p.id?all.find(x=>String(x.id)===String(p.id)):null,dup=all.find(x=>(!existing||String(x.id)!==String(existing.id))&&normalizeTextV181(x.nome)===normalizeTextV181(name));if(dup&&isActiveV181(dup.ativo))throw new Error("Esta função já está cadastrada.");let id;if(existing){id=existing.id;await updateV181("especialidades",id,{nome:name,atualizado_em:nowIsoV181()});await auditV181(user,"ALTERAR","FUNCAO",id,{antes:existing,nome:name});}else if(dup){id=dup.id;await updateV181("especialidades",id,{nome:name,ativo:true,atualizado_em:nowIsoV181()});}else{const row={id:uidV181("ESP"),nome:name,ativo:true,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};await insertV181("especialidades",row);id=row.id;await auditV181(user,"CRIAR","FUNCAO",id,row);}
  const ids=[...new Set((p.servico_ids||[]).map(String).filter(Boolean))],services=(await allRowsV181("servicos")).filter(s=>ids.includes(String(s.id))&&isActiveV181(s.ativo)&&catalogStatusV181(s)==="ATUAL");if(services.length!==ids.length)throw new Error("Um dos serviços selecionados não está disponível no catálogo atual.");const links=await allRowsV181("especialidade_servicos");for(const r of links.filter(x=>String(x.especialidade_id)===String(id)&&isActiveV181(x.ativo)))await updateV181("especialidade_servicos",r.id,{ativo:false,atualizado_em:nowIsoV181()});for(const s of services){const rel=links.find(r=>String(r.especialidade_id)===String(id)&&String(r.servico_id)===String(s.id));if(rel)await updateV181("especialidade_servicos",rel.id,{servico_nome:s.nome,ativo:true,atualizado_em:nowIsoV181()});else await insertV181("especialidade_servicos",{id:uidV181("EFS"),especialidade_id:id,servico_id:s.id,servico_nome:s.nome,ativo:true,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()});}return id;
}
async function savePaymentMethodV181(user,p){p=p||{};if(!p.nome)throw new Error("Informe o nome da forma de pagamento.");const all=await allRowsV181("formas_pagamento"),existing=p.id?all.find(x=>String(x.id)===String(p.id)):null;if(!existing&&all.find(x=>normalizeTextV181(x.nome)===normalizeTextV181(p.nome)))throw new Error("Esta forma de pagamento já existe.");const patch={nome:titleV181(p.nome),atualizado_em:nowIsoV181()};if(existing){await updateV181("formas_pagamento",existing.id,patch);await auditV181(user,"ALTERAR","FORMA_PAGAMENTO",existing.id,{antes:existing,depois:patch});return existing.id;}const row={id:uidV181("FPG"),nome:patch.nome,ativo:true,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};await insertV181("formas_pagamento",row);await auditV181(user,"CRIAR","FORMA_PAGAMENTO",row.id,row);return row.id;}
async function saveExpenseSubcategoryV181(user,p){p=p||{};const cat=await rowByIdV181("categorias_despesas",p.categoria_despesa_id);if(!cat||!isActiveV181(cat.ativo))throw new Error("Selecione uma categoria de despesa ativa.");if(!p.nome)throw new Error("Informe a subcategoria.");const name=titleV181(p.nome),all=await allRowsV181("subcategorias_despesas"),existing=p.id?all.find(x=>String(x.id)===String(p.id)):null,dup=all.find(x=>(!existing||String(x.id)!==String(existing.id))&&String(x.categoria_despesa_id)===String(cat.id)&&normalizeTextV181(x.nome)===normalizeTextV181(name));if(dup&&isActiveV181(dup.ativo))throw new Error("Esta subcategoria já está cadastrada para a categoria selecionada.");if(existing){await updateV181("subcategorias_despesas",existing.id,{categoria_despesa_id:cat.id,nome:name,atualizado_em:nowIsoV181()});await auditV181(user,"ALTERAR","SUBCATEGORIA_DESPESA",existing.id,{antes:existing,categoria:cat.nome,nome:name});return existing.id;}if(dup){await updateV181("subcategorias_despesas",dup.id,{nome:name,ativo:true,atualizado_em:nowIsoV181()});return dup.id;}const row={id:uidV181("SDP"),categoria_despesa_id:cat.id,nome:name,ativo:true,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};await insertV181("subcategorias_despesas",row);await auditV181(user,"CRIAR","SUBCATEGORIA_DESPESA",row.id,row);return row.id;}
async function saveCampaignV181(user,p){p=p||{};const name=titleV181(p.nome);if(!name)throw new Error("Informe o nome da campanha.");const all=await allRowsV181("campanhas"),existing=p.id?all.find(x=>String(x.id)===String(p.id)):null,dup=all.find(x=>(!existing||String(x.id)!==String(existing.id))&&normalizeTextV181(x.nome)===normalizeTextV181(name)&&isActiveV181(x.ativo));if(dup)throw new Error("Esta campanha já está cadastrada.");const patch={nome:name,descricao:String(p.descricao||""),data_inicio:dateOnlyV181(p.data_inicio)||null,data_fim:dateOnlyV181(p.data_fim)||null,atualizado_em:nowIsoV181()};if(existing){await updateV181("campanhas",existing.id,patch);await auditV181(user,"ALTERAR","CAMPANHA",existing.id,patch);return existing.id;}const row={id:uidV181("CAM"),...patch,ativo:true,criado_em:nowIsoV181()};await insertV181("campanhas",row);await auditV181(user,"CRIAR","CAMPANHA",row.id,row);return row.id;}
function validatePinV181(pin){const v=String(pin||"").trim();if(!/^\d{6,}$/.test(v))throw new Error("A senha de acesso deve ser numérica e ter no mínimo 6 dígitos.");return v;}
async function createUserV181(admin,p){p=p||{};if(!p.nome||!p.identificador||!p.pin)throw new Error("Preencha nome, identificador e senha de acesso.");const pin=validatePinV181(p.pin),ident=String(p.identificador).trim().toLowerCase(),all=await allRowsV181("usuarios");if(all.find(x=>normalizeTextV181(x.identificador)===normalizeTextV181(ident)))throw new Error("Já existe usuário com esse identificador.");const profile=String(p.perfil||"USUARIO").toUpperCase()==="ADMIN"?"ADMIN":"USUARIO",row={id:uidV181("USR"),nome:titleV181(p.nome),identificador:ident,pin_hash:await sha256("studio-essence|"+pin),perfil:profile,ativo:true,criado_em:nowIsoV181(),ultimo_login:null,atualizado_em:nowIsoV181(),visualizar_atendimentos_dias:profile==="ADMIN"?99999:Math.max(1,Math.floor(numV181(p.visualizar_atendimentos_dias)||5)),editar_atendimentos_dias:profile==="ADMIN"?99999:Math.max(1,Math.floor(numV181(p.editar_atendimentos_dias)||1)),cancelar_atendimentos_dias:profile==="ADMIN"?99999:Math.max(1,Math.floor(numV181(p.cancelar_atendimentos_dias)||1))};await insertV181("usuarios",row);await auditV181(admin,"CRIAR","USUARIO",row.id,{nome:row.nome,perfil:row.perfil,permissoes:publicUser(row)});return publicUser(row);}
async function updateUserV181(admin,p){p=p||{};const u=await rowByIdV181("usuarios",p.id);if(!u)throw new Error("Usuário não encontrado.");if(!p.nome||!p.identificador)throw new Error("Informe nome e identificador.");const ident=String(p.identificador).trim().toLowerCase(),all=await allRowsV181("usuarios");if(all.find(x=>String(x.id)!==String(u.id)&&normalizeTextV181(x.identificador)===normalizeTextV181(ident)))throw new Error("Já existe outro usuário com esse identificador.");const profile=String(p.perfil||u.perfil).toUpperCase()==="ADMIN"?"ADMIN":"USUARIO",patch={nome:titleV181(p.nome),identificador:ident,perfil:profile,visualizar_atendimentos_dias:profile==="ADMIN"?99999:Math.max(1,Math.floor(numV181(p.visualizar_atendimentos_dias)||5)),editar_atendimentos_dias:profile==="ADMIN"?99999:Math.max(1,Math.floor(numV181(p.editar_atendimentos_dias)||1)),cancelar_atendimentos_dias:profile==="ADMIN"?99999:Math.max(1,Math.floor(numV181(p.cancelar_atendimentos_dias)||1)),atualizado_em:nowIsoV181()};if(p.pin)patch.pin_hash=await sha256("studio-essence|"+validatePinV181(p.pin));await updateV181("usuarios",u.id,patch);await auditV181(admin,"ALTERAR","USUARIO",u.id,{antes:publicUser(u),depois:patch});return publicUser({...u,...patch});}
async function setActiveV181(admin,entity,id,active){const map={PROFISSIONAL:"profissionais",SERVICO:"servicos",PRODUTO:"produtos",USUARIO:"usuarios",CLIENTE:"clientes",FORMA_PAGAMENTO:"formas_pagamento",CATEGORIA_SERVICO:"categorias_servicos",CATEGORIA_DESPESA:"categorias_despesas",CATEGORIA_PRODUTO:"categorias_produtos",SUBCATEGORIA_DESPESA:"subcategorias_despesas",ESPECIALIDADE:"especialidades",CAMPANHA:"campanhas"};const key=String(entity||"").toUpperCase();if(key==="TAXA_PAGAMENTO"||key==="REGRA_TAXA_PROFISSIONAL")throw new Error("Ativação versionada de taxas será liberada no próximo bloco da migração.");const table=map[key];if(!table)throw new Error("Tipo de cadastro inválido.");const row=await rowByIdV181(table,id);if(!row)throw new Error("Registro não encontrado.");if(key==="PROFISSIONAL"&&professionalDeletedV181(row))throw new Error("Profissional excluída não pode ser reativada.");if(key==="USUARIO"&&String(id)===String(admin.id)&&!active)throw new Error("Você não pode inativar o seu próprio usuário enquanto está conectado.");if(key==="USUARIO"&&!active&&String(row.perfil).toUpperCase()==="ADMIN"){const users=await allRowsV181("usuarios"),count=users.filter(x=>isActiveV181(x.ativo)&&String(x.perfil).toUpperCase()==="ADMIN").length;if(count<=1)throw new Error("O sistema precisa manter pelo menos um administrador ativo.");}await updateV181(table,id,{ativo:!!active,atualizado_em:nowIsoV181()});await auditV181(admin,active?"REATIVAR":"INATIVAR",key,id,{registro:row});return true;}


function feeConditionV181(v){const s=String(v||"QUALQUER").toUpperCase().replace(/\s+/g,"_");if(["A_VISTA","AVISTA","VISTA"].includes(s))return "A_VISTA";if(["PARCELADO","PARCELADA"].includes(s))return "PARCELADO";return "QUALQUER";}
function previousDayV181(date){const d=new Date(String(dateOnlyV181(date))+"T12:00:00-03:00");d.setDate(d.getDate()-1);return new Intl.DateTimeFormat("en-CA",{timeZone:"America/Sao_Paulo",year:"numeric",month:"2-digit",day:"2-digit"}).format(d);}
function rangeOverlapV181(a1,a2,b1,b2){const ae=a2||"9999-12-31",be=b2||"9999-12-31";return a1<=be&&b1<=ae;}
async function saveRateV181(user,p){
  p=p||{};const forma=await rowByIdV181("formas_pagamento",p.forma_id);if(!forma)throw new Error("Forma de pagamento inválida.");const old=p.id?await rowByIdV181("taxas_pagamento",p.id):null,bandeira=titleV181(p.bandeira||"",true),condicao=feeConditionV181(p.condicao),start=dateOnlyV181(p.vigencia_inicio||todayV181()),end=dateOnlyV181(p.vigencia_fim||"");if(end&&end<start)throw new Error("O fim da vigência não pode ser anterior ao início.");const all=await allRowsV181("taxas_pagamento"),tuple=(r)=>[String(r.forma_id||""),normalizeTextV181(r.bandeira||""),feeConditionV181(r.condicao)].join("|"),wanted=[String(forma.id),normalizeTextV181(bandeira),condicao].join("|"),overlap=all.find(r=>String(r.id)!==String(old?.id||"")&&tuple(r)===wanted&&isActiveV181(r.ativo)&&rangeOverlapV181(dateOnlyV181(r.vigencia_inicio||"1900-01-01"),dateOnlyV181(r.vigencia_fim||""),start,end));if(overlap)throw new Error("Já existe uma taxa ativa com vigência sobreposta para esta forma, bandeira e condição.");if(old&&isActiveV181(old.ativo)){const oldStart=dateOnlyV181(old.vigencia_inicio||"1900-01-01"),close=start>oldStart?previousDayV181(start):oldStart,keep=oldStart<start&&close>=todayV181();await updateV181("taxas_pagamento",old.id,{vigencia_fim:close,ativo:keep,atualizado_em:nowIsoV181()});}const row={id:uidV181("TAX"),forma_id:forma.id,forma_nome:forma.nome,bandeira,condicao,percentual:numV181(p.percentual)/100,taxa_fixa:round2V181(p.taxa_fixa),vigencia_inicio:start,vigencia_fim:end||null,ativo:true,versao_anterior_id:old?old.id:"",criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};await insertV181("taxas_pagamento",row);await auditV181(user,old?"VERSIONAR":"CRIAR","TAXA_PAGAMENTO",row.id,{antes:old||null,depois:row});return row.id;
}
async function currentFeeRuleV181(profId,formaId,date){const d=dateOnlyV181(date||todayV181()),all=await allRowsV181("profissional_regras_taxa");return all.filter(r=>String(r.profissional_id)===String(profId)&&String(r.forma_id)===String(formaId)&&(!dateOnlyV181(r.vigencia_inicio)||dateOnlyV181(r.vigencia_inicio)<=d)&&(!dateOnlyV181(r.vigencia_fim)||dateOnlyV181(r.vigencia_fim)>=d)).sort((a,b)=>(isActiveV181(b.ativo)?1:0)-(isActiveV181(a.ativo)?1:0)||String(dateOnlyV181(b.vigencia_inicio)).localeCompare(String(dateOnlyV181(a.vigencia_inicio)))||String(b.criado_em||"").localeCompare(String(a.criado_em||"")))[0]||null;}
async function saveFeeRuleV181(user,p){
  p=p||{};const prof=await rowByIdV181("profissionais",p.profissional_id),forma=await rowByIdV181("formas_pagamento",p.forma_id);if(!prof||!forma)throw new Error("Profissional ou forma inválida.");const old=p.id?await rowByIdV181("profissional_regras_taxa",p.id):await currentFeeRuleV181(prof.id,forma.id,todayV181()),start=dateOnlyV181(p.vigencia_inicio||todayV181()),end=dateOnlyV181(p.vigencia_fim||"");if(end&&end<start)throw new Error("O fim da vigência não pode ser anterior ao início.");const all=await allRowsV181("profissional_regras_taxa"),overlap=all.find(r=>String(r.id)!==String(old?.id||"")&&String(r.profissional_id)===String(prof.id)&&String(r.forma_id)===String(forma.id)&&isActiveV181(r.ativo)&&rangeOverlapV181(dateOnlyV181(r.vigencia_inicio||"1900-01-01"),dateOnlyV181(r.vigencia_fim||""),start,end));if(overlap)throw new Error("Já existe uma regra ativa com vigência sobreposta para esta profissional e forma de pagamento.");if(old&&isActiveV181(old.ativo)){const oldStart=dateOnlyV181(old.vigencia_inicio||"1900-01-01"),close=start>oldStart?previousDayV181(start):oldStart,keep=oldStart<start&&close>=todayV181();await updateV181("profissional_regras_taxa",old.id,{vigencia_fim:close,ativo:keep,atualizado_em:nowIsoV181()});}const row={id:uidV181("RGR"),profissional_id:prof.id,profissional_nome:prof.nome,forma_id:forma.id,forma_nome:forma.nome,desconta_taxa:!!p.desconta_taxa,vigencia_inicio:start,vigencia_fim:end||null,ativo:true,versao_anterior_id:old?old.id:"",criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};await insertV181("profissional_regras_taxa",row);await auditV181(user,old?"VERSIONAR":"CRIAR","REGRA_TAXA_PROFISSIONAL",row.id,{antes:old||null,depois:row});return row.id;
}


function boolV181(v,def){if(v===true||String(v).toLowerCase()==="true"||String(v)==="1")return true;if(v===false||String(v).toLowerCase()==="false"||String(v)==="0")return false;return def;}
async function accountBalanceAtV181(account,endDate){
  const end=dateOnlyV181(endDate||todayV181()),openingDate=dateOnlyV181(account.data_saldo_inicial||"1900-01-01"),mov=await allRowsV181("mov_caixa");let total=openingDate<=end?numV181(account.saldo_inicial):0;mov.forEach(m=>{if(String(m.status||"").toUpperCase()!=="REALIZADO")return;if(String(m.conta_financeira_id||"")!==String(account.id))return;const d=dateOnlyV181(m.data);if(d&&d<=end)total+=numV181(m.valor);});return round2V181(total);
}
async function commissionPositionV181(){
  const [atts,sales,ai,vi,closings,adv]=await Promise.all([allRowsV181("atendimentos"),allRowsV181("vendas"),allRowsV181("atendimento_itens"),allRowsV181("venda_itens"),allRowsV181("comissoes_fechamentos"),allRowsV181("vales_adiantamentos")]),am={},sm={},by={};atts.forEach(a=>am[String(a.id)]=a);sales.forEach(s=>sm[String(s.id)]=s);const bucket=(id,name)=>{const k=String(id||name||"SEM_PROFISSIONAL");return by[k]||(by[k]={profissional_id:id||"",profissional:name||"Sem profissional",pendentes:0,fechamentos_abertos:0,adiantamentos_abertos:0,a_pagar:0});};
  ai.forEach(i=>{const a=am[String(i.atendimento_id)];if(!a||String(a.status)==="CANCELADO"||!["","ATIVO","REALIZADO","CONCLUIDO"].includes(String(i.status||"").toUpperCase())||String(i.comissao_status||"PENDENTE")!=="PENDENTE")return;bucket(i.profissional_id,i.profissional_nome).pendentes+=numV181(i.valor_comissao);});
  vi.forEach(i=>{const s=sm[String(i.venda_id)];if(!s||String(s.status)==="CANCELADO"||!["","ATIVO","REALIZADO","CONCLUIDO"].includes(String(i.status||"").toUpperCase())||String(i.comissao_status||"")!=="PENDENTE")return;bucket(i.profissional_id,i.profissional_nome).pendentes+=numV181(i.valor_comissao);});
  closings.forEach(c=>{const st=String(c.status||"").toUpperCase();if(["PAGO","CANCELADO","EXCLUIDO"].includes(st))return;const net=c.total_liquido!==""&&c.total_liquido!=null?numV181(c.total_liquido):numV181(c.total_comissao);bucket(c.profissional_id,c.profissional_nome).fechamentos_abertos+=net;});
  adv.forEach(v=>{const st=String(v.status||"ABERTO").toUpperCase(),saldo=Math.max(0,numV181(v.saldo_aberto));if(!saldo||["CANCELADO","COMPENSADO"].includes(st))return;bucket(v.profissional_id,v.profissional_nome).adiantamentos_abertos+=saldo;});
  let total=0;const professionals=Object.values(by).map(x=>{x.pendentes=round2V181(x.pendentes);x.fechamentos_abertos=round2V181(x.fechamentos_abertos);x.adiantamentos_abertos=round2V181(x.adiantamentos_abertos);x.a_pagar=round2V181(Math.max(0,x.pendentes+x.fechamentos_abertos-x.adiantamentos_abertos));total+=x.a_pagar;return x;}).filter(x=>x.pendentes||x.fechamentos_abertos||x.adiantamentos_abertos).sort((a,b)=>b.a_pagar-a.a_pagar||String(a.profissional).localeCompare(String(b.profissional),"pt-BR"));return {total:round2V181(total),professionals};
}
async function financialPositionV181(){
  const [accounts,thirds]=await Promise.all([allRowsV181("contas_financeiras"),allRowsV181("repasses_terceiros")]);
  const out=[];
  for(const a of accounts){
    out.push({
      id:a.id,nome:a.nome,tipo:a.tipo,instituicao:a.instituicao||"",
      ativo:isActiveV181(a.ativo),saldo_inicial:round2V181(a.saldo_inicial),
      data_saldo_inicial:dateOnlyV181(a.data_saldo_inicial),
      incluir_consolidado:boolV181(a.incluir_consolidado,true),
      transitoria:boolV181(a.transitoria,false),
      permite_conciliacao:boolV181(a.permite_conciliacao,true),
      saldo:await accountBalanceAtV181(a,todayV181())
    });
  }
  const total=round2V181(out.filter(a=>a.ativo&&a.incluir_consolidado).reduce((s,a)=>s+a.saldo,0));
  const third=round2V181(thirds.filter(r=>String(r.status||"PENDENTE").toUpperCase()==="PENDENTE").reduce((s,r)=>s+numV181(r.valor_liquido),0));
  const [commission,card]=await Promise.all([commissionPositionV181(),cardPayableCalcV181()]);
  return {
    as_of:todayV181(),
    accounts:out.map(a=>({...a,incluir:a.incluir_consolidado})),
    total,
    thirdPartyPayable:third,
    commissionPayable:commission.total,
    cardPayable:card.total,
    available:round2V181(total-third-commission.total-card.total),
    professionals:commission.professionals
  };
}
async function saveFinancialAccountV181(user,p){
  p=p||{};const name=titleV181(p.nome);if(!name)throw new Error("Informe o nome da conta financeira.");const type=String(p.tipo||"BANCO").toUpperCase(),allowed=["BANCO","CARTEIRA","CAIXA","TRANSITORIA","RECEBIVEIS","OUTRA"];if(!allowed.includes(type))throw new Error("Tipo de conta inválido.");const patch={nome:name,tipo,instituicao:titleV181(p.instituicao||""),ativo:boolV181(p.ativo,true),saldo_inicial:round2V181(p.saldo_inicial),data_saldo_inicial:dateOnlyV181(p.data_saldo_inicial||todayV181()),incluir_consolidado:boolV181(p.incluir_consolidado,true),transitoria:boolV181(p.transitoria,false),permite_conciliacao:boolV181(p.permite_conciliacao,true),atualizado_em:nowIsoV181(),editado_por:user.nome};if(p.id){const before=await rowByIdV181("contas_financeiras",p.id);if(!before)throw new Error("Conta financeira não encontrada.");await updateV181("contas_financeiras",before.id,patch);const maps=await allRowsV181("forma_conta_financeira");for(const m of maps.filter(x=>String(x.conta_financeira_id)===String(before.id)))await updateV181("forma_conta_financeira",m.id,{conta_financeira_nome:name,atualizado_em:nowIsoV181()});await auditV181(user,"ALTERAR","CONTA_FINANCEIRA",before.id,{antes:before,depois:patch});return before.id;}const id=uidV181("CF");await insertV181("contas_financeiras",{id,...patch,observacoes:"",origem:"SISTEMA",criado_em:nowIsoV181()});await auditV181(user,"CRIAR","CONTA_FINANCEIRA",id,patch);return id;
}
async function addCashV181(data,competencia,tipo,origem,origemId,desc,value,status,payment,accountId,impact,financialId){
  const a=accountId?await rowByIdV181("contas_financeiras",accountId):null;const id=uidV181("MOV");await insertV181("mov_caixa",{id,data:dateOnlyV181(data||todayV181()),competencia:dateOnlyV181(competencia||data||todayV181()),tipo:String(tipo||""),origem:String(origem||""),origem_id:String(origemId||""),descricao:String(desc||""),valor:round2V181(value),status:String(status||"REALIZADO"),forma_pagamento:String(payment||""),criado_em:nowIsoV181(),conta_financeira_id:a?a.id:"",conta_financeira_nome:a?a.nome:"",impacto_resultado:impact===undefined?true:!!impact,conciliado:false,conciliacao_id:"",movimento_financeiro_id:String(financialId||"")});return id;
}



// ============================= v1.8.1 — Atendimentos / migração Supabase =============================
function attendanceSubtractDaysV181(iso:string,days:number){
  const p=String(iso||todayV181()).slice(0,10).split("-").map(Number);
  const d=new Date(Date.UTC(p[0],p[1]-1,p[2],12,0,0));d.setUTCDate(d.getUTCDate()-Math.max(0,days||0));
  return d.toISOString().slice(0,10);
}
function attendanceDateAllowedV181(user:any,date:any,field:string,fallback:number){
  if(String(user?.perfil||"").toUpperCase()==="ADMIN")return true;
  const d=dateOnlyV181(date),t=todayV181(),raw=Math.floor(numV181(user?.[field])),days=Math.max(1,raw>0?raw:fallback);
  return !!d&&d<=t&&d>=attendanceSubtractDaysV181(t,days-1);
}
function canViewAttendanceV181(user:any,date:any){return attendanceDateAllowedV181(user,date,"visualizar_atendimentos_dias",5);}
function canEditAttendanceV181(user:any,date:any){return attendanceDateAllowedV181(user,date,"editar_atendimentos_dias",1);}
function canCancelAttendanceV181(user:any,date:any){return attendanceDateAllowedV181(user,date,"cancelar_atendimentos_dias",1);}
function attendanceRowActiveV181(r:any){return ["","ATIVO","REALIZADO","CONCLUIDO"].includes(String(r?.status||"ATIVO").toUpperCase());}
function attendanceCommissionEditableV181(r:any){return ["PENDENTE","SEM_COMISSAO"].includes(String(r?.comissao_status||"PENDENTE").toUpperCase());}
function feeDateOkV181(r:any,date:string){const a=dateOnlyV181(r?.vigencia_inicio||""),b=dateOnlyV181(r?.vigencia_fim||"");return (!a||a<=date)&&(!b||b>=date);}
function feeBrandNormV181(v:any){return normalizeTextV181(v||"");}

async function resolveRateAttendanceV181(formId:string,date:string,p:any){
  const all=(await allRowsV181("taxas_pagamento")).filter(r=>String(r.forma_id)===String(formId)&&feeDateOkV181(r,date));
  if(p?.taxa_id){
    const exact=all.find(r=>String(r.id)===String(p.taxa_id));
    if(!exact)throw new Error("A taxa selecionada não é válida para esta forma/data. Atualize os dados.");
    return exact;
  }
  const brand=feeBrandNormV181(p?.bandeira||""),cond=feeConditionV181(p?.condicao||"QUALQUER");
  const ranked=all.map(r=>{
    const rb=feeBrandNormV181(r.bandeira||""),rc=feeConditionV181(r.condicao||"QUALQUER");
    let score=0;
    if(brand){if(rb===brand)score+=40;else if(!rb)score+=20;else return null;}
    else {if(!rb)score+=30;else score+=5;}
    if(cond!=="QUALQUER"){if(rc===cond)score+=20;else if(rc==="QUALQUER")score+=10;else return null;}
    else {if(rc==="QUALQUER")score+=15;else score+=2;}
    if(isActiveV181(r.ativo))score+=1;
    return {r,score};
  }).filter(Boolean) as any[];
  ranked.sort((a,b)=>b.score-a.score||String(dateOnlyV181(b.r.vigencia_inicio)).localeCompare(String(dateOnlyV181(a.r.vigencia_inicio)))||String(b.r.criado_em||"").localeCompare(String(a.r.criado_em||"")));
  return ranked[0]?.r||{id:"",bandeira:"",condicao:"QUALQUER",percentual:0,taxa_fixa:0};
}
async function paymentAccountAttendanceV181(formId:string){
  const maps=(await allRowsV181("forma_conta_financeira")).filter(m=>String(m.forma_id)===String(formId)&&isActiveV181(m.ativo));
  const map=maps.sort((a,b)=>String(b.atualizado_em||"").localeCompare(String(a.atualizado_em||"")))[0];
  if(!map)throw new Error("A forma de pagamento não possui conta financeira vinculada.");
  const acc=await rowByIdV181("contas_financeiras",map.conta_financeira_id);
  if(!acc||!isActiveV181(acc.ativo))throw new Error("A conta financeira vinculada à forma de pagamento está inativa ou não existe.");
  return acc;
}
async function campaignAttendanceV181(id:string,date:string){
  if(!id)return null;const c=await rowByIdV181("campanhas",id);
  if(!c||!isActiveV181(c.ativo)||dateOnlyV181(c.data_inicio)>date||dateOnlyV181(c.data_fim)<date)throw new Error("Selecione uma campanha/motivo ativa para o desconto.");
  return c;
}
async function feeRuleAttendanceV181(profId:string,formId:string,date:string){
  const r=await currentFeeRuleV181(profId,formId,date);return !!r?.desconta_taxa;
}
function roundMoneyV181(v:any){return round2V181(v);}
function moneyEqualV181(a:any,b:any){return Math.abs(roundMoneyV181(a)-roundMoneyV181(b))<=0.02;}

async function prepareAttendanceTxV181(user:any,p:any,id:string){
  p=p||{};if(!p.data||!Array.isArray(p.items)||!p.items.length)throw new Error("Preencha data, cliente e ao menos um serviço.");
  const date=dateOnlyV181(p.data);if(!date)throw new Error("Data do atendimento inválida.");
  const client=await rowByIdV181("clientes",p.cliente_id);
  if(!client||!isActiveV181(client.ativo))throw new Error("Selecione uma cliente ativa já cadastrada.");
  const nature=String(p.natureza||"NORMAL").toUpperCase();
  if(!["NORMAL","CORTESIA_COM_COMISSAO","CORTESIA_SEM_COMISSAO"].includes(nature))throw new Error("Tipo de atendimento inválido.");
  const courtesyReason=titleV181(p.cortesia_motivo||"");
  if(nature!=="NORMAL"&&!courtesyReason)throw new Error("Informe o motivo da cortesia.");
  let payer=String(p.cortesia_comissao_pagador||"").toUpperCase();
  if(nature==="CORTESIA_COM_COMISSAO"&&!["CLIENTE","STUDIO"].includes(payer))throw new Error("Informe quem assume a comissão da cortesia.");
  if(nature!=="CORTESIA_COM_COMISSAO")payer="";

  const [profs,services,oldItems,packageItems,packages]=await Promise.all([
    allRowsV181("profissionais"),allRowsV181("servicos"),allRowsV181("atendimento_itens"),allRowsV181("pacote_itens"),allRowsV181("pacotes")
  ]);
  const oldActive=oldItems.filter(x=>String(x.atendimento_id)===String(id)&&attendanceRowActiveV181(x));
  const legacyAllowed=new Set(oldActive.map(x=>String(x.servico_id)));
  const packageAllowed=new Set(oldActive.map(x=>String(x.pacote_item_id||"")).filter(Boolean));

  const prepared:any[]=[];
  for(const x of p.items){
    const prof=profs.find(r=>String(r.id)===String(x.profissional_id));
    if(!prof||!isActiveV181(prof.ativo)||professionalDeletedV181(prof))throw new Error("Selecione uma profissional ativa em todos os serviços.");
    const svc=services.find(r=>String(r.id)===String(x.servico_id));
    if(!svc||!isActiveV181(svc.ativo)||(catalogStatusV181(svc)==="LEGADO"&&!legacyAllowed.has(String(svc.id))))throw new Error("Selecione um serviço ativo do catálogo atual.");
    const table=roundMoneyV181(svc.preco_padrao);
    let charged=roundMoneyV181(x.valor),ref=charged,campaign:any=null,pkgItem:any=null,pkg:any=null,packageCourtesy=false;
    const pkgItemId=String(x.pacote_item_id||"");
    if(pkgItemId){
      if(nature!=="NORMAL")throw new Error("Consumo de pacote deve ser registrado como atendimento normal.");
      pkgItem=packageItems.find(r=>String(r.id)===pkgItemId);
      if(!pkgItem||String(pkgItem.servico_id)!==String(svc.id)||!attendanceRowActiveV181(pkgItem))throw new Error("O item de pacote selecionado é inválido.");
      pkg=packages.find(r=>String(r.id)===String(pkgItem.pacote_id));
      if(!pkg||String(pkg.cliente_id)!==String(client.id)||String(pkg.status||"").toUpperCase()==="CANCELADO")throw new Error("O pacote selecionado não pertence à cliente ou está cancelado.");
      const available=numV181(pkgItem.quantidade)-numV181(pkgItem.quantidade_consumida);
      if(available<1&&!packageAllowed.has(pkgItemId))throw new Error("O saldo selecionado do pacote não está mais disponível.");
      charged=0;packageCourtesy=!!pkgItem.cortesia_sem_comissao;ref=packageCourtesy?0:roundMoneyV181(pkgItem.valor_unitario_negociado);
    }else if(nature==="NORMAL"){
      if(charged<0)throw new Error("O valor do serviço não pode ser negativo.");
      if(charged<table-0.009)campaign=await campaignAttendanceV181(String(x.campanha_id||""),date);
      ref=charged;
    }else if(nature==="CORTESIA_COM_COMISSAO"){
      charged=0;ref=roundMoneyV181(x.valor_referencia_comissao||x.valor||table);
    }else {charged=0;ref=0;}
    const pct=(nature==="CORTESIA_SEM_COMISSAO"||packageCourtesy)?0:numV181(prof.comissao_padrao);
    prepared.push({x,prof,svc,table,charged,ref,campaign,pkgItem,pkg,packageCourtesy,pct,commissionTarget:roundMoneyV181(ref*pct)});
  }

  const serviceTotal=roundMoneyV181(prepared.reduce((s,i)=>s+i.charged,0));
  const commissionTarget=roundMoneyV181(prepared.reduce((s,i)=>s+i.commissionTarget,0));
  const rawPayments=Array.isArray(p.payments)?p.payments:[];
  let usePayments:any[]=[];
  if(nature==="CORTESIA_COM_COMISSAO"&&payer==="STUDIO")usePayments=[];
  else usePayments=rawPayments.filter(x=>x&&x.forma_id&&numV181(x.valor)>0);
  if(nature==="NORMAL"&&!moneyEqualV181(usePayments.reduce((s,x)=>s+numV181(x.valor),0),serviceTotal))throw new Error("A soma das formas de pagamento deve fechar com o total do atendimento.");
  if(nature==="CORTESIA_COM_COMISSAO"&&payer==="CLIENTE"&&!usePayments.length)throw new Error("Informe a forma de pagamento da comissão.");
  if(nature==="CORTESIA_SEM_COMISSAO"&&usePayments.length)throw new Error("Cortesia sem comissão não deve possuir pagamento.");

  const payments:any[]=[],cash:any[]=[],trocos:any[]=[];
  for(const rp of usePayments){
    const form=await rowByIdV181("formas_pagamento",rp.forma_id);
    if(!form||!isActiveV181(form.ativo))throw new Error("Forma de pagamento inválida ou inativa.");
    const account=await paymentAccountAttendanceV181(form.id);
    const rate=await resolveRateAttendanceV181(form.id,date,rp);
    const gross=roundMoneyV181(rp.valor),fee=roundMoneyV181(gross*numV181(rate.percentual)+numV181(rate.taxa_fixa)),net=roundMoneyV181(Math.max(0,gross-fee));
    const pid=uidV181("PAG");
    const txBrand=titleV181(rp.bandeira||rate.bandeira||"",true),txCond=feeConditionV181(rp.condicao||rate.condicao||"QUALQUER");
    payments.push({id:pid,forma_id:form.id,forma_nome:form.nome,taxa_id:rate.id||"",bandeira:txBrand,condicao:txCond,valor_bruto:gross,taxa_percentual:numV181(rate.percentual),taxa_fixa:numV181(rate.taxa_fixa),valor_taxa:fee,valor_liquido:net,data_recebimento:date,account});
    cash.push({id:uidV181("MOV"),data:date,competencia:date,tipo:"RECEITA",origem:"ATENDIMENTO",origem_id:id,descricao:"Receita - "+clientNameV181(client),valor:gross,forma_pagamento:form.nome,conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:true,movimento_financeiro_id:""});
    if(fee>0)cash.push({id:uidV181("MOV"),data:date,competencia:date,tipo:"TAXA_FINANCEIRA",origem:"PAGAMENTO",origem_id:pid,descricao:"Taxa "+form.nome,valor:-fee,forma_pagamento:form.nome,conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:true,movimento_financeiro_id:""});

    const cashForm=normalizeTextV181(form.nome).includes("dinheiro"),received=rp.valor_recebido==null?gross:roundMoneyV181(rp.valor_recebido),change=roundMoneyV181(Math.max(0,received-gross));
    if(cashForm&&received+0.001<gross)throw new Error("O valor recebido em dinheiro não pode ser menor que o valor do pagamento.");
    if(cashForm&&change>0){
      const outAcc=await rowByIdV181("contas_financeiras",rp.troco_conta_id);
      if(!outAcc||!isActiveV181(outAcc.ativo))throw new Error("Selecione a conta que devolveu o troco.");
      const tid=uidV181("TRC"),inId=uidV181("MOV"),outId=uidV181("MOV");
      cash.push({id:inId,data:date,competencia:date,tipo:"TROCO_ENTRADA",origem:"TROCO_CLIENTE",origem_id:tid,descricao:"Valor excedente recebido para troco",valor:change,forma_pagamento:form.nome,conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:false,movimento_financeiro_id:""});
      cash.push({id:outId,data:date,competencia:date,tipo:"TROCO_SAIDA",origem:"TROCO_CLIENTE",origem_id:tid,descricao:"Troco devolvido à cliente",valor:-change,forma_pagamento:"",conta_financeira_id:outAcc.id,conta_financeira_nome:outAcc.nome,impacto_resultado:false,movimento_financeiro_id:""});
      trocos.push({id:tid,pagamento_id:pid,data:date,valor_servico:gross,valor_recebido:received,valor_troco:change,conta_dinheiro_id:account.id,conta_dinheiro_nome:account.nome,conta_saida_id:outAcc.id,conta_saida_nome:outAcc.nome,mov_entrada_id:inId,mov_saida_id:outId});
    }
  }

  const actualNet=roundMoneyV181(payments.reduce((s,x)=>s+x.valor_liquido,0));
  const allFee=roundMoneyV181(payments.reduce((s,x)=>s+x.valor_taxa,0));
  const items:any[]=[],cons:any[]=[];
  for(const it of prepared){
    const courtesyWithCommission=nature==="CORTESIA_COM_COMISSAO";
    let feeAll=0,feeCommission=0,base=it.ref;
    if(courtesyWithCommission){
      const w=commissionTarget>0?it.commissionTarget/commissionTarget:0;feeAll=roundMoneyV181(allFee*w);base=roundMoneyV181(Math.max(0,it.ref));
    }else{
      const denom=serviceTotal;
      const w=denom>0?it.charged/denom:0;
      feeAll=roundMoneyV181(payments.reduce((s,p)=>s+p.valor_taxa*w,0));
      for(const pay of payments)if(await feeRuleAttendanceV181(it.prof.id,pay.forma_id,date))feeCommission+=pay.valor_taxa*w;
      feeCommission=roundMoneyV181(feeCommission);base=roundMoneyV181(Math.max(0,it.ref-feeCommission));
    }
    const commission=roundMoneyV181(base*it.pct),itemId=uidV181("ATI");
    const netShare=courtesyWithCommission&&commissionTarget>0?roundMoneyV181(actualNet*(it.commissionTarget/commissionTarget)):roundMoneyV181(it.charged-feeAll);
    const studio=courtesyWithCommission?roundMoneyV181(netShare-commission):roundMoneyV181(it.charged-commission);
    const studioPost=roundMoneyV181(netShare-commission);
    const item={id:itemId,profissional_id:it.prof.id,profissional_nome:it.prof.nome,servico_id:it.svc.id,servico_nome:it.svc.nome,valor_tabela:it.table,valor_bruto:it.charged,desconto_valor:roundMoneyV181(Math.max(0,it.table-it.charged)),campanha_id:it.campaign?.id||"",campanha_nome:it.campaign?.nome||"",valor_referencia_comissao:it.ref,taxa_considerada_comissao:feeCommission,valor_liquido:netShare,base_comissao:base,percentual_comissao:it.pct,valor_comissao:commission,studio_liquido:studio,studio_liquido_pos_taxas:studioPost,regra_taxa:courtesyWithCommission?"CORTESIA_COMISSAO_INTEGRAL":(feeCommission>0?"BASE_LIQUIDA_APOS_TAXA":"BASE_REFERENCIA"),comissao_status:(nature==="CORTESIA_SEM_COMISSAO"||it.packageCourtesy)?"SEM_COMISSAO":"PENDENTE",cortesia_tipo:it.packageCourtesy?"CORTESIA_PACOTE":(nature==="NORMAL"?"":nature),cortesia_motivo:it.packageCourtesy?"Cortesia de pacote":courtesyReason,pacote_id:it.pkg?.id||"",pacote_item_id:it.pkgItem?.id||"",origem:it.pkgItem?"PACOTE":(nature==="NORMAL"?"SISTEMA":"CORTESIA")};
    items.push(item);
    if(it.pkgItem)cons.push({id:uidV181("PCO"),pacote_id:it.pkg.id,pacote_item_id:it.pkgItem.id,atendimento_item_id:itemId,cliente_id:client.id,cliente_nome:clientNameV181(client),servico_id:it.svc.id,servico_nome:it.svc.nome,profissional_id:it.prof.id,profissional_nome:it.prof.nome,data:date,valor_referencia:it.ref,cortesia_pacote:!!it.packageCourtesy});
  }

  return {id,total:nature==="CORTESIA_COM_COMISSAO"&&payer==="CLIENTE"?roundMoneyV181(payments.reduce((s,x)=>s+x.valor_bruto,0)):serviceTotal,attendance:{data:date,cliente_id:client.id,cliente_nome:clientNameV181(client),observacoes:String(p.observacoes||""),natureza:nature,cortesia_comissao_pagador:payer,cortesia_motivo:courtesyReason},payments:payments.map(({account,...x})=>x),items,package_consumptions:cons,cash,trocos};
}

async function attendanceRpcV181(action:string,payload:any,user:any){
  const {data,error}=await db.rpc("studio_attendance_tx_v181",{p_action:action,p_payload:payload,p_user:{id:user.id,nome:user.nome}});
  if(error)throw new Error(error.message);return data;
}
async function getAttendanceV181(user:any,id:string){
  const a=await rowByIdV181("atendimentos",id);if(!a||String(a.status).toUpperCase()==="CANCELADO")throw new Error("Atendimento não encontrado.");
  if(!canViewAttendanceV181(user,a.data))throw new Error("Este atendimento está fora do período permitido para o seu usuário.");
  const [allItems,allPays,allTrocos]=await Promise.all([allRowsV181("atendimento_itens"),allRowsV181("pagamentos_receita"),allRowsV181("troco_cliente")]);
  const items=allItems.filter(x=>String(x.atendimento_id)===String(id)&&attendanceRowActiveV181(x));
  const pays=allPays.filter(x=>String(x.atendimento_id)===String(id)&&attendanceRowActiveV181(x));
  const trocos=allTrocos.filter(x=>String(x.atendimento_id)===String(id)&&String(x.status||"ATIVO").toUpperCase()==="ATIVO");
  const allowed=canEditAttendanceV181(user,a.data),editable=items.filter(attendanceCommissionEditableV181),locked=items.filter(x=>!attendanceCommissionEditableV181(x));
  return {id:a.id,data:dateOnlyV181(a.data),cliente_id:a.cliente_id,cliente:a.cliente_nome,observacoes:a.observacoes||"",natureza:a.natureza||"NORMAL",cortesia_comissao_pagador:a.cortesia_comissao_pagador||(String(a.natureza)==="CORTESIA_COM_COMISSAO"?"STUDIO":""),cortesia_motivo:a.cortesia_motivo||"",
    items:items.map(i=>({id:i.id,profissional_id:i.profissional_id,profissional_nome:i.profissional_nome,servico_id:i.servico_id,servico_nome:i.servico_nome,valor:roundMoneyV181(i.valor_bruto),valor_tabela:roundMoneyV181(i.valor_tabela||i.valor_bruto),valor_referencia_comissao:roundMoneyV181(i.valor_referencia_comissao||i.valor_bruto),campanha_id:i.campanha_id||"",campanha_nome:i.campanha_nome||"",pacote_id:i.pacote_id||"",pacote_item_id:i.pacote_item_id||"",comissao_status:i.comissao_status||"PENDENTE",editable:allowed&&attendanceCommissionEditableV181(i)})),
    payments:pays.map(p=>{const t=trocos.find(x=>String(x.pagamento_id)===String(p.id));return {forma_id:p.forma_id,forma_nome:p.forma_nome,valor:roundMoneyV181(p.valor_bruto),taxa_id:p.taxa_id||"",bandeira:p.bandeira||"",condicao:p.condicao||"QUALQUER",valor_recebido:t?roundMoneyV181(t.valor_recebido):roundMoneyV181(p.valor_bruto),troco_conta_id:t?.conta_saida_id||""};}),
    can_edit:allowed&&editable.length>0,can_cancel:canCancelAttendanceV181(user,a.data)&&locked.length===0,partial_edit:allowed&&editable.length>0&&locked.length>0,comissao_bloqueada:locked.length>0};
}
async function partialAttendancePayloadV181(user:any,p:any,a:any){
  const current=await getAttendanceV181(user,a.id);
  const [allItems,profs,services,pays]=await Promise.all([allRowsV181("atendimento_itens"),allRowsV181("profissionais"),allRowsV181("servicos"),allRowsV181("pagamentos_receita")]);
  const active=allItems.filter(x=>String(x.atendimento_id)===String(a.id)&&attendanceRowActiveV181(x));
  const activePays=pays.filter(x=>String(x.atendimento_id)===String(a.id)&&attendanceRowActiveV181(x));
  const denom=roundMoneyV181(active.reduce((s,x)=>s+numV181(x.valor_bruto),0)),nature=String(a.natureza||"NORMAL").toUpperCase();
  const incoming=new Map((p.items||[]).map((x:any)=>[String(x.item_id||""),x]));
  const out:any[]=[];
  for(const old of active.filter(attendanceCommissionEditableV181)){
    const x:any=incoming.get(String(old.id));if(!x)continue;
    const prof=profs.find(r=>String(r.id)===String(x.profissional_id));if(!prof||!isActiveV181(prof.ativo)||professionalDeletedV181(prof))throw new Error("Selecione uma profissional ativa.");
    const svc=services.find(r=>String(r.id)===String(x.servico_id));if(!svc||!isActiveV181(svc.ativo))throw new Error("Selecione um serviço ativo.");
    if(old.pacote_item_id&&String(svc.id)!==String(old.servico_id))throw new Error("O serviço de um consumo de pacote não pode ser alterado na edição parcial.");
    let campaign:any=null;if(numV181(old.valor_bruto)<numV181(svc.preco_padrao)-0.009&&!old.pacote_item_id&&nature==="NORMAL")campaign=await campaignAttendanceV181(String(x.campanha_id||""),dateOnlyV181(a.data));
    const pct=String(old.comissao_status||"PENDENTE").toUpperCase()==="SEM_COMISSAO"?0:numV181(prof.comissao_padrao);
    let feeCommission=0;
    if(nature!=="CORTESIA_COM_COMISSAO"&&denom>0){
      const w=numV181(old.valor_bruto)/denom;
      for(const pay of activePays)if(await feeRuleAttendanceV181(prof.id,pay.forma_id,dateOnlyV181(a.data)))feeCommission+=numV181(pay.valor_taxa)*w;
    }
    feeCommission=roundMoneyV181(feeCommission);
    const base=nature==="CORTESIA_COM_COMISSAO"?roundMoneyV181(old.valor_referencia_comissao):roundMoneyV181(Math.max(0,numV181(old.valor_referencia_comissao)-feeCommission));
    const commission=roundMoneyV181(base*pct);
    out.push({id:old.id,profissional_id:prof.id,profissional_nome:prof.nome,servico_id:svc.id,servico_nome:svc.nome,campanha_id:campaign?.id||"",campanha_nome:campaign?.nome||"",taxa_considerada_comissao:feeCommission,base_comissao:base,percentual_comissao:pct,valor_comissao:commission,studio_liquido:nature==="CORTESIA_COM_COMISSAO"?roundMoneyV181(numV181(old.valor_liquido)-commission):roundMoneyV181(numV181(old.valor_bruto)-commission),studio_liquido_pos_taxas:roundMoneyV181(numV181(old.valor_liquido)-commission),regra_taxa:nature==="CORTESIA_COM_COMISSAO"?"CORTESIA_COMISSAO_INTEGRAL":(feeCommission>0?"BASE_LIQUIDA_APOS_TAXA":"BASE_REFERENCIA")});
  }
  if(!out.length)throw new Error("Este atendimento não possui itens pendentes editáveis.");
  return {id:a.id,observacoes:String(p.observacoes??a.observacoes??""),partial_items:out,total:current.payments.reduce((s:any,x:any)=>s+numV181(x.valor),0)};
}
async function listAttendancesV181(user:any,filters:any){
  filters=filters||{};const [atts,items,pays]=await Promise.all([allRowsV181("atendimentos"),allRowsV181("atendimento_itens"),allRowsV181("pagamentos_receita")]);
  const days=String(user?.perfil||"").toUpperCase()==="ADMIN"?99999:Math.max(1,Math.floor(numV181(user?.visualizar_atendimentos_dias)||5));
  const min=attendanceSubtractDaysV181(todayV181(),days-1),start=dateOnlyV181(filters.start)||min,end=dateOnlyV181(filters.end)||todayV181();
  const lo=start<min&&String(user?.perfil||"").toUpperCase()!=="ADMIN"?min:start,ci=String(filters.cliente_id||""),pi=String(filters.profissional_id||""),si=String(filters.servico_id||"");
  const grouped:any={},pg:any={};items.filter(attendanceRowActiveV181).forEach(x=>(grouped[String(x.atendimento_id)]??=[]).push(x));pays.filter(attendanceRowActiveV181).forEach(x=>(pg[String(x.atendimento_id)]??=[]).push(x));
  return atts.filter(a=>{const d=dateOnlyV181(a.data),its=grouped[String(a.id)]||[];return String(a.status).toUpperCase()!=="CANCELADO"&&d>=lo&&d<=end&&canViewAttendanceV181(user,d)&&(!ci||String(a.cliente_id)===ci)&&(!pi||its.some((x:any)=>String(x.profissional_id)===pi))&&(!si||its.some((x:any)=>String(x.servico_id)===si));}).sort((a,b)=>String(dateOnlyV181(b.data)).localeCompare(String(dateOnlyV181(a.data)))||String(b.criado_em||"").localeCompare(String(a.criado_em||""))).slice(0,500).map(a=>{const its=grouped[String(a.id)]||[],ps=pg[String(a.id)]||[],locked=its.some((x:any)=>!attendanceCommissionEditableV181(x)),courtesy=String(a.natureza)==="CORTESIA_COM_COMISSAO"&&String(a.cortesia_comissao_pagador)==="CLIENTE";return {id:a.id,data:dateOnlyV181(a.data),cliente:a.cliente_nome,total:courtesy?roundMoneyV181(ps.reduce((s:any,x:any)=>s+numV181(x.valor_bruto),0)):roundMoneyV181(its.reduce((s:any,x:any)=>s+numV181(x.valor_bruto),0)),servicos:its.map((x:any)=>x.servico_nome).join(", "),profissionais:[...new Set(its.map((x:any)=>x.profissional_nome).filter(Boolean))].join(", "),pagamentos:[...new Set(ps.map((x:any)=>x.forma_nome).filter(Boolean))].join(", "),observacoes:a.observacoes||"",status:a.status||"CONCLUIDO",origem:a.origem||"SISTEMA",natureza:a.natureza||"NORMAL",cortesia_comissao_pagador:a.cortesia_comissao_pagador||"",cortesia_motivo:a.cortesia_motivo||"",usa_pacote:its.some((x:any)=>!!x.pacote_item_id),can_edit:canEditAttendanceV181(user,a.data)&&its.some(attendanceCommissionEditableV181),can_cancel:canCancelAttendanceV181(user,a.data)&&!locked,comissao_bloqueada:locked};});
}
async function clientActivePackagesV181(clientId:string){
  const [pkgs,items]=await Promise.all([allRowsV181("pacotes"),allRowsV181("pacote_itens")]);const today=todayV181();
  return pkgs.filter(p=>String(p.cliente_id)===String(clientId)&&String(p.status||"ATIVO").toUpperCase()!=="CANCELADO"&&(!dateOnlyV181(p.validade)||dateOnlyV181(p.validade)>=today)).map(p=>{const its=items.filter(i=>String(i.pacote_id)===String(p.id)&&attendanceRowActiveV181(i)).map(i=>({id:i.id,servico_id:i.servico_id,servico:i.servico_nome,quantidade:numV181(i.quantidade),consumida:numV181(i.quantidade_consumida),saldo:Math.max(0,numV181(i.quantidade)-numV181(i.quantidade_consumida)),valor_unitario_original:numV181(i.valor_unitario_original),valor_unitario_negociado:numV181(i.valor_unitario_negociado),cortesia_sem_comissao:!!i.cortesia_sem_comissao})).filter(i=>i.saldo>0);return {id:p.id,cliente_id:p.cliente_id,cliente:p.cliente_nome,data_compra:dateOnlyV181(p.data_compra),validade:dateOnlyV181(p.validade),status:its.length?"ATIVO":"CONSUMIDO",items:its};}).filter(p=>p.items.length>0);
}
// ============================= fim Atendimentos v1.8.1 =============================



// ============================= v1.8.1 — Dashboard / leitura integral =============================
function dashboardActiveV181(r:any){return ["","ATIVO","REALIZADO","CONCLUIDO"].includes(String(r?.status||"ATIVO").toUpperCase());}
function dashboardImpactV181(r:any){const v=r?.impacto_resultado;if(v===false||String(v).toUpperCase()==="FALSE"||String(v)==="0")return false;return true;}
function dashboardTypeLabelV181(v:any){
  const s=String(v||"OUTROS").toUpperCase();
  const m:any={DESPESA:"Despesas",COMISSAO:"Comissões",TAXA_FINANCEIRA:"Taxas financeiras",CONSIGNACAO_REPASSE:"Repasse consignado",REPASSE_TERCEIRO:"Repasse terceiros",ATIVO:"Ativos",ATIVO_COMPRA:"Ativos",ESTOQUE:"Estoque",COMPRA_ESTOQUE:"Estoque"};
  return m[s]||String(v||"Outros").replace(/_/g," ").toLocaleLowerCase("pt-BR").replace(/^\p{L}/u,c=>c.toLocaleUpperCase("pt-BR"));
}
async function futurePackageCommissionCalcV181(){
  const [pkgs,items]=await Promise.all([allRowsV181("pacotes"),allRowsV181("pacote_itens")]),pm:any={};
  pkgs.forEach(p=>pm[String(p.id)]=p);let base=0,remainingServices=0;const pack=new Set<string>(),today=todayV181();
  items.forEach(i=>{const p=pm[String(i.pacote_id)];if(!p||String(p.status||"").toUpperCase()==="CANCELADO"||String(i.status||"ATIVO").toUpperCase()!=="ATIVO")return;if(dateOnlyV181(p.validade)&&dateOnlyV181(p.validade)<today)return;const rem=Math.max(0,numV181(i.quantidade)-numV181(i.quantidade_consumida));if(!rem)return;remainingServices+=rem;pack.add(String(p.id));if(boolV181(i.cortesia_sem_comissao,false))return;base+=rem*numV181(i.valor_unitario_negociado);});
  base=round2V181(base);const rate=.45,estimated=round2V181(base*rate);return {base,rate,estimated,remainingServices:round2V181(remainingServices),packages:pack.size};
}
async function consignmentPayableCalcV181(){
  const rows=(await allRowsV181("consignacao_repasses")).filter(r=>String(r.status||"PENDENTE").toUpperCase()==="PENDENTE");
  const total=round2V181(rows.reduce((s,r)=>s+numV181(r.valor_total_repasse),0)),sup=new Set(rows.map(r=>String(r.fornecedor||"")).filter(Boolean));
  return {total,items:rows.length,suppliers:sup.size};
}
async function cardPayableCalcV181(){
  // "Cartões a pagar" é o passivo de despesas lançadas no cartão.
  // A v1.8.1 registra essas obrigações em MOV_CAIXA sem impacto no resultado,
  // com tipo OBRIGACAO_CARTAO_DESPESA e status OBRIGACAO.
  const rows=(await allRowsV181("mov_caixa")).filter(r=>
    String(r.tipo||"").toUpperCase()==="OBRIGACAO_CARTAO_DESPESA" &&
    String(r.status||"").toUpperCase()==="OBRIGACAO"
  );
  return {
    total:round2V181(Math.abs(rows.reduce((s,r)=>s+numV181(r.valor),0))),
    items:rows.length,
    rows:rows.map(r=>({
      id:r.id,
      data:dateOnlyV181(r.data),
      competencia:dateOnlyV181(r.competencia),
      descricao:r.descricao||"",
      valor:round2V181(Math.abs(numV181(r.valor))),
      origem_id:r.origem_id||""
    }))
  };
}
async function dashboardSnapshotV181(user:any,filters:any){
  filters=filters||{};const end=dateOnlyV181(filters.end||todayV181()),start=dateOnlyV181(filters.start||end.slice(0,8)+"01"),admin=String(user?.perfil||"").toUpperCase()==="ADMIN";
  const [atts,ai,sales,vi,pkgs,pSvc,pSale,pPkg,mov,closings,parcels,products,paidMap]=await Promise.all([
    allRowsV181("atendimentos"),allRowsV181("atendimento_itens"),allRowsV181("vendas"),allRowsV181("venda_itens"),allRowsV181("pacotes"),
    allRowsV181("pagamentos_receita"),allRowsV181("pagamentos_venda"),allRowsV181("pacote_pagamentos"),allRowsV181("mov_caixa"),
    allRowsV181("comissoes_fechamentos"),allRowsV181("despesa_parcelas"),allRowsV181("produtos"),paidCommissionItemMapHF5()
  ]);
  const aRows=atts.filter(a=>{const d=dateOnlyV181(a.data);return d>=start&&d<=end&&String(a.status||"").toUpperCase()!=="CANCELADO";}),am:any={};aRows.forEach(a=>am[String(a.id)]=a);
  const serviceItems=ai.filter(i=>am[String(i.atendimento_id)]&&dashboardActiveV181(i));
  const sRows=sales.filter(s=>{const d=dateOnlyV181(s.data);return d>=start&&d<=end&&String(s.status||"").toUpperCase()!=="CANCELADO";}),sm:any={};sRows.forEach(s=>sm[String(s.id)]=s);
  const saleItems=vi.filter(i=>sm[String(i.venda_id)]&&dashboardActiveV181(i));
  const packageRows=pkgs.filter(p=>{const d=dateOnlyV181(p.data_compra);return d>=start&&d<=end&&String(p.status||"").toUpperCase()!=="CANCELADO";});
  const grossServices=round2V181(serviceItems.reduce((s,i)=>s+numV181(i.valor_bruto),0)),grossSales=round2V181(saleItems.reduce((s,i)=>s+numV181(i.valor_bruto),0)),grossPackages=round2V181(packageRows.reduce((s,p)=>s+numV181(p.valor_negociado),0)),gross=round2V181(grossServices+grossSales+grossPackages);
  const generated=round2V181(serviceItems.reduce((s,i)=>s+recognizedCommissionHF5(i,paidMap,'SERVICO'),0)+saleItems.reduce((s,i)=>s+recognizedCommissionHF5(i,paidMap,'VENDA'),0));
  const courtesyClientCommission=round2V181(serviceItems.filter(i=>{
    const a=am[String(i.atendimento_id)]||{};
    return String(a.natureza||"").toUpperCase()==="CORTESIA_COM_COMISSAO" &&
           String(a.cortesia_comissao_pagador||"").toUpperCase()==="CLIENTE";
  }).reduce((s,i)=>s+numV181(i.valor_comissao),0));
  const pays=[...pSvc.filter(p=>dateOnlyV181(p.data_recebimento)>=start&&dateOnlyV181(p.data_recebimento)<=end&&dashboardActiveV181(p)),...pSale.filter(p=>dateOnlyV181(p.data_recebimento)>=start&&dateOnlyV181(p.data_recebimento)<=end&&dashboardActiveV181(p)),...pPkg.filter(p=>dateOnlyV181(p.data_recebimento)>=start&&dateOnlyV181(p.data_recebimento)<=end&&dashboardActiveV181(p))];
  const cashAll=mov.filter(m=>dateOnlyV181(m.data)>=start&&dateOnlyV181(m.data)<=end&&String(m.status||"").toUpperCase()==="REALIZADO"),cash=cashAll.filter(dashboardImpactV181);
  const fees=round2V181(Math.abs(cashAll.filter(m=>String(m.tipo||"").toUpperCase()==="TAXA_FINANCEIRA").reduce((s,m)=>s+numV181(m.valor),0)));
  const paidCommission=round2V181(closings.filter(c=>String(c.status||"").toUpperCase()==="PAGO"&&dateOnlyV181(c.data_pagamento)>=start&&dateOnlyV181(c.data_pagamento)<=end).reduce((s,c)=>s+numV181(c.total_comissao),0));
  const pendingCommission=round2V181(serviceItems.filter(i=>String(i.comissao_status||"PENDENTE").toUpperCase()==="PENDENTE").reduce((s,i)=>s+numV181(i.valor_comissao),0)+saleItems.filter(i=>String(i.comissao_status||"").toUpperCase()==="PENDENTE").reduce((s,i)=>s+numV181(i.valor_comissao),0));
  const cashIn=round2V181(cash.filter(m=>numV181(m.valor)>0).reduce((s,m)=>s+numV181(m.valor),0)),
        cashOut=round2V181(cash.filter(m=>numV181(m.valor)<0).reduce((s,m)=>s+numV181(m.valor),0)),
        expensesPaid=round2V181(parcels.filter(p=>
          String(p.status||"").toUpperCase()==="PAGO" &&
          dateOnlyV181(p.data_pagamento)>=start &&
          dateOnlyV181(p.data_pagamento)<=end
        ).reduce((s,p)=>s+numV181(p.valor),0));
  const legacyBalance=round2V181(mov.filter(m=>dateOnlyV181(m.data)<=end&&String(m.status||"").toUpperCase()==="REALIZADO"&&dashboardImpactV181(m)).reduce((s,m)=>s+numV181(m.valor),0));
  const forecast=round2V181(parcels.filter(p=>String(p.status||"").toUpperCase()==="PREVISTO"&&dateOnlyV181(p.vencimento)>=start&&dateOnlyV181(p.vencimento)<=end).reduce((s,p)=>s+numV181(p.valor),0));
  const day:any={};cash.forEach(m=>{const d=dateOnlyV181(m.data);if(!d)return;const x=day[d]||(day[d]={date:d,receitas:0,despesas:0});if(numV181(m.valor)>=0)x.receitas+=numV181(m.valor);else x.despesas+=Math.abs(numV181(m.valor));});const timeline=Object.keys(day).sort().map(k=>({date:k,receitas:round2V181(day[k].receitas),despesas:round2V181(day[k].despesas)}));
  const form:any={};pays.forEach(p=>{const k=String(p.forma_nome||"Não informado");form[k]=(form[k]||0)+numV181(p.valor_bruto);});const paymentMix=Object.keys(form).map(k=>({label:k,value:round2V181(form[k])})).sort((a,b)=>b.value-a.value);
  const prof:any={};serviceItems.forEach(i=>{if(!i.profissional_nome)return;const v=i.pacote_item_id?numV181(i.valor_referencia_comissao):numV181(i.valor_bruto);prof[i.profissional_nome]=(prof[i.profissional_nome]||0)+v;});saleItems.forEach(i=>{if(i.profissional_nome)prof[i.profissional_nome]=(prof[i.profissional_nome]||0)+numV181(i.valor_bruto);});const byProfessional=Object.keys(prof).map(k=>({label:k,value:round2V181(prof[k])})).sort((a,b)=>b.value-a.value);
  const stockAlerts=products.filter(p=>isActiveV181(p.ativo)&&!productDeletedV181(p)&&numV181(p.estoque_minimo)>0&&numV181(p.estoque_atual)<=numV181(p.estoque_minimo)).map(p=>({id:p.id,produto:p.produto,estoque:numV181(p.estoque_atual),minimo:numV181(p.estoque_minimo),zerado:numV181(p.estoque_atual)<=0}));
  const grouped:any={};serviceItems.forEach(i=>(grouped[String(i.atendimento_id)]??=[]).push(i));const latestAppointments=aRows.slice().sort((a,b)=>String(dateOnlyV181(b.data)).localeCompare(String(dateOnlyV181(a.data)))||String(b.criado_em||"").localeCompare(String(a.criado_em||""))).slice(0,10).map(a=>{const its=grouped[String(a.id)]||[];return {id:a.id,data:dateOnlyV181(a.data),cliente:a.cliente_nome||"",profissionais:[...new Set(its.map((i:any)=>i.profissional_nome).filter(Boolean))].join(", "),servicos:its.map((i:any)=>i.servico_nome).join(", "),total:round2V181(its.reduce((s:any,i:any)=>s+numV181(i.valor_bruto),0))};});
  const exp:any={};cash.filter(m=>numV181(m.valor)<0).forEach(m=>{const k=dashboardTypeLabelV181(m.tipo);exp[k]=(exp[k]||0)+Math.abs(numV181(m.valor));});const expenseCompositionV159=Object.keys(exp).map(k=>({label:k,value:round2V181(exp[k])})).sort((a,b)=>b.value-a.value),expenseVsRevenueV180=expenseCompositionV159.map(x=>({...x,percentage:gross>0?round2V181(x.value/gross*100):0}));
  if(!admin)return {start,end,admin:false,appointments:aRows.length,sales:sRows.length,packages:packageRows.length,stockAlerts,timeline:[],paymentMix:[],byProfessional:[],latestAppointments};
  const [position,future,consign,card]=await Promise.all([financialPositionV181(),futurePackageCommissionCalcV181(),consignmentPayableCalcV181(),cardPayableCalcV181()]);
  const availableBalanceV180=round2V181(position.total-position.commissionPayable-card.total-position.thirdPartyPayable);
  return {start,end,admin:true,appointments:aRows.length,sales:sRows.length,packages:packageRows.length,gross,grossServices,grossSales,grossPackages,fees,netRevenue:round2V181(gross-fees),commissionGenerated:generated,commissionPaid:paidCommission,commissionPending:pendingCommission,studioAfterCommission:round2V181(gross-generated+courtesyClientCommission),expensesPaid,cashIn,cashOut:Math.abs(cashOut),cashResult:round2V181(cashIn+cashOut),balance:legacyBalance,forecast,timeline,paymentMix,byProfessional,stockAlerts,latestAppointments,expenseCompositionV159,expenseVsRevenueV180,balanceCurrentV180:position.total,commissionPayableV180:position.commissionPayable,availableBalanceV180,thirdPartyPayableV180:position.thirdPartyPayable,cardPayableB4:card.total,cardPayableDetailB4:card,futurePackageCommissionV180:future.estimated,futurePackageCommissionDetailV180:future,consignmentPayableV180:consign.total,consignmentPayableDetailV180:consign};
}
async function dashboardMonthlyDataV181(year:any){
  const y=String(year||new Date().getFullYear()).replace(/\D/g,"").slice(0,4),mov=await allRowsV181("mov_caixa"),years=new Set<string>([String(new Date().getFullYear())]);mov.forEach(m=>{const d=dateOnlyV181(m.data);if(/^\d{4}/.test(d))years.add(d.slice(0,4));});
  const names=["Jan","Fev","Mar","Abr","Mai","Jun","Jul","Ago","Set","Out","Nov","Dez"],rows=names.map((month,i)=>({month,month_num:i+1,receitas:0,despesas:0}));
  mov.filter(m=>String(m.status||"").toUpperCase()==="REALIZADO"&&dashboardImpactV181(m)&&dateOnlyV181(m.data).slice(0,4)===y).forEach(m=>{const mo=Number(dateOnlyV181(m.data).slice(5,7))-1;if(mo<0||mo>11)return;const v=numV181(m.valor);if(v>=0)rows[mo].receitas+=v;else rows[mo].despesas+=Math.abs(v);});rows.forEach(r=>{r.receitas=round2V181(r.receitas);r.despesas=round2V181(r.despesas);});return {year:y,years:[...years].sort().reverse(),rows};
}

// HF5: paid commission closing item takes precedence over mutable source item.
// This helper is read-only and never changes paid balances, bookings or ledgers.
async function paidCommissionItemMapHF5(){
  const [closings,items]=await Promise.all([allRowsV181("comissoes_fechamentos"),allRowsV181("comissoes_itens")]);
  const paid=new Set(closings.filter(c=>String(c.status||"").toUpperCase()==="PAGO").map(c=>String(c.id)));
  const map:any={};
  items.filter(i=>paid.has(String(i.fechamento_id))).forEach(i=>{
    const origin=String(i.origem_tipo||"SERVICO").toUpperCase();
    const kind=origin==="VENDA_PRODUTO"?"VENDA":"SERVICO";
    const key=String(i.origem_item_id||i.atendimento_item_id||"");
    if(key)map[kind+":"+key]=numV181(i.valor_comissao);
  });
  return map;
}
function recognizedCommissionHF5(i:any,map:any,kind:string){
  const key=kind+":"+String(i.id||"");
  return Object.prototype.hasOwnProperty.call(map,key)?map[key]:numV181(i.valor_comissao);
}

async function commissionGeneratedDetailDataV181(filters:any){
  filters=filters||{};const end=dateOnlyV181(filters.end||todayV181()),start=dateOnlyV181(filters.start||end.slice(0,8)+"01"),[atts,ai,sales,vi,paidMap]=await Promise.all([allRowsV181("atendimentos"),allRowsV181("atendimento_itens"),allRowsV181("vendas"),allRowsV181("venda_itens"),paidCommissionItemMapHF5()]),am:any={},sm:any={},m:any={};
  atts.filter(a=>dateOnlyV181(a.data)>=start&&dateOnlyV181(a.data)<=end&&String(a.status||"").toUpperCase()!=="CANCELADO").forEach(a=>am[String(a.id)]=a);sales.filter(s=>dateOnlyV181(s.data)>=start&&dateOnlyV181(s.data)<=end&&String(s.status||"").toUpperCase()!=="CANCELADO").forEach(s=>sm[String(s.id)]=s);
  ai.filter(i=>am[String(i.atendimento_id)]&&dashboardActiveV181(i)).forEach(i=>{const k=String(i.profissional_id||i.profissional_nome||"");if(!k)return;const r=m[k]||(m[k]={professional_id:i.profissional_id||"",professional_name:i.profissional_nome||"Sem profissional",commission:0});r.commission+=recognizedCommissionHF5(i,paidMap,'SERVICO');});
  vi.filter(i=>sm[String(i.venda_id)]&&dashboardActiveV181(i)).forEach(i=>{const k=String(i.profissional_id||i.profissional_nome||"");if(!k)return;const r=m[k]||(m[k]={professional_id:i.profissional_id||"",professional_name:i.profissional_nome||"Sem profissional",commission:0});r.commission+=recognizedCommissionHF5(i,paidMap,'VENDA');});
  const rows=Object.values(m).map((r:any)=>({...r,commission:round2V181(r.commission)})).filter((r:any)=>r.commission!==0).sort((a:any,b:any)=>b.commission-a.commission||String(a.professional_name).localeCompare(String(b.professional_name),"pt-BR"));
  return {start,end,total:round2V181(rows.reduce((s:any,r:any)=>s+r.commission,0)),rows};
}
async function cashFlowDataV181(filters:any){
  filters=filters||{};const start=dateOnlyV181(filters.start||"1900-01-01"),end=dateOnlyV181(filters.end||"2999-12-31"),[mov,parcels,expenses]=await Promise.all([allRowsV181("mov_caixa"),allRowsV181("despesa_parcelas"),allRowsV181("despesas")]),dm:any={};expenses.forEach(d=>dm[String(d.id)]=d);
  const rows=mov.filter(m=>dateOnlyV181(m.data)>=start&&dateOnlyV181(m.data)<=end&&String(m.status||"").toUpperCase()!=="ESTORNADO").map(m=>({data:dateOnlyV181(m.data),competencia:dateOnlyV181(m.competencia),tipo:m.tipo,descricao:m.descricao,valor:round2V181(m.valor),status:m.status,forma:m.forma_pagamento||"",impacto_resultado:dashboardImpactV181(m),conta_financeira_id:m.conta_financeira_id||"",conta_financeira_nome:m.conta_financeira_nome||""}));
  if(filters.includeForecast!==false)parcels.filter(p=>String(p.status||"").toUpperCase()==="PREVISTO"&&dateOnlyV181(p.vencimento)>=start&&dateOnlyV181(p.vencimento)<=end).forEach(p=>{const d=dm[String(p.despesa_id)];rows.push({data:dateOnlyV181(p.vencimento),competencia:d?dateOnlyV181(d.data_compra):dateOnlyV181(p.vencimento),tipo:"DESPESA_PREVISTA",descricao:d?.descricao||"Despesa prevista",valor:-round2V181(p.valor),status:"PREVISTO",forma:d?.forma_pagamento||"",impacto_resultado:true,conta_financeira_id:"",conta_financeira_nome:""});});
  rows.sort((a,b)=>String(a.data).localeCompare(String(b.data))||String(a.descricao).localeCompare(String(b.descricao),"pt-BR"));

  // Compatibilidade integral com o frontend v1.8.0-HF1/v1.8.1:
  // os cards consolidados leem summaryHF1, enquanto a tabela continua usando rows.
  // Movimentos internos (transferências e troco) permanecem na tabela, mas são
  // excluídos dos cards por impacto_resultado=false.
  const realized=rows.filter(r=>String(r.status||"").toUpperCase()==="REALIZADO");
  const counted=realized.filter(r=>r.impacto_resultado!==false);
  const internal=realized.filter(r=>r.impacto_resultado===false);
  const forecastRows=rows.filter(r=>String(r.status||"").toUpperCase()==="PREVISTO");

  const entries=round2V181(counted.reduce((s,r)=>s+(numV181(r.valor)>0?numV181(r.valor):0),0));
  const exits=round2V181(counted.reduce((s,r)=>s+(numV181(r.valor)<0?Math.abs(numV181(r.valor)):0),0));
  const forecast=round2V181(forecastRows.reduce((s,r)=>s+Math.abs(numV181(r.valor)),0));

  const cashBreakdownLabel=(tipo:any)=>{
    const t=String(tipo||"OUTROS").toUpperCase();
    const labels:any={
      RECEITA:"Serviços / atendimentos",
      RECEITA_MANUAL:"Receitas manuais",
      RECEITA_PRODUTO:"Venda de produtos",
      APORTE:"Aportes",
      VENDA_ATIVO:"Venda de ativos",
      TERCEIRO_ENTRADA:"Entradas de terceiros",
      DESPESA:"Despesas",
      COMISSAO:"Comissões",
      TAXA_FINANCEIRA:"Taxas financeiras",
      ADIANTAMENTO_PROFISSIONAL:"Vales / adiantamentos",
      REPASSE_TERCEIRO:"Repasses a terceiros",
      CONSIGNACAO_REPASSE:"Repasse consignado"
    };
    return labels[t]||String(tipo||"Outros").replace(/_/g," ").toLocaleLowerCase("pt-BR").replace(/^\p{L}/u,c=>c.toLocaleUpperCase("pt-BR"));
  };
  const breakdown=(positive:boolean)=>{
    const map:any={};
    counted.forEach(r=>{
      const v=numV181(r.valor);
      if(positive?v<=0:v>=0)return;
      const label=cashBreakdownLabel(r.tipo);
      map[label]=round2V181((map[label]||0)+Math.abs(v));
    });
    return Object.entries(map)
      .map(([label,value])=>({label,value:round2V181(value)}))
      .sort((a:any,b:any)=>b.value-a.value||String(a.label).localeCompare(String(b.label),"pt-BR"));
  };

  const summaryHF1={
    entries,
    exits,
    result:round2V181(entries-exits),
    forecast,
    entryBreakdown:breakdown(true),
    exitBreakdown:breakdown(false),
    excludedInternal:{
      entries:round2V181(internal.reduce((s,r)=>s+(numV181(r.valor)>0?numV181(r.valor):0),0)),
      exits:round2V181(internal.reduce((s,r)=>s+(numV181(r.valor)<0?Math.abs(numV181(r.valor)):0),0))
    }
  };

  const [position,future,consign,card]=await Promise.all([financialPositionV181(),futurePackageCommissionCalcV181(),consignmentPayableCalcV181(),cardPayableCalcV181()]);
  return {rows,summaryHF1,position:{...position,cardPayable:card.total},futurePackageCommission:future,consignmentPayable:consign};
}
async function rankingRowsDataV181(filters:any){
  filters=filters||{};
  const end=dateOnlyV181(filters.end||todayV181()),
        start=dateOnlyV181(filters.start||end.slice(0,8)+"01"),
        [clients,atts,ai,pkgs,sales,vi]=await Promise.all([
          allRowsV181("clientes"),
          allRowsV181("atendimentos"),
          allRowsV181("atendimento_itens"),
          allRowsV181("pacotes"),
          allRowsV181("vendas"),
          allRowsV181("venda_itens")
        ]),
        cm:any={},am:any={},sm:any={},b:any={};

  clients.forEach(c=>cm[String(c.id)]=c);

  const add=(cid:any,type:string,date:string,description:string,value:any)=>{
    cid=String(cid||"");
    const v=round2V181(value);
    // Ranking legado considera somente interações pagas.
    if(!cid||!cm[cid]||v<=0)return;
    const c=cm[cid],
          r=b[cid]||(b[cid]={
            client_key:cid,
            client_id:cid,
            client_name:clientNameV181(c),
            phone:c.telefone||"",
            revenue:0,
            interactions:0,
            rows:[]
          });
    r.revenue+=v;
    r.interactions++;
    r.rows.push({date,type,description,value:v});
  };

  // 1 interação por ATENDIMENTO pago, independentemente da quantidade de serviços.
  atts
    .filter(a=>{
      const d=dateOnlyV181(a.data);
      return d>=start&&d<=end&&String(a.status||"").toUpperCase()!=="CANCELADO";
    })
    .forEach(a=>am[String(a.id)]=a);

  const attendanceGroups:any={};
  ai
    .filter(i=>am[String(i.atendimento_id)]&&dashboardActiveV181(i)&&!i.pacote_item_id)
    .forEach(i=>{
      const aid=String(i.atendimento_id);
      const g=attendanceGroups[aid]||(attendanceGroups[aid]={gross:0,names:[]});
      g.gross+=numV181(i.valor_bruto);
      const n=String(i.servico_nome||"").trim();
      if(n&&!g.names.includes(n))g.names.push(n);
    });

  Object.keys(attendanceGroups).forEach(aid=>{
    const a=am[aid],g=attendanceGroups[aid];
    if(!a||round2V181(g.gross)<=0)return;
    add(
      a.cliente_id,
      "SERVICO",
      dateOnlyV181(a.data),
      g.names.length?g.names.join(" + "):"Atendimento",
      g.gross
    );
  });

  // 1 interação por PACOTE pago. Vale-presente pertence à pessoa que comprou.
  pkgs
    .filter(p=>{
      const d=dateOnlyV181(p.data_compra);
      return d>=start&&d<=end&&String(p.status||"").toUpperCase()!=="CANCELADO";
    })
    .forEach(p=>{
      const gross=round2V181(p.valor_negociado);
      if(gross<=0)return;
      const isGift=String(p.tipo_pacote||"").toUpperCase()==="VALE_PRESENTE";
      const cid=isGift&&p.comprador_id?p.comprador_id:p.cliente_id;
      add(
        cid,
        "PACOTE",
        dateOnlyV181(p.data_compra),
        isGift?"Vale-presente":"Pacote",
        gross
      );
    });

  // 1 interação por VENDA paga, independentemente da quantidade de produtos.
  sales
    .filter(s=>{
      const d=dateOnlyV181(s.data);
      return d>=start&&d<=end&&String(s.status||"").toUpperCase()!=="CANCELADO";
    })
    .forEach(s=>sm[String(s.id)]=s);

  const saleGroups:any={};
  vi
    .filter(i=>sm[String(i.venda_id)]&&dashboardActiveV181(i))
    .forEach(i=>{
      const sid=String(i.venda_id);
      const g=saleGroups[sid]||(saleGroups[sid]={gross:0,names:[]});
      g.gross+=numV181(i.valor_bruto);
      const n=String(i.produto_nome||"").trim();
      if(n&&!g.names.includes(n))g.names.push(n);
    });

  Object.keys(saleGroups).forEach(sid=>{
    const s=sm[sid],g=saleGroups[sid];
    if(!s||round2V181(g.gross)<=0)return;
    add(
      s.cliente_id,
      "PRODUTO",
      dateOnlyV181(s.data),
      g.names.length?g.names.join(" + "):"Venda de produtos",
      g.gross
    );
  });

  const rows=Object.values(b)
    .map((r:any)=>({
      ...r,
      revenue:round2V181(r.revenue),
      ticket_average:r.interactions?round2V181(r.revenue/r.interactions):0
    }))
    .sort((a:any,b:any)=>b.revenue-a.revenue||String(a.client_name).localeCompare(String(b.client_name),"pt-BR"))
    .map((r:any,i)=>({...r,position:i+1}));

  const totalRevenue=round2V181(rows.reduce((s:any,r:any)=>s+r.revenue,0));
  const totalInteractions=rows.reduce((s:any,r:any)=>s+r.interactions,0);

  return {
    start,
    end,
    summary:{
      clients:rows.length,
      revenue:totalRevenue,
      ticket_average:totalInteractions?round2V181(totalRevenue/totalInteractions):0
    },
    rows
  };
}

// ============================= fim Dashboard v1.8.1 =============================


// ============================= v1.8.1 — Receitas completas =============================
function revenueDeletedV181(r:any){
  if(!r)return true;
  if(r.excluido===true)return true;
  return ["TRUE","1","SIM","YES","EXCLUIDO"].includes(String(r.excluido||"").toUpperCase()) ||
         String(r.status||"").toUpperCase()==="EXCLUIDA";
}
function revenueNatureV181(r:any){ return String(r?.natureza||"OPERACIONAL").toUpperCase()==="APORTE"?"APORTE":"OPERACIONAL"; }
function revenueCanEditV181(user:any,date:any){
  return String(user?.perfil||"").toUpperCase()==="ADMIN" || dateOnlyV181(date)===todayV181();
}
function addMonthsRevenueV181(date:any,months:any){
  const s=dateOnlyV181(date); if(!/^\d{4}-\d{2}-\d{2}$/.test(s))return s;
  const parts=s.split("-").map(Number),y=parts[0],m=parts[1],d=parts[2],target=m-1+Number(months||0);
  const ty=y+Math.floor(target/12),tm=((target%12)+12)%12;
  const last=new Date(Date.UTC(ty,tm+1,0)).getUTCDate(),day=Math.min(d,last);
  return String(ty)+"-"+String(tm+1).padStart(2,"0")+"-"+String(day).padStart(2,"0");
}
function revenueStatusFromParcelsV181(revenue:any,parcels:any[]){
  if(revenueDeletedV181(revenue))return "EXCLUIDA";
  if(String(revenue?.status||"").toUpperCase()==="CANCELADA")return "CANCELADA";
  const active=(parcels||[]).filter(p=>!["CANCELADO","EXCLUIDO"].includes(String(p.status||"").toUpperCase()));
  if(!active.length)return String(revenue?.status||"PREVISTA").toUpperCase();
  const received=active.filter(p=>String(p.status||"").toUpperCase()==="RECEBIDA").length;
  if(received===active.length)return "RECEBIDA";
  if(received>0)return "PARCIAL";
  return "PREVISTA";
}
async function revenueDomainsV181(){
  const vals=await Promise.all([allRowsV181("categorias_receitas"),allRowsV181("subcategorias_receitas")]),cats=vals[0],subs=vals[1];
  return {
    categories:cats.filter(x=>isActiveV181(x.ativo)).sort((a,b)=>String(a.nome||"").localeCompare(String(b.nome||""),"pt-BR")).map(x=>({id:x.id,nome:x.nome})),
    subcategories:subs.filter(x=>isActiveV181(x.ativo)).sort((a,b)=>String(a.nome||"").localeCompare(String(b.nome||""),"pt-BR")).map(x=>({id:x.id,categoria_id:x.categoria_receita_id,nome:x.nome}))
  };
}
async function revenueCategoryV181(payload:any,fallback:string){
  const cats=(await allRowsV181("categorias_receitas")).filter(x=>isActiveV181(x.ativo));
  let cat=payload?.categoria_id?cats.find(x=>String(x.id)===String(payload.categoria_id)):null;
  if(!cat&&payload?.categoria)cat=cats.find(x=>normalizeTextV181(x.nome)===normalizeTextV181(payload.categoria));
  if(!cat&&fallback)cat=cats.find(x=>normalizeTextV181(x.nome)===normalizeTextV181(fallback));
  if(!cat)throw new Error("Selecione uma categoria de receita válida.");
  return cat;
}
async function revenueSubcategoryV181(categoryId:string,payload:any){
  if(!payload?.subcategoria_id&&!payload?.subcategoria)return null;
  const subs=(await allRowsV181("subcategorias_receitas")).filter(x=>isActiveV181(x.ativo)&&String(x.categoria_receita_id)===String(categoryId));
  const sub=payload?.subcategoria_id?subs.find(x=>String(x.id)===String(payload.subcategoria_id)):subs.find(x=>normalizeTextV181(x.nome)===normalizeTextV181(payload.subcategoria));
  if(!sub)throw new Error("Subcategoria de receita inválida para a categoria selecionada.");
  return sub;
}
async function revenuePartyMetaV181(payload:any){
  const formId=String(payload?.forma_id||"");let forma:any=null,client:any=null;
  if(formId){forma=await rowByIdV181("formas_pagamento",formId);if(!forma||!isActiveV181(forma.ativo))throw new Error("Forma de pagamento inválida ou inativa.");}
  const clientId=String(payload?.cliente_id||"");
  if(clientId){client=await rowByIdV181("clientes",clientId);if(!client||!isActiveV181(client.ativo))throw new Error("Cliente inválida ou inativa.");}
  return {forma,client,clientName:client?clientNameV181(client):titleV181(payload?.cliente||"")};
}
async function revenuePaymentMetaV181(formaId:string,date:string,gross:any){
  const amount=round2V181(gross);
  if(!formaId)return {forma_id:"",forma_nome:"Não informado",taxa_percentual:0,taxa_fixa:0,fee:0,net:amount,account:null};
  const forma=await rowByIdV181("formas_pagamento",formaId);
  if(!forma||!isActiveV181(forma.ativo))throw new Error("Forma de pagamento inválida ou inativa.");
  const rate=await resolveRateAttendanceV181(forma.id,date,{});
  const fee=round2V181(amount*numV181(rate?.percentual)+numV181(rate?.taxa_fixa));
  const account=await paymentAccountAttendanceV181(forma.id);
  return {forma_id:forma.id,forma_nome:forma.nome,taxa_percentual:numV181(rate?.percentual),taxa_fixa:numV181(rate?.taxa_fixa),fee,net:round2V181(amount-fee),account};
}
function revenueAuditRowV181(user:any,action:string,entity:string,entityId:string,details:any){
  return {id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user?.id||"SYSTEM",usuario_nome:user?.nome||"Sistema",acao:action,entidade:entity,entidade_id:entityId,detalhes:JSON.stringify(details||{})};
}
function revenueCashRowV181(revenue:any,parcel:any,date:string,meta:any,typeOverride?:string){
  const id=uidV181("MOV"),nature=revenueNatureV181(revenue),isFee=typeOverride==="TAXA_FINANCEIRA";
  return {
    id,data:dateOnlyV181(date),competencia:dateOnlyV181(revenue.data_competencia),
    tipo:typeOverride||(nature==="APORTE"?"APORTE":"RECEITA_MANUAL"),
    origem:isFee?"RECEITA_PARCELA_TAXA":"RECEITA_PARCELA",origem_id:parcel.id,
    descricao:isFee?"Taxa "+String(revenue.forma_pagamento||"")+" - "+String(revenue.descricao||""):String(revenue.descricao||""),
    valor:isFee?-round2V181(meta.fee):round2V181(parcel.valor_bruto),status:"REALIZADO",forma_pagamento:revenue.forma_pagamento||"",
    criado_em:nowIsoV181(),conta_financeira_id:meta.account?.id||null,conta_financeira_nome:meta.account?.nome||null,
    impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""
  };
}
async function revenueTxV181(action:string,payload:any,user:any){
  const x=await db.rpc("studio_revenue_tx_v181",{p_action:action,p_payload:payload,p_user:{id:user.id,nome:user.nome}});
  if(x.error)throw new Error(x.error.message);return x.data;
}
async function automaticRevenueRowsV181(){
  const vals=await Promise.all([allRowsV181("atendimentos"),allRowsV181("pagamentos_receita"),allRowsV181("vendas"),allRowsV181("pagamentos_venda"),allRowsV181("pacotes"),allRowsV181("pacote_pagamentos")]);
  const atts=vals[0],pAtt=vals[1],sales=vals[2],pSales=vals[3],pkgs=vals[4],pPkgs=vals[5],am:any={},sm:any={},pm:any={},out:any[]=[];
  atts.forEach(x=>am[String(x.id)]=x);sales.forEach(x=>sm[String(x.id)]=x);pkgs.forEach(x=>pm[String(x.id)]=x);
  pAtt.filter(p=>dashboardActiveV181(p)).forEach(p=>{const a=am[String(p.atendimento_id)]||{};out.push({
    row_id:"ATENDIMENTO:"+p.id,source_type:"AUTOMATICA",record_id:p.atendimento_id,parcel_id:"",data:dateOnlyV181(p.data_recebimento),competencia:dateOnlyV181(a.data||p.data_recebimento),
    descricao:"Atendimento"+(a.cliente_nome?" - "+a.cliente_nome:""),cliente:a.cliente_nome||"",categoria:"Serviços",subcategoria:"",natureza:"OPERACIONAL",origem:"ATENDIMENTO",forma:p.forma_nome||"",
    valor_bruto:round2V181(p.valor_bruto),taxa:round2V181(p.valor_taxa),valor_liquido:round2V181(p.valor_liquido),status:"RECEBIDA",can_edit:false,can_cancel:false,can_delete:false,can_receive:false
  });});
  pSales.filter(p=>dashboardActiveV181(p)).forEach(p=>{const s=sm[String(p.venda_id)]||{};out.push({
    row_id:"VENDA:"+p.id,source_type:"AUTOMATICA",record_id:p.venda_id,parcel_id:"",data:dateOnlyV181(p.data_recebimento),competencia:dateOnlyV181(s.data||p.data_recebimento),
    descricao:"Venda de produtos"+(s.cliente_nome?" - "+s.cliente_nome:""),cliente:s.cliente_nome||"",categoria:"Venda de Produtos",subcategoria:"",natureza:"OPERACIONAL",origem:"VENDA",forma:p.forma_nome||"",
    valor_bruto:round2V181(p.valor_bruto),taxa:round2V181(p.valor_taxa),valor_liquido:round2V181(p.valor_liquido),status:"RECEBIDA",can_edit:false,can_cancel:false,can_delete:false,can_receive:false
  });});
  pPkgs.filter(p=>dashboardActiveV181(p)).forEach(p=>{const pkg=pm[String(p.pacote_id)]||{};out.push({
    row_id:"PACOTE:"+p.id,source_type:"AUTOMATICA",record_id:p.pacote_id,parcel_id:"",data:dateOnlyV181(p.data_recebimento),competencia:dateOnlyV181(pkg.data_compra||p.data_recebimento),
    descricao:"Venda de pacote"+(pkg.cliente_nome?" - "+pkg.cliente_nome:""),cliente:pkg.cliente_nome||"",categoria:"Pacotes",subcategoria:"",natureza:"OPERACIONAL",origem:"PACOTE",forma:p.forma_nome||"",
    valor_bruto:round2V181(p.valor_bruto),taxa:round2V181(p.valor_taxa),valor_liquido:round2V181(p.valor_liquido),status:"RECEBIDA",can_edit:false,can_cancel:false,can_delete:false,can_receive:false
  });});
  return out;
}
async function manualRevenueRowsV181(user:any,includeCancelled=false){
  const vals=await Promise.all([allRowsV181("receitas"),allRowsV181("receita_parcelas")]),revenues=vals[0],parcels=vals[1],rm:any={},out:any[]=[];
  revenues.filter(r=>!revenueDeletedV181(r)&&String(r.status||"").toUpperCase()!=="CANCELADA").forEach(r=>rm[String(r.id)]=r);
  parcels.filter(p=>!["CANCELADO","EXCLUIDO"].includes(String(p.status||"").toUpperCase())&&rm[String(p.receita_id)]).forEach(p=>{
    const r=rm[String(p.receita_id)],raw=String(p.status||"PREVISTA").toUpperCase(),due=dateOnlyV181(p.vencimento),display=raw!=="RECEBIDA"&&due&&due<todayV181()?"VENCIDA":raw;
    out.push({row_id:"MANUAL:"+p.id,source_type:"MANUAL",record_id:r.id,parcel_id:p.id,data:raw==="RECEBIDA"?dateOnlyV181(p.data_recebimento||due):due,competencia:dateOnlyV181(r.data_competencia),
      descricao:r.descricao||"",cliente:r.cliente_nome||"",categoria:r.categoria||"Outras Receitas",subcategoria:r.subcategoria||"",natureza:revenueNatureV181(r),origem:"MANUAL",forma:r.forma_pagamento||"",
      valor_bruto:round2V181(p.valor_bruto),taxa:round2V181(p.valor_taxa),valor_liquido:round2V181(raw==="RECEBIDA"?p.valor_liquido:p.valor_bruto),status:display,
      parcela:String(p.parcela_num||1)+"/"+String(p.total_parcelas||1),can_edit:revenueCanEditV181(user,r.data_competencia),can_cancel:String(user?.perfil||"").toUpperCase()==="ADMIN",
      can_delete:String(user?.perfil||"").toUpperCase()==="ADMIN",can_receive:String(user?.perfil||"").toUpperCase()==="ADMIN"&&raw!=="RECEBIDA"});
  });
  if(includeCancelled)revenues.filter(r=>!revenueDeletedV181(r)&&String(r.status||"").toUpperCase()==="CANCELADA").forEach(r=>out.push({
    row_id:"MANUAL-CANCELADA:"+r.id,source_type:"MANUAL",record_id:r.id,parcel_id:"",data:dateOnlyV181(r.data_competencia),competencia:dateOnlyV181(r.data_competencia),
    descricao:r.descricao||"",cliente:r.cliente_nome||"",categoria:r.categoria||"Outras Receitas",subcategoria:r.subcategoria||"",natureza:revenueNatureV181(r),origem:"MANUAL",forma:r.forma_pagamento||"",
    valor_bruto:round2V181(r.valor_total),taxa:0,valor_liquido:0,status:"CANCELADA",parcela:"—",can_edit:false,can_cancel:false,can_delete:String(user?.perfil||"").toUpperCase()==="ADMIN",can_receive:false
  }));
  return out;
}
async function listRevenuesV181(user:any,filters:any){
  filters=filters||{};const requestedStatus=String(filters.status||"").toUpperCase();
  let data=(await automaticRevenueRowsV181()).concat(await manualRevenueRowsV181(user,requestedStatus==="CANCELADA"));
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")data=data.filter(x=>x.data===todayV181());
  const st=requestedStatus,origin=String(filters.origem||"").toUpperCase(),cat=normalizeTextV181(filters.categoria||""),client=normalizeTextV181(filters.cliente||""),form=normalizeTextV181(filters.forma_pagamento||"");
  data=data.filter(x=>(!filters.start||x.data>=dateOnlyV181(filters.start))&&(!filters.end||x.data<=dateOnlyV181(filters.end))&&(!st||String(x.status||"").toUpperCase()===st)&&
    (!origin||String(x.origem||"").toUpperCase()===origin)&&(!cat||normalizeTextV181(x.categoria)===cat)&&(!client||normalizeTextV181(x.cliente).includes(client))&&(!form||normalizeTextV181(x.forma)===form));
  data.sort((a,b)=>String(b.data||"").localeCompare(String(a.data||""))||String(a.descricao||"").localeCompare(String(b.descricao||""),"pt-BR"));
  const operational=data.filter(x=>String(x.natureza||"OPERACIONAL").toUpperCase()!=="APORTE");
  const futuras=round2V181(operational.filter(x=>["PREVISTA","PARCIAL"].includes(x.status)&&x.data>=todayV181()).reduce((s,x)=>s+numV181(x.valor_bruto),0));
  const recebidas=round2V181(operational.filter(x=>x.status==="RECEBIDA").reduce((s,x)=>s+numV181(x.valor_bruto),0));
  const aReceber=round2V181(operational.filter(x=>["PREVISTA","PARCIAL","VENCIDA"].includes(x.status)).reduce((s,x)=>s+numV181(x.valor_bruto),0));
  const vencidas=round2V181(operational.filter(x=>x.status==="VENCIDA").reduce((s,x)=>s+numV181(x.valor_bruto),0));
  return {rows:data,summary:{previstas:futuras,recebidas,a_receber:aReceber,vencidas}};
}
async function createRevenueParcelsPreparedV181(revenue:any,initialStatus:string){
  const qtd=Math.max(1,Math.floor(numV181(revenue.qtd_parcelas)||1)),received=String(initialStatus||"PREVISTA").toUpperCase()==="RECEBIDA",parcels:any[]=[],cash:any[]=[];let allocated=0;
  for(let i=0;i<qtd;i++){
    const gross=i===qtd-1?round2V181(numV181(revenue.valor_total)-allocated):round2V181(numV181(revenue.valor_total)/qtd);allocated=round2V181(allocated+gross);
    const due=addMonthsRevenueV181(revenue.data_primeiro_recebimento,i),meta=received?await revenuePaymentMetaV181(revenue.forma_id,due,gross):{taxa_percentual:0,taxa_fixa:0,fee:0,net:gross,account:null};
    const parcel:any={id:uidV181("RCP"),receita_id:revenue.id,parcela_num:i+1,total_parcelas:qtd,vencimento:due,valor_bruto:gross,taxa_percentual:meta.taxa_percentual||0,
      taxa_fixa:meta.taxa_fixa||0,valor_taxa:meta.fee||0,valor_liquido:meta.net===undefined?gross:meta.net,status:received?"RECEBIDA":"PREVISTA",
      data_recebimento:received?due:null,criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),mov_caixa_id:null};
    if(received){const recMov=revenueCashRowV181(revenue,parcel,due,meta);parcel.mov_caixa_id=recMov.id;cash.push(recMov);if(meta.fee>0)cash.push(revenueCashRowV181(revenue,parcel,due,meta,"TAXA_FINANCEIRA"));}
    parcels.push(parcel);
  }
  return {parcels,cash};
}
async function saveRevenueV181(user:any,payload:any){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Somente o administrador pode cadastrar receitas.");
  payload=payload||{};const description=titleV181(payload.descricao||""),total=round2V181(payload.valor),competence=dateOnlyV181(payload.data_competencia||todayV181()),firstDue=dateOnlyV181(payload.vencimento||competence);
  if(!description||total<=0||!competence||!firstDue)throw new Error("Informe descrição, competência, data prevista e valor da receita.");
  let nature=String(payload.natureza||"OPERACIONAL").toUpperCase()==="APORTE"?"APORTE":"OPERACIONAL";
  const cat=await revenueCategoryV181(payload,nature==="APORTE"?"Aportes / Capital":"Outras Receitas");if(normalizeTextV181(cat.nome).includes("aporte"))nature="APORTE";
  const sub=await revenueSubcategoryV181(cat.id,payload),party=await revenuePartyMetaV181(payload),qtd=Math.max(1,Math.floor(numV181(payload.parcelas)||1));
  const recurring=!!payload.recorrente,recurCount=recurring?Math.max(1,Math.floor(numV181(payload.recorrencia_meses)||12)):1,initial=String(payload.status||"PREVISTA").toUpperCase()==="RECEBIDA"?"RECEBIDA":"PREVISTA";
  const revenues:any[]=[],parcels:any[]=[],cash:any[]=[],audit:any[]=[];
  for(let occ=0;occ<recurCount;occ++){
    const id=uidV181("REC"),revenue:any={id,descricao:description+(recurring?" ["+String(occ+1)+"/"+String(recurCount)+"]":""),cliente_id:party.client?.id||"",cliente_nome:party.clientName,
      data_competencia:addMonthsRevenueV181(competence,occ),categoria_receita_id:cat.id,subcategoria_receita_id:sub?.id||"",categoria:cat.nome,subcategoria:sub?.nome||"",natureza,
      valor_total:total,forma_id:party.forma?.id||"",forma_pagamento:party.forma?.nome||"Não informado",qtd_parcelas:qtd,data_primeiro_recebimento:addMonthsRevenueV181(firstDue,occ),
      status:initial,recorrente:recurring,recorrencia_meses:recurCount,observacoes:String(payload.observacoes||""),origem:"MANUAL",usuario_id:user.id,usuario_nome:user.nome,
      criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),editado_por:"",excluido:false};
    const prep=await createRevenueParcelsPreparedV181(revenue,initial);revenues.push(revenue);parcels.push(...prep.parcels);cash.push(...prep.cash);
    audit.push(revenueAuditRowV181(user,"CRIAR","RECEITA",id,{descricao:revenue.descricao,valor:total,status:initial,natureza,parcelas:qtd}));
  }
  return await revenueTxV181("CREATE",{revenues,parcels,cash,audit},user);
}
async function getRevenueV181(user:any,id:string){
  const r=await rowByIdV181("receitas",id);if(!r||revenueDeletedV181(r))throw new Error("Receita não encontrada.");
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN"&&dateOnlyV181(r.data_competencia)!==todayV181())throw new Error("Usuários podem editar somente receitas manuais do dia.");
  const parcels=(await allRowsV181("receita_parcelas")).filter(p=>String(p.receita_id)===String(id)&&!["CANCELADO","EXCLUIDO"].includes(String(p.status||"").toUpperCase()));
  const hasReceived=parcels.some(p=>String(p.status||"").toUpperCase()==="RECEBIDA");
  return {id:r.id,descricao:r.descricao,cliente_id:r.cliente_id||"",cliente:r.cliente_nome||"",data_competencia:dateOnlyV181(r.data_competencia),categoria_id:r.categoria_receita_id||"",
    subcategoria_id:r.subcategoria_receita_id||"",categoria:r.categoria||"",subcategoria:r.subcategoria||"",natureza:revenueNatureV181(r),valor_total:round2V181(r.valor_total),
    forma_id:r.forma_id||"",forma_pagamento:r.forma_pagamento||"",qtd_parcelas:Number(r.qtd_parcelas||1),vencimento:dateOnlyV181(r.data_primeiro_recebimento),observacoes:r.observacoes||"",
    status:revenueStatusFromParcelsV181(r,parcels),has_received:hasReceived,can_edit:revenueCanEditV181(user,r.data_competencia),
    parcels:parcels.map(p=>({id:p.id,status:p.status,valor_bruto:round2V181(p.valor_bruto),valor_taxa:round2V181(p.valor_taxa),valor_liquido:round2V181(p.valor_liquido),vencimento:dateOnlyV181(p.vencimento),data_recebimento:dateOnlyV181(p.data_recebimento)}))};
}
async function updateRevenueV181(user:any,payload:any){
  payload=payload||{};const r=await rowByIdV181("receitas",payload.id);if(!r||revenueDeletedV181(r))throw new Error("Receita não encontrada.");
  if(String(r.origem||"MANUAL").toUpperCase()!=="MANUAL")throw new Error("Receitas automáticas devem ser alteradas na operação de origem.");
  if(!revenueCanEditV181(user,r.data_competencia))throw new Error("Usuários podem editar somente receitas do dia.");
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN"&&dateOnlyV181(payload.data_competencia||r.data_competencia)!==todayV181())throw new Error("Usuários não podem mover a receita para outra data.");
  const parcels=(await allRowsV181("receita_parcelas")).filter(p=>String(p.receita_id)===String(r.id)&&!["CANCELADO","EXCLUIDO"].includes(String(p.status||"").toUpperCase())),hasReceived=parcels.some(p=>String(p.status||"").toUpperCase()==="RECEBIDA");
  const cat=await revenueCategoryV181(payload,r.categoria||"Outras Receitas"),sub=await revenueSubcategoryV181(cat.id,payload),party=await revenuePartyMetaV181(payload);
  const nature=(String(payload.natureza||r.natureza||"OPERACIONAL").toUpperCase()==="APORTE"||normalizeTextV181(cat.nome).includes("aporte"))?"APORTE":"OPERACIONAL";
  const total=round2V181(payload.valor_total),qtd=Math.max(1,Math.floor(numV181(payload.qtd_parcelas)||1)),due=dateOnlyV181(payload.vencimento||r.data_primeiro_recebimento);
  if(total<=0)throw new Error("O valor da receita deve ser maior que zero.");
  const financialChanged=round2V181(r.valor_total)!==total||Number(r.qtd_parcelas||1)!==qtd||dateOnlyV181(r.data_primeiro_recebimento)!==due||String(r.forma_id||"")!==String(party.forma?.id||"")||revenueNatureV181(r)!==nature;
  if(hasReceived&&financialChanged)throw new Error("Para preservar o histórico, valor, parcelas, vencimentos, forma e natureza não podem ser alterados.");
  const updated:any={...r,descricao:titleV181(payload.descricao||r.descricao),cliente_id:party.client?.id||"",cliente_nome:party.clientName,data_competencia:dateOnlyV181(payload.data_competencia||r.data_competencia),
    categoria_receita_id:cat.id,subcategoria_receita_id:sub?.id||"",categoria:cat.nome,subcategoria:sub?.nome||"",observacoes:String(payload.observacoes||""),atualizado_em:nowIsoV181(),editado_por:user.nome};
  let cancelIds:any[]=[],newParcels:any[]=[],cash:any[]=[];
  if(!hasReceived){Object.assign(updated,{valor_total:total,qtd_parcelas:qtd,data_primeiro_recebimento:due,forma_id:party.forma?.id||"",forma_pagamento:party.forma?.nome||"Não informado",natureza});
    if(financialChanged){cancelIds=parcels.map(p=>p.id);const prep=await createRevenueParcelsPreparedV181(updated,"PREVISTA");newParcels=prep.parcels;cash=prep.cash;updated.status="PREVISTA";}}
  const audit=[revenueAuditRowV181(user,"ALTERAR","RECEITA",r.id,{antes:r,depois:updated})];
  return await revenueTxV181("UPDATE",{revenue:updated,cancel_parcel_ids:cancelIds,new_parcels:newParcels,cash,audit},user);
}
async function receiveRevenueV181(user:any,parcelId:string,receiptDate:any){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Somente o administrador pode registrar recebimentos.");
  const p=await rowByIdV181("receita_parcelas",parcelId);if(!p||["CANCELADO","EXCLUIDO"].includes(String(p.status||"").toUpperCase()))throw new Error("Parcela de receita não encontrada.");
  if(String(p.status||"").toUpperCase()==="RECEBIDA")throw new Error("Parcela já recebida.");
  const r=await rowByIdV181("receitas",p.receita_id);if(!r||revenueDeletedV181(r)||String(r.status||"").toUpperCase()==="CANCELADA")throw new Error("Receita não encontrada ou cancelada.");
  const date=dateOnlyV181(receiptDate||todayV181()),meta=await revenuePaymentMetaV181(r.forma_id,date,p.valor_bruto),recMov=revenueCashRowV181(r,p,date,meta);
  const parcel:any={...p,status:"RECEBIDA",data_recebimento:date,taxa_percentual:meta.taxa_percentual,taxa_fixa:meta.taxa_fixa,valor_taxa:meta.fee,valor_liquido:meta.net,atualizado_em:nowIsoV181(),mov_caixa_id:recMov.id};
  const all=(await allRowsV181("receita_parcelas")).filter(x=>String(x.receita_id)===String(r.id)&&!["CANCELADO","EXCLUIDO"].includes(String(x.status||"").toUpperCase())).map(x=>String(x.id)===String(parcel.id)?parcel:x);
  const revenue:any={...r,status:revenueStatusFromParcelsV181({...r,status:"PREVISTA"},all),atualizado_em:nowIsoV181(),editado_por:user.nome};
  const cash:any[]=[recMov];if(meta.fee>0)cash.push(revenueCashRowV181(r,p,date,meta,"TAXA_FINANCEIRA"));
  const audit=[revenueAuditRowV181(user,"RECEBER","RECEITA_PARCELA",p.id,{receita_id:r.id,valor:p.valor_bruto,data:date,taxa:meta.fee})];
  return await revenueTxV181("RECEIVE",{parcel,revenue,cash,audit},user);
}
async function cancelRevenueV181(user:any,id:string){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Somente o administrador pode cancelar receitas.");
  const r=await rowByIdV181("receitas",id);if(!r||revenueDeletedV181(r))throw new Error("Receita não encontrada.");
  if(String(r.origem||"MANUAL").toUpperCase()!=="MANUAL")throw new Error("Receitas automáticas devem ser canceladas na operação de origem.");
  if(String(r.status||"").toUpperCase()==="CANCELADA")throw new Error("Receita já cancelada.");
  const revenue={...r,status:"CANCELADA",excluido:false,atualizado_em:nowIsoV181(),editado_por:user.nome};
  return await revenueTxV181("CANCEL",{revenue,audit:[revenueAuditRowV181(user,"CANCELAR","RECEITA",r.id,{descricao:r.descricao,valor:r.valor_total})]},user);
}
async function deleteRevenueV181(user:any,id:string){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Somente o administrador pode excluir receitas.");
  const r=await rowByIdV181("receitas",id);if(!r||revenueDeletedV181(r))throw new Error("Receita não encontrada.");
  if(String(r.origem||"MANUAL").toUpperCase()!=="MANUAL")throw new Error("Receitas automáticas não podem ser excluídas por esta tela.");
  const revenue={...r,status:"EXCLUIDA",excluido:true,atualizado_em:nowIsoV181(),editado_por:user.nome};
  return await revenueTxV181("DELETE",{revenue,audit:[revenueAuditRowV181(user,"EXCLUIR","RECEITA",r.id,{descricao:r.descricao,valor:r.valor_total,metodo:"EXCLUSAO_LOGICA"})]},user);
}
// ============================= fim Receitas completas =============================


// ============================= v1.8.1 — Pacotes leitura =============================
function packageItemActiveV181(i:any){return String(i?.status||"ATIVO").toUpperCase()==="ATIVO";}
function packagePaymentActiveV181(p:any){return String(p?.status||"ATIVO").toUpperCase()==="ATIVO";}
function packageGiftV181(p:any){return String(p?.tipo_pacote||"USO_PROPRIO").toUpperCase()==="VALE_PRESENTE";}
function packageStatusCalcV181(p:any,items:any[]){
  if(String(p?.status||"").toUpperCase()==="CANCELADO")return "CANCELADO";
  if(packageGiftV181(p)&&!String(p?.beneficiario_id||""))return "AGUARDANDO_BENEFICIARIO";
  const rem=(items||[]).filter(packageItemActiveV181).reduce((s:any,i:any)=>s+Math.max(0,numV181(i.quantidade)-numV181(i.quantidade_consumida)),0);
  return rem>0.0001?"ATIVO":"CONSUMIDO";
}
async function packageRefundCalcV181(id:string){
  const p=await rowByIdV181("pacotes",id);if(!p)throw new Error("Pacote não encontrado.");
  const [items,refunds]=await Promise.all([allRowsV181("pacote_itens"),allRowsV181("pacote_reembolsos")]);
  const its=items.filter(i=>String(i.pacote_id)===String(id)&&packageItemActiveV181(i));
  let consumed=0,unused=0,courtesy=0;
  its.forEach(i=>{const qty=numV181(i.quantidade),used=Math.min(qty,Math.max(0,numV181(i.quantidade_consumida))),rem=Math.max(0,qty-used),isCourtesy=boolV181(i.cortesia_sem_comissao,false),unit=isCourtesy?0:numV181(i.valor_unitario_negociado);consumed+=used*unit;unused+=rem*unit;if(isCourtesy)courtesy+=rem;});
  const refund=refunds.filter(r=>String(r.pacote_id)===String(id)).sort((a,b)=>String(b.criado_em||"").localeCompare(String(a.criado_em||"")))[0]||null;
  return {pacote_id:id,valor_pacote:round2V181(p.valor_negociado),valor_consumido:round2V181(consumed),valor_nao_utilizado:round2V181(unused),reembolso_calculado:round2V181(unused),cortesias_nao_utilizadas:round2V181(courtesy),
    refund:refund?{id:refund.id,status:refund.status,valor_calculado:round2V181(refund.valor_calculado),valor_pago:round2V181(refund.valor_pago),forma_id:refund.forma_id||"",forma_pagamento:refund.forma_pagamento||"",data_pagamento:dateOnlyV181(refund.data_pagamento),observacoes:refund.observacoes||""}:null};
}
async function packageListV181(user:any,filters:any){
  filters=filters||{};
  const [pkgs,items,refunds,clients,consumptions]=await Promise.all([allRowsV181("pacotes"),allRowsV181("pacote_itens"),allRowsV181("pacote_reembolsos"),allRowsV181("clientes"),allRowsV181("pacote_consumos")]);
  const admin=String(user?.perfil||"").toUpperCase()==="ADMIN",cm:any={};clients.forEach(c=>cm[String(c.id)]=c);
  const out:any[]=[];
  for(const p of pkgs){
    const its=items.filter(i=>String(i.pacote_id)===String(p.id)&&packageItemActiveV181(i)),status=packageStatusCalcV181(p,its),hasConsumption=its.some(i=>numV181(i.quantidade_consumida)>0.0001)||consumptions.some(c=>String(c.pacote_id)===String(p.id)&&String(c.status||"ATIVO").toUpperCase()==="ATIVO");
    const latestRefund=refunds.filter(r=>String(r.pacote_id)===String(p.id)).sort((a,b)=>String(b.criado_em||"").localeCompare(String(a.criado_em||"")))[0]||null;
    const buyer=cm[String(p.comprador_id||"")]||{},benef=cm[String(p.beneficiario_id||"")]||{},q=normalizeTextV181(filters.q||""),hay=normalizeTextV181([p.vale_codigo,p.comprador_nome,p.beneficiario_nome,p.presente_para,buyer.telefone,benef.telefone].join(" "));
    if(filters.client_id&&String(p.cliente_id)!==String(filters.client_id))continue;
    if(filters.start&&dateOnlyV181(p.data_compra)<dateOnlyV181(filters.start))continue;
    if(filters.end&&dateOnlyV181(p.data_compra)>dateOnlyV181(filters.end))continue;
    if(filters.status&&status!==String(filters.status).toUpperCase())continue;
    if(filters.servico_id&&!its.some(i=>String(i.servico_id)===String(filters.servico_id)))continue;
    if(q&&!hay.includes(q))continue;
    out.push({id:p.id,cliente_id:p.cliente_id||"",cliente:p.cliente_nome||p.beneficiario_nome||p.comprador_nome||"",data_compra:dateOnlyV181(p.data_compra),validade:dateOnlyV181(p.validade),
      valor_original:round2V181(p.valor_original),valor_negociado:round2V181(p.valor_negociado),status,status_exibicao:status,observacoes:p.observacoes||"",
      tipo_pacote:p.tipo_pacote||"USO_PROPRIO",comprador_id:p.comprador_id||p.cliente_id||"",comprador:p.comprador_nome||p.cliente_nome||"",beneficiario_id:p.beneficiario_id||"",beneficiario:p.beneficiario_nome||"",
      presente_para:p.presente_para||"",vale_codigo:p.vale_codigo||"",has_consumption:hasConsumption,can_edit:admin&&status!=="CANCELADO",edit_mode:hasConsumption?"PROTECTED":"FULL",
      can_delete:admin&&!hasConsumption&&status!=="CANCELADO",can_assign_beneficiary:packageGiftV181(p)&&status!=="CANCELADO"&&(!p.beneficiario_id||admin),refund_status:latestRefund?.status||"",
      items:its.map(i=>({id:i.id,servico_id:i.servico_id,servico:i.servico_nome,quantidade:numV181(i.quantidade),consumida:numV181(i.quantidade_consumida),saldo:Math.max(0,numV181(i.quantidade)-numV181(i.quantidade_consumida)),
        valor_unitario_original:round2V181(i.valor_unitario_original),valor_unitario_negociado:round2V181(i.valor_unitario_negociado),cortesia_sem_comissao:boolV181(i.cortesia_sem_comissao,false),cortesia:boolV181(i.cortesia_sem_comissao,false),incluido_em:i.criado_em||""}))});
  }
  return out.sort((a,b)=>String(b.data_compra).localeCompare(String(a.data_compra))||String(b.id).localeCompare(String(a.id)));
}
async function packageGetV181(user:any,id:string){
  const row=(await packageListV181(user,{})).find(p=>String(p.id)===String(id));if(!row)throw new Error("Pacote não encontrado.");
  const p=await rowByIdV181("pacotes",id),payments=(await allRowsV181("pacote_pagamentos")).filter(x=>String(x.pacote_id)===String(id)&&packagePaymentActiveV181(x));
  return {...row,cliente_id:p?.comprador_id||p?.cliente_id||"",cliente:p?.comprador_nome||p?.cliente_nome||"",payments:payments.map(x=>({id:x.id,forma_id:x.forma_id,forma_nome:x.forma_nome,valor:round2V181(x.valor_bruto),data:dateOnlyV181(x.data_recebimento),taxa:round2V181(x.valor_taxa),liquido:round2V181(x.valor_liquido)}))};
}
async function packageStatementV181(user:any,id:string){
  const row=(await packageListV181(user,{})).find(p=>String(p.id)===String(id));if(!row)throw new Error("Pacote não encontrado.");
  const [payments,cons,ai,atts]=await Promise.all([allRowsV181("pacote_pagamentos"),allRowsV181("pacote_consumos"),allRowsV181("atendimento_itens"),allRowsV181("atendimentos")]),am:any={};atts.forEach(a=>am[String(a.id)]=a);
  const running:any={},qty:any={};row.items.forEach(i=>{running[String(i.id)]=0;qty[String(i.id)]=numV181(i.quantidade);});
  const uses=cons.filter(c=>String(c.pacote_id)===String(id)&&String(c.status||"ATIVO").toUpperCase()==="ATIVO").sort((a,b)=>String(dateOnlyV181(a.data)).localeCompare(String(dateOnlyV181(b.data)))||String(a.criado_em||"").localeCompare(String(b.criado_em||""))).map(c=>{const k=String(c.pacote_item_id);running[k]=(running[k]||0)+1;return {data:dateOnlyV181(c.data),servico:c.servico_nome,profissional:c.profissional_nome,tipo:boolV181(c.cortesia_pacote,false)?"Cortesia":"Consumo",valor_referencia:round2V181(c.valor_referencia),saldo_apos:Math.max(0,(qty[k]||0)-running[k])};});
  const commissions=ai.filter(i=>String(i.pacote_id)===String(id)&&attendanceRowActiveV181(i)).map(i=>({data:dateOnlyV181(am[String(i.atendimento_id)]?.data),profissional:i.profissional_nome,servico:i.servico_nome,status:i.comissao_status||"PENDENTE",base:round2V181(i.base_comissao),valor:round2V181(i.valor_comissao)})).sort((a,b)=>String(a.data).localeCompare(String(b.data)));
  const calc=await packageRefundCalcV181(id);
  return {...row,payments:payments.filter(x=>String(x.pacote_id)===String(id)&&packagePaymentActiveV181(x)).map(x=>({data:dateOnlyV181(x.data_recebimento),forma:x.forma_nome,valor:round2V181(x.valor_bruto),taxa:round2V181(x.valor_taxa),liquido:round2V181(x.valor_liquido)})),uses,commissions,refund:calc.refund,refund_calculation:calc};
}
async function packageClientHistoryV181(user:any,clientId:string){
  const packages=await packageListV181(user,{client_id:clientId}),cons=(await allRowsV181("pacote_consumos")).filter(c=>String(c.cliente_id)===String(clientId)&&String(c.status||"ATIVO").toUpperCase()==="ATIVO").map(c=>({pacote_id:c.pacote_id,data:dateOnlyV181(c.data),servico:c.servico_nome,profissional:c.profissional_nome,valor_referencia:round2V181(c.valor_referencia)})).sort((a,b)=>String(b.data).localeCompare(String(a.data)));
  return {packages,consumptions:cons};
}
// ============================= fim Pacotes leitura =============================


// ============================= v1.8.1 — Pacotes gravação =============================
async function packageTxV181(action:string,payload:any,user:any){
  const r=await db.rpc("studio_package_tx_v181",{p_action:action,p_payload:payload,p_user:{id:user?.id||"",nome:user?.nome||""}});
  if(r.error)throw new Error(r.error.message);return r.data;
}
function packageAuditRowV181(user:any,action:string,id:string,details:any){
  return {id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user?.id||"SYSTEM",usuario_nome:user?.nome||"Sistema",acao:action,entidade:"PACOTE",entidade_id:id,detalhes:JSON.stringify(details||{})};
}
async function packageHasConsumptionV181(id:string){
  const [items,cons]=await Promise.all([allRowsV181("pacote_itens"),allRowsV181("pacote_consumos")]);
  return items.some(i=>String(i.pacote_id)===String(id)&&packageItemActiveV181(i)&&numV181(i.quantidade_consumida)>0.0001) ||
         cons.some(c=>String(c.pacote_id)===String(id)&&String(c.status||"ATIVO").toUpperCase()==="ATIVO");
}
async function preparePackageItemsV181(rawItems:any[],packageId:string){
  const services=await allRowsV181("servicos"),sm:any={};services.forEach(s=>sm[String(s.id)]=s);
  const items:any[]=[];let original=0,negotiated=0;
  for(const x of rawItems||[]){
    const s=sm[String(x?.servico_id||"")];
    if(!s||!isActiveV181(s.ativo)||catalogStatusV181(s)!=="ATUAL")throw new Error("Serviço inválido no pacote.");
    const qty=Math.max(1,Math.floor(numV181(x.quantidade)||1)),courtesy=!!x.cortesia_sem_comissao,uo=courtesy?0:round2V181(s.preco_padrao),un=courtesy?0:round2V181(x.valor_unitario_negociado);
    if(un<0)throw new Error("Valor negociado inválido.");
    const row={id:uidV181("PKI"),pacote_id:packageId,servico_id:s.id,servico_nome:s.nome,categoria:s.categoria||"",quantidade:qty,quantidade_consumida:0,
      valor_unitario_original:uo,valor_total_original:round2V181(uo*qty),valor_unitario_negociado:un,valor_total_negociado:round2V181(un*qty),
      cortesia_sem_comissao:courtesy,status:"ATIVO",criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};
    original=round2V181(original+row.valor_total_original);negotiated=round2V181(negotiated+row.valor_total_negociado);items.push(row);
  }
  return {items,original,negotiated};
}
async function preparePackagePaymentsV181(packageId:string,date:string,raw:any[],target:number,description:string){
  const payments:any[]=[],cash:any[]=[];let sum=0;
  for(const x of raw||[]){
    const amount=round2V181(x.valor);if(amount<=0)continue;
    const form=await rowByIdV181("formas_pagamento",String(x.forma_id||""));if(!form||!isActiveV181(form.ativo))throw new Error("Forma de pagamento inválida.");
    const rate=await resolveRateAttendanceV181(form.id,date,x||{}),fee=round2V181(amount*numV181(rate?.percentual)+numV181(rate?.taxa_fixa)),account=await paymentAccountAttendanceV181(form.id),id=uidV181("PPG");
    payments.push({id,pacote_id:packageId,forma_id:form.id,forma_nome:form.nome,taxa_id:rate?.id||"",bandeira:rate?.bandeira||"",condicao:rate?.condicao||"QUALQUER",
      valor_bruto:amount,taxa_percentual:numV181(rate?.percentual),taxa_fixa:numV181(rate?.taxa_fixa),valor_taxa:fee,valor_liquido:round2V181(amount-fee),data_recebimento:date,status:"ATIVO",criado_em:nowIsoV181(),atualizado_em:nowIsoV181()});
    cash.push({id:uidV181("MOV"),data,competencia:date,tipo:"RECEITA",origem:"PACOTE",origem_id:packageId,descricao:description,valor:amount,status:"REALIZADO",forma_pagamento:form.nome,criado_em:nowIsoV181(),
      conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""});
    if(fee>0)cash.push({id:uidV181("MOV"),data,competencia:date,tipo:"TAXA_FINANCEIRA",origem:"PACOTE_PAGAMENTO",origem_id:id,descricao:"Taxa "+form.nome+" - pacote",valor:-fee,status:"REALIZADO",forma_pagamento:form.nome,criado_em:nowIsoV181(),
      conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""});
    sum=round2V181(sum+amount);
  }
  if(Math.abs(sum-round2V181(target))>0.02)throw new Error("A soma dos pagamentos deve ser igual ao valor do pacote.");
  return {payments,cash};
}
async function packageSaveV181(user:any,payload:any){
  payload=payload||{};const existing=payload.id?await rowByIdV181("pacotes",payload.id):null,admin=String(user?.perfil||"").toUpperCase()==="ADMIN";
  if(existing&&!admin)throw new Error("Somente o administrador pode editar um pacote já vendido.");
  if(existing&&await packageHasConsumptionV181(existing.id))throw new Error("Este pacote já possui consumo e deve ser alterado pelo modo protegido.");
  const buyer=await rowByIdV181("clientes",String(payload.cliente_id||""));if(!buyer||!isActiveV181(buyer.ativo))throw new Error("Selecione a cliente/compradora.");
  const date=dateOnlyV181(payload.data_compra||todayV181()),type=String(payload.tipo_pacote||"USO_PROPRIO").toUpperCase()==="VALE_PRESENTE"?"VALE_PRESENTE":"USO_PROPRIO";
  const id=existing?existing.id:uidV181("PKT"),prep=await preparePackageItemsV181(payload.items||[],id);if(!prep.items.length)throw new Error("Inclua ao menos um serviço no pacote.");
  const negotiated=round2V181(payload.valor_negociado);if(negotiated<0||Math.abs(prep.negotiated-negotiated)>0.02)throw new Error("A soma dos valores dos serviços deve ser igual ao valor negociado do pacote.");
  const buyerName=clientNameV181(buyer),pay=await preparePackagePaymentsV181(id,date,payload.payments||[],negotiated,"Venda de pacote - "+buyerName);
  let beneficiaryId="",beneficiaryName="",coreId="",coreName="",vale="",associatedAt:any=null,associatedBy="";
  if(type==="USO_PROPRIO"){beneficiaryId=buyer.id;beneficiaryName=buyerName;coreId=buyer.id;coreName=buyerName;}
  else{
    vale=existing?.vale_codigo||("VP-"+id.replace(/^PKT-/,""));
    if(existing&&packageGiftV181(existing)&&existing.beneficiario_id){beneficiaryId=existing.beneficiario_id;beneficiaryName=existing.beneficiario_nome||"";coreId=beneficiaryId;coreName=beneficiaryName;associatedAt=existing.beneficiario_associado_em||null;associatedBy=existing.beneficiario_associado_por||"";}
  }
  const pkg:any={id,cliente_id:coreId||null,cliente_nome:coreName||"",data_compra:date,validade:dateOnlyV181(payload.validade)||null,valor_original:prep.original,valor_negociado:negotiated,
    status:type==="VALE_PRESENTE"&&!beneficiaryId?"AGUARDANDO_BENEFICIARIO":"ATIVO",observacoes:String(payload.observacoes||""),usuario_id:existing?.usuario_id||user.id,usuario_nome:existing?.usuario_nome||user.nome,
    criado_em:existing?.criado_em||nowIsoV181(),atualizado_em:nowIsoV181(),editado_por:existing?user.nome:"",tipo_pacote:type,comprador_id:buyer.id,comprador_nome:buyerName,
    beneficiario_id:beneficiaryId||null,beneficiario_nome:beneficiaryName,presente_para:type==="VALE_PRESENTE"?String(payload.presente_para||""):"",vale_codigo:vale,
    beneficiario_associado_em:associatedAt,beneficiario_associado_por:associatedBy};
  const action=existing?"FULL_UPDATE":"CREATE";
  await packageTxV181(action,{package:pkg,items:prep.items,payments:pay.payments,cash:pay.cash,audit:[packageAuditRowV181(user,existing?"ALTERAR":"VENDER",id,{comprador:buyerName,valor:negotiated,tipo_pacote:type})]},user);
  return {ok:true,id};
}
async function packageProtectedUpdateV181(user:any,payload:any){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Somente o administrador pode editar pacote consumido.");
  const p=await rowByIdV181("pacotes",String(payload?.id||""));if(!p||String(p.status||"").toUpperCase()==="CANCELADO")throw new Error("Pacote não encontrado ou cancelado.");
  if(!(await packageHasConsumptionV181(p.id)))throw new Error("Este pacote não exige modo protegido.");
  const prep=await preparePackageItemsV181(payload.new_items||[],p.id),pay=await preparePackagePaymentsV181(p.id,todayV181(),payload.payments||[],prep.negotiated,"Adição ao pacote - "+String(p.comprador_nome||p.cliente_nome||""));
  const current=(await allRowsV181("pacote_itens")).filter(i=>String(i.pacote_id)===String(p.id)&&packageItemActiveV181(i)),status=packageStatusCalcV181({...p,status:"ATIVO"},current.concat(prep.items));
  const pkg={...p,validade:dateOnlyV181(payload.validade)||null,valor_original:round2V181(numV181(p.valor_original)+prep.original),valor_negociado:round2V181(numV181(p.valor_negociado)+prep.negotiated),
    status,observacoes:String(payload.observacoes||""),atualizado_em:nowIsoV181(),editado_por:user.nome};
  await packageTxV181("PROTECTED_UPDATE",{package:pkg,items:prep.items,payments:pay.payments,cash:pay.cash,audit:[packageAuditRowV181(user,"ALTERAR_PROTEGIDO",p.id,{adicao:prep.negotiated,novos_itens:prep.items.length})]},user);
  return {ok:true,id:p.id};
}
async function packageDeleteV181(user:any,id:string){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Somente o administrador pode excluir pacotes.");
  const p=await rowByIdV181("pacotes",id);if(!p)throw new Error("Pacote não encontrado.");
  if(String(p.status||"").toUpperCase()==="CANCELADO")throw new Error("Pacote cancelado não pode ser excluído.");
  if(await packageHasConsumptionV181(id))throw new Error("Pacote com consumo não pode ser excluído. Use cancelamento/reembolso.");
  await packageTxV181("DELETE",{package:p,audit:[packageAuditRowV181(user,"EXCLUIR",id,{cliente:p.cliente_nome||p.comprador_nome,valor:p.valor_negociado})]},user);return true;
}
async function packageCancelRefundV181(user:any,id:string,obs:any){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Somente o administrador pode cancelar pacotes.");
  const p=await rowByIdV181("pacotes",id);if(!p||String(p.status||"").toUpperCase()==="CANCELADO")throw new Error("Pacote não encontrado ou já cancelado.");
  if(!(await packageHasConsumptionV181(id)))throw new Error("Pacote sem consumo deve ser excluído, não cancelado.");
  const calc=await packageRefundCalcV181(id),refunds:any[]=[];let refund:any=null;
  if(calc.reembolso_calculado>0){refund={id:uidV181("PRF"),pacote_id:id,data_cancelamento:todayV181(),valor_calculado:calc.reembolso_calculado,valor_pago:0,forma_id:null,forma_pagamento:"",data_pagamento:null,status:"PENDENTE",
      observacoes:String(obs||""),usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};refunds.push(refund);}
  const note=[String(p.observacoes||"").trim(),obs?("Cancelamento: "+String(obs)):""].filter(Boolean).join(" | "),pkg={...p,status:"CANCELADO",observacoes:note,atualizado_em:nowIsoV181(),editado_por:user.nome};
  await packageTxV181("CANCEL_REFUND",{package:pkg,refunds,audit:[packageAuditRowV181(user,"CANCELAR",id,{reembolso:calc.reembolso_calculado,observacoes:String(obs||"")})]},user);
  return {ok:true,calculation:calc,refund:refund?{id:refund.id,status:"PENDENTE",valor_calculado:refund.valor_calculado,valor_pago:0}:null};
}
async function packagePayRefundV181(user:any,payload:any){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Somente o administrador pode pagar reembolsos.");
  const r=await rowByIdV181("pacote_reembolsos",String(payload?.refund_id||""));if(!r||String(r.status||"").toUpperCase()!=="PENDENTE")throw new Error("Reembolso pendente não encontrado.");
  const form=await rowByIdV181("formas_pagamento",String(payload?.forma_id||""));if(!form||!isActiveV181(form.ativo))throw new Error("Forma de pagamento inválida.");
  const account=await paymentAccountAttendanceV181(form.id),date=dateOnlyV181(payload?.data_pagamento||todayV181()),amount=round2V181(r.valor_calculado),obs=String(payload?.observacoes||r.observacoes||"");
  const refund={...r,valor_pago:amount,forma_id:form.id,forma_pagamento:form.nome,data_pagamento:date,status:"PAGO",observacoes:obs,atualizado_em:nowIsoV181()};
  const cash=[{id:uidV181("MOV"),data,competencia:date,tipo:"REEMBOLSO_PACOTE",origem:"PACOTE_REEMBOLSO",origem_id:r.id,descricao:"Reembolso de pacote",valor:-amount,status:"REALIZADO",forma_pagamento:form.nome,
    criado_em:nowIsoV181(),conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""}];
  await packageTxV181("PAY_REFUND",{refund,cash,audit:[packageAuditRowV181(user,"PAGAR_REEMBOLSO",r.pacote_id,{refund_id:r.id,valor:amount,forma:form.nome})]},user);return true;
}
async function packageAssignBeneficiaryV181(user:any,payload:any){
  const p=await rowByIdV181("pacotes",String(payload?.package_id||""));if(!p||!packageGiftV181(p)||String(p.status||"").toUpperCase()==="CANCELADO")throw new Error("Vale Presente não encontrado.");
  const c=await rowByIdV181("clientes",String(payload?.beneficiario_id||""));if(!c||!isActiveV181(c.ativo))throw new Error("Beneficiária inválida.");
  const consumed=await packageHasConsumptionV181(p.id),admin=String(user?.perfil||"").toUpperCase()==="ADMIN",reatribuido=!!p.beneficiario_id&&String(p.beneficiario_id)!==String(c.id);
  if((consumed||reatribuido)&&!admin)throw new Error("Somente o administrador pode reatribuir um Vale Presente com beneficiária/consumo.");
  const items=(await allRowsV181("pacote_itens")).filter(i=>String(i.pacote_id)===String(p.id)&&packageItemActiveV181(i)),status=packageStatusCalcV181({...p,beneficiario_id:c.id,status:"ATIVO"},items),name=clientNameV181(c);
  const pkg={...p,cliente_id:c.id,cliente_nome:name,beneficiario_id:c.id,beneficiario_nome:name,status,beneficiario_associado_em:nowIsoV181(),beneficiario_associado_por:user.nome,atualizado_em:nowIsoV181(),editado_por:user.nome};
  await packageTxV181("ASSIGN_BENEFICIARY",{package:pkg,audit:[packageAuditRowV181(user,reatribuido?"REATRIBUIR_BENEFICIARIO":"ASSOCIAR_BENEFICIARIO",p.id,{beneficiario_id:c.id,beneficiario:name,consumo_existente:consumed})]},user);
  return {ok:true,reatribuido,beneficiario_id:c.id,beneficiario:name};
}
// ============================= fim Pacotes gravação =============================


// ============================= v1.8.1 — Vendas completas =============================
function saleItemActiveV181(r:any){return ["","ATIVO","REALIZADO","CONCLUIDO"].includes(String(r?.status||"ATIVO").toUpperCase());}
function salePaymentActiveV181(r:any){return String(r?.status||"ATIVO").toUpperCase()==="ATIVO";}
async function saleTxV181(action:string,payload:any,user:any){
  const r=await db.rpc("studio_sale_tx_v181",{p_action:action,p_payload:payload,p_user:{id:user?.id||"",nome:user?.nome||""}});
  if(r.error)throw new Error(r.error.message);return r.data;
}
function saleAuditRowV181(user:any,action:string,id:string,details:any){
  return {id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user?.id||"SYSTEM",usuario_nome:user?.nome||"Sistema",acao:action,entidade:"VENDA",entidade_id:id,detalhes:JSON.stringify(details||{})};
}
function saleCanEditV181(user:any,date:any){return canEditAttendanceV181(user,date);}
function saleCanCancelV181(user:any,date:any){return String(user?.perfil||"").toUpperCase()==="ADMIN"||canCancelAttendanceV181(user,date);}
async function saleRowsV181(user:any,filters:any){
  filters=filters||{};const [sales,items]=await Promise.all([allRowsV181("vendas"),allRowsV181("venda_itens")]),admin=String(user?.perfil||"").toUpperCase()==="ADMIN";
  let start=dateOnlyV181(filters.start||"1900-01-01"),end=dateOnlyV181(filters.end||"2999-12-31");
  if(!admin){start=todayV181();end=todayV181();}
  return sales.filter(s=>String(s.status||"").toUpperCase()!=="CANCELADO"&&dateOnlyV181(s.data)>=start&&dateOnlyV181(s.data)<=end)
    .sort((a,b)=>String(b.data).localeCompare(String(a.data))||String(b.criado_em||"").localeCompare(String(a.criado_em||"")))
    .slice(0,500).map(s=>{
      const its=items.filter(i=>String(i.venda_id)===String(s.id)&&saleItemActiveV181(i));
      return {id:s.id,data:dateOnlyV181(s.data),destino:s.destino||"CLIENTE",cliente:s.cliente_nome||"",vendedor:String(s.vendedor_tipo||"STUDIO")==="PROFISSIONAL"?(s.vendedor_profissional_nome||""):"Studio Essence",
        produtos:its.map(i=>String(i.produto_nome||"")+" x"+numV181(i.quantidade)).join(", "),total:round2V181(its.reduce((z,i)=>z+numV181(i.valor_bruto),0)),
        can_edit:saleCanEditV181(user,s.data),can_cancel:saleCanCancelV181(user,s.data)};
    });
}
async function salesPageV181(user:any,filters:any){
  const admin=String(user?.perfil||"").toUpperCase()==="ADMIN",rows=await saleRowsV181(user,filters||{}),allSales=(await allRowsV181("vendas")).filter(s=>String(s.status||"").toUpperCase()!=="CANCELADO"),items=await allRowsV181("venda_itens");
  const today=todayV181(),month=today.slice(0,7),year=today.slice(0,4);
  function bucket(pred:(s:any)=>boolean){const ss=allSales.filter(pred),ids=new Set(ss.map(s=>String(s.id))),its=items.filter(i=>ids.has(String(i.venda_id))&&saleItemActiveV181(i));return {count:ss.length,value:round2V181(its.reduce((z,i)=>z+numV181(i.valor_bruto),0))};}
  return {admin,summary:{today:bucket(s=>dateOnlyV181(s.data)===today),month:bucket(s=>dateOnlyV181(s.data).slice(0,7)===month),year:bucket(s=>dateOnlyV181(s.data).slice(0,4)===year)},rows,restricted_start:admin?"":today,restricted_end:admin?"":today};
}
async function saleGetV181(user:any,id:string){
  const s=await rowByIdV181("vendas",id);if(!s||String(s.status||"").toUpperCase()==="CANCELADO")throw new Error("Venda não encontrada.");
  const [items,pays]=await Promise.all([allRowsV181("venda_itens"),allRowsV181("pagamentos_venda")]);
  return {id:s.id,data:dateOnlyV181(s.data),destino:s.destino||"CLIENTE",cliente_id:s.cliente_id||"",cliente:s.cliente_nome||"",vendedor_tipo:s.vendedor_tipo||"STUDIO",profissional_id:s.vendedor_profissional_id||"",
    profissional_nome:s.vendedor_profissional_nome||"",observacoes:s.observacoes||"",
    items:items.filter(i=>String(i.venda_id)===String(id)&&saleItemActiveV181(i)).map(i=>({id:i.id,produto_id:i.produto_id,produto_nome:i.produto_nome,quantidade:numV181(i.quantidade),valor_unitario:round2V181(i.valor_unitario),percentual_comissao:numV181(i.percentual_comissao),comissao_status:i.comissao_status||"SEM_COMISSAO"})),
    payments:pays.filter(p=>String(p.venda_id)===String(id)&&salePaymentActiveV181(p)).map(p=>({forma_id:p.forma_id,forma_nome:p.forma_nome,valor:round2V181(p.valor_bruto),taxa_id:p.taxa_id||"",bandeira:p.bandeira||"",condicao:p.condicao||"QUALQUER"})),
    can_edit:saleCanEditV181(user,s.data),can_cancel:saleCanCancelV181(user,s.data)};
}
async function salePrepareV181(user:any,payload:any,id:string){
  payload=payload||{};const date=dateOnlyV181(payload.data||todayV181());if(!date||!Array.isArray(payload.items)||!payload.items.length)throw new Error("Informe a data e ao menos um produto.");
  const destino=["CLIENTE","USO_STUDIO","USO_PARTICULAR"].includes(String(payload.destino||"CLIENTE").toUpperCase())?String(payload.destino||"CLIENTE").toUpperCase():"CLIENTE";
  let client:any=null;if(destino==="CLIENTE"&&payload.cliente_id){client=await rowByIdV181("clientes",String(payload.cliente_id));if(!client||!isActiveV181(client.ativo))throw new Error("Cliente inválida.");}
  const sellerType=destino==="CLIENTE"&&String(payload.vendedor_tipo||"STUDIO").toUpperCase()==="PROFISSIONAL"?"PROFISSIONAL":"STUDIO";
  let prof:any=null;if(sellerType==="PROFISSIONAL"){prof=await rowByIdV181("profissionais",String(payload.profissional_id||""));if(!prof||!isActiveV181(prof.ativo)||professionalDeletedV181(prof))throw new Error("Selecione a profissional que realizou a venda.");}
  const [products,oldItems,repays]=await Promise.all([allRowsV181("produtos"),allRowsV181("venda_itens"),allRowsV181("consignacao_repasses")]),pm:any={};products.forEach(p=>pm[String(p.id)]=p);
  const existingCredit:any={};oldItems.filter(i=>String(i.venda_id)===String(id)&&saleItemActiveV181(i)).forEach(i=>existingCredit[String(i.produto_id)]=(existingCredit[String(i.produto_id)]||0)+numV181(i.quantidade));
  const needed:any={},prepared:any[]=[];
  for(const x of payload.items){
    const p=pm[String(x.produto_id||"")];if(!p||!isActiveV181(p.ativo)||productDeletedV181(p)||String(p.finalidade||"OPERACIONAL").toUpperCase()!=="VENDA")throw new Error("Selecione um Produto para Venda ativo em todos os itens.");
    const qty=Math.abs(numV181(x.quantidade)),unit=destino==="CLIENTE"?round2V181(x.valor_unitario):0;if(qty<=0)throw new Error("A quantidade deve ser maior que zero.");if(unit<0)throw new Error("O valor do produto não pode ser negativo.");
    needed[p.id]=(needed[p.id]||0)+qty;prepared.push({product:p,qty,unit,gross:round2V181(qty*unit),pct:sellerType==="PROFISSIONAL"?Math.max(0,numV181(x.percentual_comissao)):0});
  }
  for(const pid of Object.keys(needed)){const p=pm[pid],available=numV181(p.estoque_atual)+numV181(existingCredit[pid]);if(available+0.0001<needed[pid])throw new Error("Estoque insuficiente para "+p.produto+". Disponível: "+available+".");}
  const total=destino==="CLIENTE"?round2V181(prepared.reduce((s,x)=>s+x.gross,0)):0;if(destino==="CLIENTE"&&total<=0)throw new Error("O valor total da venda deve ser maior que zero.");
  const payments:any[]=[],cash:any[]=[];let paySum=0;
  if(destino==="CLIENTE"){
    for(const x of payload.payments||[]){
      const amount=round2V181(x.valor);if(amount<=0)continue;const form=await rowByIdV181("formas_pagamento",String(x.forma_id||""));if(!form||!isActiveV181(form.ativo))throw new Error("Forma de pagamento inválida.");
      const rate=await resolveRateAttendanceV181(form.id,date,x||{}),fee=round2V181(amount*numV181(rate?.percentual)+numV181(rate?.taxa_fixa)),account=await paymentAccountAttendanceV181(form.id),pid=uidV181("PVD");
      payments.push({id:pid,venda_id:id,forma_id:form.id,forma_nome:form.nome,taxa_id:rate?.id||"",bandeira:rate?.bandeira||"",condicao:rate?.condicao||"QUALQUER",valor_bruto:amount,taxa_percentual:numV181(rate?.percentual),taxa_fixa:numV181(rate?.taxa_fixa),valor_taxa:fee,valor_liquido:round2V181(amount-fee),data_recebimento:date,origem:"SISTEMA",criado_em:nowIsoV181(),status:"ATIVO",atualizado_em:nowIsoV181()});
      cash.push({id:uidV181("MOV"),data,competencia:date,tipo:"RECEITA_PRODUTO",origem:"VENDA",origem_id:id,descricao:"Venda de produtos"+(client?" - "+clientNameV181(client):""),valor:amount,status:"REALIZADO",forma_pagamento:form.nome,criado_em:nowIsoV181(),conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""});
      if(fee>0)cash.push({id:uidV181("MOV"),data,competencia:date,tipo:"TAXA_FINANCEIRA",origem:"PAGAMENTO_VENDA",origem_id:pid,descricao:"Taxa "+form.nome+" - venda",valor:-fee,status:"REALIZADO",forma_pagamento:form.nome,criado_em:nowIsoV181(),conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""});
      paySum=round2V181(paySum+amount);
    }
    if(Math.abs(paySum-total)>0.02)throw new Error("A soma dos pagamentos deve ser igual ao valor da venda.");
  }
  const items:any[]=[],stock:any[]=[],consignment:any[]=[];
  for(const it of prepared){
    const feeAll=destino==="CLIENTE"?payments.reduce((s,p)=>s+numV181(p.valor_taxa)*(it.gross/total),0):0;
    const feeCommission=prof?payments.reduce((s,p)=>s+0,0):0;
    let feeComm=0;if(prof){for(const p of payments)if(await feeRuleAttendanceV181(prof.id,p.forma_id,date))feeComm+=numV181(p.valor_taxa)*(it.gross/total);}
    const base=round2V181(Math.max(0,it.gross-feeComm)),commission=prof?round2V181(base*it.pct):0,itemId=uidV181("VIT"),p=it.product;
    items.push({id:itemId,venda_id:id,profissional_id:prof?.id||"",profissional_nome:prof?.nome||"",produto_id:p.id,produto_nome:p.produto,quantidade:it.qty,valor_unitario:it.unit,valor_bruto:it.gross,taxa_considerada_comissao:round2V181(feeComm),valor_liquido:round2V181(it.gross-feeAll),base_comissao:base,percentual_comissao:it.pct,valor_comissao:commission,studio_liquido:round2V181(it.gross-commission),studio_liquido_pos_taxas:round2V181(it.gross-commission-feeAll),regra_taxa:feeComm>0?"BASE_LIQUIDA_APOS_TAXA":"BASE_BRUTA",comissao_status:prof&&commission>0?"PENDENTE":"SEM_COMISSAO",status:"ATIVO",origem:"SISTEMA",criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),finalidade:"VENDA",modelo_comercial:p.modelo_comercial||"NORMAL",fornecedor:p.fornecedor||"",custo_unitario_snapshot:numV181(p.custo_unitario),valor_repasse_fornecedor_snapshot:numV181(p.valor_repasse_fornecedor),preco_referencia_venda:numV181(p.preco_venda),destino});
    stock.push({id:uidV181("EST"),data,produto_id:p.id,produto_nome:p.produto,tipo:destino==="CLIENTE"?"VENDA":destino,quantidade:-it.qty,profissional_id:prof?.id||"",profissional_nome:prof?.nome||"",custo_total:0,observacoes:"Baixa automática por "+(destino==="CLIENTE"?"venda ":"movimentação ")+id,usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),referencia_tipo:"VENDA_ITEM",referencia_id:itemId,status:"ATIVO"});
    if(destino==="USO_STUDIO"){
      const op=pm[String(p.produto_operacional_vinculado_id||"")];if(!op)throw new Error("O produto "+p.produto+" não possui produto operacional vinculado para Uso do Studio.");
      stock.push({id:uidV181("EST"),data,produto_id:op.id,produto_nome:op.produto,tipo:"ENTRADA_USO_STUDIO",quantidade:it.qty,profissional_id:"",profissional_nome:"",custo_total:0,observacoes:"Transferência automática da área de venda "+id,usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),referencia_tipo:"VENDA_ITEM",referencia_id:itemId,status:"ATIVO"});
    }
    if(String(p.modelo_comercial||"NORMAL").toUpperCase()==="CONSIGNADO"&&numV181(p.valor_repasse_fornecedor)>0){
      const rep=round2V181(numV181(p.valor_repasse_fornecedor)*it.qty),saleValue=it.gross;
      consignment.push({id:uidV181("CRP"),data,produto_id:p.id,produto_nome:p.produto,fornecedor:p.fornecedor||"",origem_tipo:"VENDA",origem_id:id,origem_item_id:itemId,destino,quantidade:it.qty,valor_unitario_repasse:numV181(p.valor_repasse_fornecedor),valor_total_repasse:rep,valor_venda_total:saleValue,resultado_bruto:round2V181(saleValue-rep),status:"PENDENTE",data_pagamento:null,forma_pagamento:null,fechamento_id:null,observacoes:"Gerado automaticamente pela venda",usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()});
    }
  }
  const sale={id,data,cliente_id:client?.id||"",cliente_nome:client?clientNameV181(client):"",vendedor_tipo:sellerType,vendedor_profissional_id:prof?.id||"",vendedor_profissional_nome:prof?.nome||"",observacoes:String(payload.observacoes||""),usuario_id:user.id,usuario_nome:user.nome,status:"CONCLUIDO",origem:"SISTEMA",criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),editado_por:"",destino};
  return {sale,items,payments,cash,stock,consignment,total};
}
async function saleSaveV181(user:any,payload:any){
  const id=uidV181("VEN"),prep=await salePrepareV181(user,payload,id);prep.audit=[saleAuditRowV181(user,"CRIAR",id,{total:prep.total,destino:prep.sale.destino})];await saleTxV181("CREATE",prep,user);return {ok:true,id,total:prep.total};
}
async function saleUpdateV181(user:any,payload:any){
  const s=await rowByIdV181("vendas",String(payload?.id||""));if(!s||String(s.status||"").toUpperCase()==="CANCELADO")throw new Error("Venda não encontrada.");if(!saleCanEditV181(user,s.data))throw new Error("Você não tem permissão para editar esta venda.");
  const [oldItems,reps]=await Promise.all([allRowsV181("venda_itens"),allRowsV181("consignacao_repasses")]),active=oldItems.filter(i=>String(i.venda_id)===String(s.id)&&saleItemActiveV181(i));
  if(active.some(i=>!["PENDENTE","SEM_COMISSAO"].includes(String(i.comissao_status||"SEM_COMISSAO").toUpperCase())))throw new Error("Esta venda possui comissão já incluída em fechamento.");
  if(reps.some(r=>String(r.origem_id)===String(s.id)&&String(r.origem_tipo)==="VENDA"&&String(r.status||"").toUpperCase()==="PAGO"))throw new Error("Esta venda possui repasse consignado já pago.");
  const prep=await salePrepareV181(user,payload,s.id);prep.sale.criado_em=s.criado_em;prep.sale.usuario_id=s.usuario_id;prep.sale.usuario_nome=s.usuario_nome;prep.sale.editado_por=user.nome;prep.audit=[saleAuditRowV181(user,"ALTERAR",s.id,{total:prep.total,destino:prep.sale.destino})];await saleTxV181("UPDATE",prep,user);return {ok:true,id:s.id,total:prep.total};
}
async function saleCancelV181(user:any,id:string){
  const s=await rowByIdV181("vendas",id);if(!s||String(s.status||"").toUpperCase()==="CANCELADO")throw new Error("Venda não encontrada ou já cancelada.");if(!saleCanCancelV181(user,s.data))throw new Error("Você não tem permissão para cancelar esta venda.");
  const [items,reps]=await Promise.all([allRowsV181("venda_itens"),allRowsV181("consignacao_repasses")]),active=items.filter(i=>String(i.venda_id)===String(id)&&saleItemActiveV181(i));
  if(active.some(i=>!["PENDENTE","SEM_COMISSAO"].includes(String(i.comissao_status||"SEM_COMISSAO").toUpperCase())))throw new Error("Esta venda possui comissão já incluída em fechamento.");
  if(reps.some(r=>String(r.origem_id)===String(id)&&String(r.origem_tipo)==="VENDA"&&String(r.status||"").toUpperCase()==="PAGO"))throw new Error("Esta venda possui repasse consignado já pago.");
  const sale={...s,status:"CANCELADO",atualizado_em:nowIsoV181(),editado_por:user.nome};await saleTxV181("CANCEL",{sale,audit:[saleAuditRowV181(user,"CANCELAR",id,{data:dateOnlyV181(s.data),cliente:s.cliente_nome})]},user);return true;
}
// ============================= fim Vendas completas =============================


// ============================= v1.8.1 — Consignação =============================
async function consignmentListV181(filters:any){
  filters=filters||{};let rows=(await allRowsV181("consignacao_repasses")).filter(r=>!["CANCELADO","SUBSTITUIDO"].includes(String(r.status||"PENDENTE").toUpperCase()));
  if(filters.fornecedor)rows=rows.filter(r=>normalizeTextV181(r.fornecedor)===normalizeTextV181(filters.fornecedor));
  if(filters.start)rows=rows.filter(r=>dateOnlyV181(r.data)>=dateOnlyV181(filters.start));
  if(filters.end)rows=rows.filter(r=>dateOnlyV181(r.data)<=dateOnlyV181(filters.end));
  if(filters.status)rows=rows.filter(r=>String(r.status||"").toUpperCase()===String(filters.status).toUpperCase());
  rows.sort((a,b)=>String(b.data).localeCompare(String(a.data))||String(b.criado_em||"").localeCompare(String(a.criado_em||"")));
  const mapped=rows.map(r=>({id:r.id,data:dateOnlyV181(r.data),fornecedor:r.fornecedor||"",produto:r.produto_nome||"",destino:r.destino||"CLIENTE",quantidade:numV181(r.quantidade),
    valor_venda_total:round2V181(r.valor_venda_total),valor_total_repasse:round2V181(r.valor_total_repasse),resultado_bruto:round2V181(r.resultado_bruto),status:r.status||"PENDENTE",
    data_pagamento:dateOnlyV181(r.data_pagamento),forma_pagamento:r.forma_pagamento||""}));
  return {rows:mapped,summary:{quantidade:round2V181(mapped.reduce((s,x)=>s+x.quantidade,0)),total_vendido:round2V181(mapped.reduce((s,x)=>s+x.valor_venda_total,0)),
    total_repasse:round2V181(mapped.reduce((s,x)=>s+x.valor_total_repasse,0)),resultado_bruto:round2V181(mapped.reduce((s,x)=>s+x.resultado_bruto,0))}};
}
async function consignmentPayV181(user:any,payload:any){
  const ids=(payload?.ids||[]).map(String).filter(Boolean);if(!ids.length)throw new Error("Selecione ao menos um repasse.");
  const all=await allRowsV181("consignacao_repasses"),rows=all.filter(r=>ids.includes(String(r.id)));
  if(rows.length!==ids.length||rows.some(r=>String(r.status||"").toUpperCase()!=="PENDENTE"))throw new Error("Há repasse inexistente ou já pago na seleção.");
  const suppliers=[...new Set(rows.map(r=>String(r.fornecedor||"")))];if(suppliers.length!==1)throw new Error("Selecione itens de apenas um fornecedor por pagamento.");
  const form=await rowByIdV181("formas_pagamento",String(payload?.forma_id||""));if(!form||!isActiveV181(form.ativo))throw new Error("Forma de pagamento inválida.");
  const account=await paymentAccountAttendanceV181(form.id),date=dateOnlyV181(payload?.data_pagamento||todayV181()),total=round2V181(rows.reduce((s,r)=>s+numV181(r.valor_total_repasse),0)),id=uidV181("CFN");
  const closing={id,fornecedor:suppliers[0],periodo_inicio:rows.map(r=>dateOnlyV181(r.data)).sort()[0],periodo_fim:rows.map(r=>dateOnlyV181(r.data)).sort().slice(-1)[0],
    quantidade:round2V181(rows.reduce((s,r)=>s+numV181(r.quantidade),0)),total_vendido:round2V181(rows.reduce((s,r)=>s+numV181(r.valor_venda_total),0)),total_repasse:total,
    resultado_bruto:round2V181(rows.reduce((s,r)=>s+numV181(r.resultado_bruto),0)),status:"PAGO",data_pagamento:date,forma_pagamento:form.nome,observacoes:String(payload?.observacoes||""),
    usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};
  const cash=[{id:uidV181("MOV"),data,competencia:closing.periodo_fim,tipo:"CONSIGNACAO_REPASSE",origem:"CONSIGNACAO_FECHAMENTO",origem_id:id,descricao:"Repasse consignado - "+suppliers[0],
    valor:-total,status:"REALIZADO",forma_pagamento:form.nome,criado_em:nowIsoV181(),conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""}];
  const audit=[{id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user.id,usuario_nome:user.nome,acao:"PAGAR",entidade:"CONSIGNACAO",entidade_id:id,detalhes:JSON.stringify({fornecedor:suppliers[0],total,ids})}];
  const r=await db.rpc("studio_consignment_tx_v181",{p_action:"PAY",p_payload:{closing,ids,cash,audit},p_user:{id:user.id,nome:user.nome}});if(r.error)throw new Error(r.error.message);
  return {ok:true,id,total};
}
async function consignmentPreviewRegularizationV181(filters:any){
  const [items,products,reps,sales]=await Promise.all([allRowsV181("venda_itens"),allRowsV181("produtos"),allRowsV181("consignacao_repasses"),allRowsV181("vendas")]),pm:any={},sm:any={};products.forEach(p=>pm[String(p.id)]=p);sales.forEach(s=>sm[String(s.id)]=s);
  const rows=items.filter(i=>saleItemActiveV181(i)).filter(i=>{
    const s=sm[String(i.venda_id)],p=pm[String(i.produto_id)];if(!s||String(s.status||"").toUpperCase()==="CANCELADO"||!p)return false;
    const consignado=String(i.modelo_comercial||p.modelo_comercial||"").toUpperCase()==="CONSIGNADO"&&numV181(i.valor_repasse_fornecedor_snapshot||p.valor_repasse_fornecedor)>0;
    if(!consignado)return false;if(filters?.fornecedor&&normalizeTextV181(i.fornecedor||p.fornecedor)!==normalizeTextV181(filters.fornecedor))return false;
    const d=dateOnlyV181(s.data);if(filters?.start&&d<dateOnlyV181(filters.start))return false;if(filters?.end&&d>dateOnlyV181(filters.end))return false;
    return !reps.some(r=>String(r.origem_tipo)==="VENDA"&&String(r.origem_item_id)===String(i.id)&&!["CANCELADO","SUBSTITUIDO"].includes(String(r.status||"").toUpperCase()));
  });
  const productsAgg:any={};let total=0;rows.forEach(i=>{const p=pm[String(i.produto_id)],rep=round2V181(numV181(i.valor_repasse_fornecedor_snapshot||p?.valor_repasse_fornecedor)*numV181(i.quantidade));total+=rep;const k=i.produto_nome||p?.produto||"";productsAgg[k]=(productsAgg[k]||0)+1;});
  return {count:rows.length,total_repasse:round2V181(total),products:Object.entries(productsAgg).map(([produto,count])=>({produto,count})),item_ids:rows.map(i=>i.id)};
}
async function consignmentRegularizeV181(user:any,filters:any){
  const preview=await consignmentPreviewRegularizationV181(filters||{});if(!preview.count)return {ok:true,updated:0,repasses_criados:0};
  const [items,products,sales]=await Promise.all([allRowsV181("venda_itens"),allRowsV181("produtos"),allRowsV181("vendas")]),im:any={},pm:any={},sm:any={};items.forEach(i=>im[String(i.id)]=i);products.forEach(p=>pm[String(p.id)]=p);sales.forEach(s=>sm[String(s.id)]=s);
  const repasses:any[]=[],updates:any[]=[];
  for(const iid of preview.item_ids){const i=im[String(iid)],p=pm[String(i.produto_id)],s=sm[String(i.venda_id)],qty=numV181(i.quantidade),unit=numV181(i.valor_repasse_fornecedor_snapshot||p.valor_repasse_fornecedor),rep=round2V181(unit*qty),saleVal=numV181(i.valor_bruto),dest=i.destino||s.destino||"CLIENTE";
    repasses.push({id:uidV181("CRP"),data:dateOnlyV181(s.data),produto_id:p.id,produto_nome:p.produto,fornecedor:i.fornecedor||p.fornecedor||"",origem_tipo:"VENDA",origem_id:s.id,origem_item_id:i.id,destino:dest,quantidade:qty,valor_unitario_repasse:unit,valor_total_repasse:rep,valor_venda_total:saleVal,resultado_bruto:round2V181(saleVal-rep),status:"PENDENTE",data_pagamento:null,forma_pagamento:null,fechamento_id:null,observacoes:"Regularização retroativa v1.8.1",usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()});
    updates.push({id:i.id,finalidade:"VENDA",modelo_comercial:p.modelo_comercial||"CONSIGNADO",fornecedor:p.fornecedor||"",custo_unitario_snapshot:numV181(p.custo_unitario),valor_repasse_fornecedor_snapshot:unit,preco_referencia_venda:numV181(p.preco_venda),destino:dest});
  }
  const audit=[{id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user.id,usuario_nome:user.nome,acao:"REGULARIZAR",entidade:"CONSIGNACAO",entidade_id:"HISTORICO",detalhes:JSON.stringify({count:repasses.length,total_repasse:preview.total_repasse})}];
  const r=await db.rpc("studio_consignment_tx_v181",{p_action:"REGULARIZE",p_payload:{repasses,item_updates:updates,audit},p_user:{id:user.id,nome:user.nome}});if(r.error)throw new Error(r.error.message);
  return {ok:true,updated:updates.length,repasses_criados:repasses.length};
}
// ============================= fim Consignação =============================


// ============================= v1.8.1 — Despesas completas =============================
function expenseCardV181(v:any){const s=normalizeTextV181(v||"");return s==="credito"||s==="cartao socio(a)"||s==="cartao socio"||s==="cartao sócio(a)";}
async function expenseCategoryResolveV181(category:any,subcategory:any){
  const [cats,subs]=await Promise.all([allRowsV181("categorias_despesas"),allRowsV181("subcategorias_despesas")]);
  const cat=cats.find(c=>isActiveV181(c.ativo)&&normalizeTextV181(c.nome)===normalizeTextV181(category));
  if(!cat)throw new Error("Selecione uma categoria de despesa válida.");
  const sub=String(subcategory||"").trim()?subs.find(s=>isActiveV181(s.ativo)&&String(s.categoria_despesa_id)===String(cat.id)&&normalizeTextV181(s.nome)===normalizeTextV181(subcategory)):null;
  if(String(subcategory||"").trim()&&!sub)throw new Error("Selecione uma subcategoria válida.");
  return {cat,sub};
}
function expenseAuditRowV181(user:any,action:string,id:string,details:any){
  return {id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user?.id||"SYSTEM",usuario_nome:user?.nome||"Sistema",acao:action,entidade:"DESPESA",entidade_id:id,detalhes:JSON.stringify(details||{})};
}
async function expenseTxV181(action:string,payload:any,user:any){
  const r=await db.rpc("studio_expense_tx_v181",{p_action:action,p_payload:payload,p_user:{id:user?.id||"",nome:user?.nome||""}});
  if(r.error)throw new Error(r.error.message);return r.data;
}
function expenseParcelsBuildV181(expense:any,status:string,paymentDate:any){
  const qty=Math.max(1,Math.floor(numV181(expense.qtd_parcelas)||1)),rows:any[]=[];let allocated=0;
  for(let i=0;i<qty;i++){
    const value=i===qty-1?round2V181(numV181(expense.valor_total)-allocated):round2V181(numV181(expense.valor_total)/qty);allocated=round2V181(allocated+value);
    const due=addMonthsRevenueV181(expense.data_primeiro_vencimento,i),paid=String(status||"PREVISTO").toUpperCase()==="PAGO";
    rows.push({id:uidV181("DSP"),despesa_id:expense.id,parcela_num:i+1,total_parcelas:qty,vencimento:due,valor:value,status:paid?"PAGO":"PREVISTO",
      data_pagamento:paid?dateOnlyV181(paymentDate||due):null,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()});
  }
  return rows;
}
async function expensePaymentCashV181(expense:any,parcel:any,accountId:any,date:any){
  const d=dateOnlyV181(date||parcel.data_pagamento||todayV181()),cash:any[]=[];
  if(expenseCardV181(expense.forma_pagamento)){
    cash.push({id:uidV181("MOV"),data:d,competencia:dateOnlyV181(expense.data_compra),tipo:"OBRIGACAO_CARTAO_DESPESA",origem:"DESPESA_CARTAO",origem_id:parcel.id,
      descricao:"Obrigação de cartão - "+expense.descricao,valor:-round2V181(parcel.valor),status:"OBRIGACAO",forma_pagamento:expense.forma_pagamento,criado_em:nowIsoV181(),
      conta_financeira_id:null,conta_financeira_nome:null,impacto_resultado:false,conciliado:false,conciliacao_id:null,movimento_financeiro_id:null});
    return {cash,mode:"CARD_OBLIGATION"};
  }
  const acc=await rowByIdV181("contas_financeiras",String(accountId||""));if(!acc||!isActiveV181(acc.ativo))throw new Error("Selecione a conta financeira utilizada no pagamento.");
  cash.push({id:uidV181("MOV"),data:d,competencia:dateOnlyV181(expense.data_compra),tipo:"DESPESA",origem:"DESPESA",origem_id:expense.id,descricao:expense.descricao,
    valor:-round2V181(parcel.valor),status:"REALIZADO",forma_pagamento:expense.forma_pagamento||"",criado_em:nowIsoV181(),conta_financeira_id:acc.id,conta_financeira_nome:acc.nome,
    impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""});
  return {cash,mode:"BANK"};
}
async function expenseListV181(user:any,filters:any){
  filters=filters||{};const [expenses,parcels,mov]=await Promise.all([allRowsV181("despesas"),allRowsV181("despesa_parcelas"),allRowsV181("mov_caixa")]),dm:any={};expenses.forEach(d=>dm[String(d.id)]=d);
  const admin=String(user?.perfil||"").toUpperCase()==="ADMIN",today=todayV181(),ob:any={},settle:any={};
  mov.filter(m=>String(m.tipo||"").toUpperCase()==="OBRIGACAO_CARTAO_DESPESA").forEach(m=>ob[String(m.origem_id)]=m);
  mov.filter(m=>String(m.tipo||"").toUpperCase()==="QUITACAO_CARTAO_DESPESA"&&String(m.status||"").toUpperCase()==="REALIZADO").forEach(m=>settle[String(m.origem_id)]=m);
  return parcels.filter(p=>String(p.status||"").toUpperCase()!=="CANCELADO").filter(p=>{
    const d=dm[String(p.despesa_id)];if(!d||String(d.status||"").toUpperCase()==="CANCELADO")return false;
    if(!admin&&dateOnlyV181(d.data_compra)!==today)return false;
    if(admin&&filters.start&&dateOnlyV181(p.vencimento)<dateOnlyV181(filters.start))return false;
    if(admin&&filters.end&&dateOnlyV181(p.vencimento)>dateOnlyV181(filters.end))return false;
    if(filters.status&&String(p.status||"").toUpperCase()!==String(filters.status).toUpperCase())return false;
    if(filters.descricao&&!normalizeTextV181(d.descricao).includes(normalizeTextV181(filters.descricao)))return false;
    if(filters.categoria&&normalizeTextV181(d.categoria)!==normalizeTextV181(filters.categoria))return false;
    if(filters.forma_pagamento&&normalizeTextV181(d.forma_pagamento)!==normalizeTextV181(filters.forma_pagamento))return false;
    return true;
  }).sort((a,b)=>String(a.vencimento).localeCompare(String(b.vencimento))||String(a.id).localeCompare(String(b.id))).map(p=>{
    const d=dm[String(p.despesa_id)]||{},o=ob[String(p.id)],s=settle[String(p.id)],pending=!!o&&String(o.status||"").toUpperCase()==="OBRIGACAO",paid=!!o&&["QUITADO","PAGO"].includes(String(o.status||"").toUpperCase());
    return {id:p.id,despesa_id:p.despesa_id,descricao:d.descricao||"",categoria:d.categoria||"",subcategoria:d.subcategoria||"",data_compra:dateOnlyV181(d.data_compra),vencimento:dateOnlyV181(p.vencimento),
      valor:round2V181(p.valor),status:p.status,parcela:String(p.parcela_num)+"/"+String(p.total_parcelas),forma:d.forma_pagamento||"",can_edit:canEditAttendanceV181(user,d.data_compra),
      can_pay:String(p.status||"").toUpperCase()==="PREVISTO"&&String(user?.perfil||"").toUpperCase()==="ADMIN",can_settle_card:String(p.status||"").toUpperCase()==="PAGO"&&pending&&String(user?.perfil||"").toUpperCase()==="ADMIN",
      can_cancel:String(user?.perfil||"").toUpperCase()==="ADMIN",can_delete:String(user?.perfil||"").toUpperCase()==="ADMIN",
      card_obligation_pending:pending,card_obligation_paid:paid,card_settlement_account:s?.conta_financeira_nome||(paid?String(o?.conta_financeira_nome||""):"")};
  });
}
async function expenseGetV181(user:any,id:string){
  const d=await rowByIdV181("despesas",id);if(!d||String(d.status||"").toUpperCase()==="CANCELADO")throw new Error("Despesa não encontrada.");
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN"&&dateOnlyV181(d.data_compra)!==todayV181())throw new Error("Usuários podem acessar para edição somente despesas do dia.");
  const parcels=(await allRowsV181("despesa_parcelas")).filter(p=>String(p.despesa_id)===String(id)&&String(p.status||"").toUpperCase()!=="CANCELADO");
  return {id:d.id,descricao:d.descricao,data_compra:dateOnlyV181(d.data_compra),categoria:d.categoria,subcategoria:d.subcategoria||"",valor_total:round2V181(d.valor_total),forma_pagamento:d.forma_pagamento,
    qtd_parcelas:Number(d.qtd_parcelas||1),vencimento:dateOnlyV181(d.data_primeiro_vencimento),observacoes:d.observacoes||"",has_paid:parcels.some(p=>String(p.status||"").toUpperCase()==="PAGO"),
    can_edit:canEditAttendanceV181(user,d.data_compra),parcels:parcels.map(p=>({id:p.id,status:p.status,valor:round2V181(p.valor),vencimento:dateOnlyV181(p.vencimento)}))};
}
async function expenseSaveV181(user:any,payload:any){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Cadastro de despesas é exclusivo do administrador.");
  if(!payload?.descricao||numV181(payload.valor)<=0||!dateOnlyV181(payload.vencimento))throw new Error("Informe descrição, valor e vencimento.");
  const cat=await expenseCategoryResolveV181(payload.categoria,payload.subcategoria),qty=Math.max(1,Math.floor(numV181(payload.parcelas)||1)),rec=!!payload.recorrente,count=rec?Math.max(1,Math.floor(numV181(payload.recorrencia_meses)||12)):1;
  const expenses:any[]=[],parcels:any[]=[],cash:any[]=[],audit:any[]=[];
  for(let occ=0;occ<count;occ++){
    const id=uidV181("DES"),first=addMonthsRevenueV181(dateOnlyV181(payload.vencimento),occ),status=String(payload.status||"PREVISTO").toUpperCase()==="PAGO"?"PAGO":"PREVISTO";
    const d={id,descricao:String(payload.descricao)+(rec?" ["+(occ+1)+"/"+count+"]":""),data_compra:dateOnlyV181(payload.data_compra||todayV181()),categoria_id:null,categoria_despesa_id:cat.cat.id,subcategoria_despesa_id:cat.sub?.id||null,
      categoria:cat.cat.nome,subcategoria:cat.sub?.nome||"",valor_total:round2V181(payload.valor),forma_pagamento:String(payload.forma_pagamento||"Não informado"),qtd_parcelas:qty,data_primeiro_vencimento:first,status,
      recorrente:rec,recorrencia_meses:count,observacoes:String(payload.observacoes||""),origem:"SISTEMA",usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),editado_por:""};
    expenses.push(d);const ps=expenseParcelsBuildV181(d,status,payload.data_pagamento);parcels.push(...ps);
    if(status==="PAGO")for(const p of ps){const c=await expensePaymentCashV181(d,p,payload.conta_financeira_id,p.data_pagamento);cash.push(...c.cash);}
    audit.push(expenseAuditRowV181(user,"CRIAR",id,{descricao:d.descricao,total:d.valor_total,parcelas:qty}));
  }
  await expenseTxV181("CREATE_MULTI",{expenses,parcels,cash,audit},user);return {ok:true,ids:expenses.map(d=>d.id)};
}
async function expenseUpdateV181(user:any,payload:any){
  const d=await rowByIdV181("despesas",String(payload?.id||""));if(!d)throw new Error("Despesa não encontrada.");if(!canEditAttendanceV181(user,d.data_compra))throw new Error("Usuários podem editar somente despesas do período permitido.");
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN"&&dateOnlyV181(payload.data_compra||d.data_compra)!==todayV181())throw new Error("Usuários não podem mover a despesa para outra data.");
  const ps=(await allRowsV181("despesa_parcelas")).filter(p=>String(p.despesa_id)===String(d.id)&&String(p.status||"").toUpperCase()!=="CANCELADO"),hasPaid=ps.some(p=>String(p.status||"").toUpperCase()==="PAGO");
  const cat=await expenseCategoryResolveV181(payload.categoria||d.categoria,payload.subcategoria||""),financial={valor_total:round2V181(payload.valor_total),qtd_parcelas:Math.max(1,Math.floor(numV181(payload.qtd_parcelas)||1)),data_primeiro_vencimento:dateOnlyV181(payload.vencimento),forma_pagamento:String(payload.forma_pagamento||d.forma_pagamento)};
  const changed=Math.abs(financial.valor_total-numV181(d.valor_total))>0.01||financial.qtd_parcelas!==Number(d.qtd_parcelas||1)||financial.data_primeiro_vencimento!==dateOnlyV181(d.data_primeiro_vencimento)||financial.forma_pagamento!==String(d.forma_pagamento);
  if(hasPaid&&changed)throw new Error("Há parcela já paga. Valores, parcelas, vencimentos ou forma de pagamento não podem ser alterados.");
  const row={...d,descricao:String(payload.descricao||d.descricao),data_compra:dateOnlyV181(payload.data_compra||d.data_compra),categoria_id:null,categoria_despesa_id:cat.cat.id,subcategoria_despesa_id:cat.sub?.id||null,categoria:cat.cat.nome,subcategoria:cat.sub?.nome||"",
    observacoes:String(payload.observacoes||""),atualizado_em:nowIsoV181(),editado_por:user.nome,...(!hasPaid?financial:{})};
  const newParcels=changed&&!hasPaid?expenseParcelsBuildV181(row,"PREVISTO",null):[];
  await expenseTxV181("UPDATE",{expense:row,replace_parcels:changed&&!hasPaid,parcels:newParcels,audit:[expenseAuditRowV181(user,"ALTERAR",d.id,{antes:d,depois:row})]},user);return true;
}
async function expensePayV181(user:any,parcelId:string,paymentDate:any,accountId:any){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Pagamento de despesas é exclusivo do administrador.");
  const p=await rowByIdV181("despesa_parcelas",parcelId);if(!p||String(p.status||"").toUpperCase()==="CANCELADO")throw new Error("Parcela não encontrada.");if(String(p.status||"").toUpperCase()==="PAGO")throw new Error("Parcela já paga.");
  const d=await rowByIdV181("despesas",p.despesa_id);if(!d||String(d.status||"").toUpperCase()==="CANCELADO")throw new Error("Despesa não encontrada.");
  const date=dateOnlyV181(paymentDate||todayV181()),parcel={...p,status:"PAGO",data_pagamento:date,atualizado_em:nowIsoV181()},c=await expensePaymentCashV181(d,parcel,accountId,date);
  await expenseTxV181("PAY",{parcel,cash:c.cash,audit:[expenseAuditRowV181(user,"PAGAR_PARCELA",parcelId,{despesa_id:d.id,valor:p.valor,modo:c.mode})]},user);return {ok:true,mode:c.mode};
}
async function expenseSettleCardV181(user:any,parcelId:string,payload:any){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Quitação de cartão é exclusiva do administrador.");
  const mov=(await allRowsV181("mov_caixa")).find(m=>String(m.tipo||"").toUpperCase()==="OBRIGACAO_CARTAO_DESPESA"&&String(m.origem_id)===String(parcelId)&&String(m.status||"").toUpperCase()==="OBRIGACAO");
  if(!mov)throw new Error("Obrigação de cartão pendente não encontrada.");const acc=await rowByIdV181("contas_financeiras",String(payload?.conta_financeira_id||""));if(!acc||!isActiveV181(acc.ativo))throw new Error("Conta financeira inválida.");
  const p=await rowByIdV181("despesa_parcelas",parcelId),d=p?await rowByIdV181("despesas",p.despesa_id):null,date=dateOnlyV181(payload?.data||todayV181()),sid=uidV181("MOV");
  const cash=[{id:sid,data,competencia:dateOnlyV181(d?.data_compra||date),tipo:"QUITACAO_CARTAO_DESPESA",origem:"QUITACAO_DESPESA_CARTAO",origem_id:parcelId,descricao:"Quitação de cartão - "+String(d?.descricao||"Despesa"),
    valor:-Math.abs(round2V181(mov.valor)),status:"REALIZADO",forma_pagamento:mov.forma_pagamento||"",criado_em:nowIsoV181(),conta_financeira_id:acc.id,conta_financeira_nome:acc.nome,impacto_resultado:false,conciliado:false,conciliacao_id:"",movimento_financeiro_id:mov.id}];
  await expenseTxV181("SETTLE_CARD",{obligation_id:mov.id,settlement_id:sid,cash,audit:[expenseAuditRowV181(user,"QUITAR_CARTAO",parcelId,{valor:Math.abs(numV181(mov.valor)),conta:acc.nome})]},user);return true;
}
async function expenseCancelV181(user:any,id:string){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Cancelamento de despesas é exclusivo do administrador.");const d=await rowByIdV181("despesas",id);if(!d||String(d.status||"").toUpperCase()==="CANCELADO")throw new Error("Despesa não encontrada ou já cancelada.");
  await expenseTxV181("CANCEL",{expense_id:id,audit:[expenseAuditRowV181(user,"CANCELAR",id,{descricao:d.descricao,valor:d.valor_total})]},user);return true;
}
async function expenseDeleteV181(user:any,id:string){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Exclusão de despesas é exclusiva do administrador.");const d=await rowByIdV181("despesas",id);if(!d)throw new Error("Despesa não encontrada.");
  await expenseTxV181("DELETE",{expense_id:id,audit:[expenseAuditRowV181(user,"EXCLUIR",id,{descricao:d.descricao,valor:d.valor_total})]},user);return true;
}
// ============================= fim Despesas completas =============================


// ============================= v1.8.1 — Comissões / Vales =============================
async function commissionTxV181(action:string,payload:any,user:any){
  const r=await db.rpc("studio_commission_tx_v181",{p_action:action,p_payload:payload,p_user:{id:user?.id||"",nome:user?.nome||""}});
  if(r.error)throw new Error(r.error.message);return r.data;
}
function commissionAuditV181(user:any,action:string,id:string,details:any){
  return {id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user?.id||"SYSTEM",usuario_nome:user?.nome||"Sistema",acao:action,entidade:"COMISSAO",entidade_id:id,detalhes:JSON.stringify(details||{})};
}
async function accountForMethodV181(method:any){
  const forms=(await allRowsV181("formas_pagamento")).filter(f=>isActiveV181(f.ativo));
  const key=normalizeTextV181(method||""),form=forms.find(f=>String(f.id)===String(method))||forms.find(f=>normalizeTextV181(f.nome)===key)||forms.find(f=>normalizeTextV181(f.nome).includes(key)||key.includes(normalizeTextV181(f.nome)));
  if(form){try{return await paymentAccountAttendanceV181(form.id);}catch(_e){}}
  const accounts=(await allRowsV181("contas_financeiras")).filter(a=>isActiveV181(a.ativo));
  return accounts.find(a=>String(a.id)==="CF-NUBANK")||accounts.find(a=>normalizeTextV181(a.nome).includes("nubank"))||accounts[0]||null;
}
function commissionMoneyTextV181(v:any){return new Intl.NumberFormat("pt-BR",{style:"currency",currency:"BRL"}).format(numV181(v));}
function commissionDateBrV181(v:any){const s=dateOnlyV181(v);if(!s)return "";const [y,m,d]=s.split("-");return d+"/"+m+"/"+y;}
async function commissionMessageV181(id:string){
  const [c,items,adjs,uses,adv]=await Promise.all([rowByIdV181("comissoes_fechamentos",id),allRowsV181("comissoes_itens"),allRowsV181("comissoes_ajustes"),allRowsV181("vales_compensacoes"),allRowsV181("vales_adiantamentos")]);
  if(!c)return "";const its=items.filter(x=>String(x.fechamento_id)===String(id)),aa=adjs.filter(x=>String(x.fechamento_id)===String(id)),uu=uses.filter(x=>String(x.fechamento_id)===String(id)&&numV181(x.valor_compensado)>0),am:any={};adv.forEach(v=>am[String(v.id)]=v);
  const gross=c.valor_comissao_bruta!=null?round2V181(c.valor_comissao_bruta):round2V181(c.total_comissao),av=c.vales_descontados!=null?round2V181(c.vales_descontados):round2V181(uu.reduce((s,x)=>s+numV181(x.valor_compensado),0)),net=c.total_liquido!=null?round2V181(c.total_liquido):round2V181(c.total_comissao);
  let msg="Oi, "+String(c.profissional_nome||"")+"! 💕\n\nSegue seu fechamento de comissão do período "+commissionDateBrV181(c.periodo_inicio)+" a "+commissionDateBrV181(c.periodo_fim)+".\n\n";
  its.forEach(x=>{msg+=commissionDateBrV181(x.data_servico)+" — "+String(x.cliente_nome||"")+" — "+String(x.servico_nome||"")+"\nValor: "+commissionMoneyTextV181(x.valor_referencia)+" | Comissão: "+commissionMoneyTextV181(x.valor_comissao)+"\n\n";});
  if(aa.length){msg+="Ajustes:\n";aa.forEach(a=>msg+=(a.descricao||a.tipo)+": "+commissionMoneyTextV181(a.valor)+"\n");msg+="\n";}
  if(uu.length){msg+="Vales / adiantamentos descontados:\n";uu.forEach(x=>{const v=am[String(x.vale_id)]||{};msg+=(v.data?commissionDateBrV181(v.data)+" — ":"")+(v.observacoes||"Adiantamento")+": -"+commissionMoneyTextV181(x.valor_compensado)+"\n";});msg+="\n";}
  if(av>0)msg+="Comissão antes dos vales: "+commissionMoneyTextV181(gross)+"\nVales descontados: -"+commissionMoneyTextV181(av)+"\n";
  msg+="*Líquido a pagar: "+commissionMoneyTextV181(net)+"*\n\nStudio Essence 💕";return msg;
}
async function openAdvancesV181(profId:string,endDate:string){
  const end=dateOnlyV181(endDate||"2999-12-31"),rows=await allRowsV181("vales_adiantamentos");
  return rows.filter(v=>String(v.profissional_id)===String(profId)&&String(v.status||"ABERTO").toUpperCase()!=="CANCELADO"&&numV181(v.saldo_aberto)>0.005&&(!end||dateOnlyV181(v.data)<=end))
    .sort((a,b)=>String(a.data).localeCompare(String(b.data))).map(v=>({id:v.id,data:dateOnlyV181(v.data),valor_original:round2V181(v.valor_original),saldo:round2V181(v.saldo_aberto),observacoes:v.observacoes||""}));
}
async function commissionPreviewV181(payload:any){
  const profId=String(payload?.profissional_id||""),start=dateOnlyV181(payload?.start),end=dateOnlyV181(payload?.end);if(!profId||!start||!end)throw new Error("Selecione profissional e período.");
  const [atts,ai,sales,vi]=await Promise.all([allRowsV181("atendimentos"),allRowsV181("atendimento_itens"),allRowsV181("vendas"),allRowsV181("venda_itens")]),am:any={},sm:any={};atts.forEach(a=>am[String(a.id)]=a);sales.forEach(s=>sm[String(s.id)]=s);
  const service=ai.filter(i=>String(i.profissional_id)===profId&&String(i.comissao_status||"PENDENTE").toUpperCase()==="PENDENTE"&&attendanceRowActiveV181(i)).filter(i=>{const a=am[String(i.atendimento_id)];const d=dateOnlyV181(a?.data);return a&&String(a.status||"").toUpperCase()!=="CANCELADO"&&d>=start&&d<=end;}).map(i=>{const a=am[String(i.atendimento_id)];return {source_type:"SERVICO",item_id:i.id,data:dateOnlyV181(a.data),cliente:a.cliente_nome,descricao:i.servico_nome,valor_original:round2V181(i.valor_bruto),valor_referencia:round2V181(i.valor_referencia_comissao??i.valor_bruto),taxa:round2V181(i.taxa_considerada_comissao),valor_liquido:round2V181(i.valor_liquido),base:round2V181(i.base_comissao),percentual:numV181(i.percentual_comissao),comissao:round2V181(i.valor_comissao),informational:round2V181(i.valor_comissao)===0&&String(i.cortesia_tipo||"")!=""};});
  const sale=vi.filter(i=>String(i.profissional_id)===profId&&String(i.comissao_status||"").toUpperCase()==="PENDENTE"&&saleItemActiveV181(i)).filter(i=>{const s=sm[String(i.venda_id)];const d=dateOnlyV181(s?.data);return s&&String(s.status||"").toUpperCase()!=="CANCELADO"&&d>=start&&d<=end;}).map(i=>{const s=sm[String(i.venda_id)];return {source_type:"VENDA_PRODUTO",item_id:i.id,data:dateOnlyV181(s.data),cliente:s.cliente_nome||"Venda balcão",descricao:"Venda: "+i.produto_nome,valor_original:round2V181(i.valor_bruto),valor_referencia:round2V181(i.valor_bruto),taxa:round2V181(i.taxa_considerada_comissao),valor_liquido:round2V181(i.valor_liquido),base:round2V181(i.base_comissao),percentual:numV181(i.percentual_comissao),comissao:round2V181(i.valor_comissao),informational:false};});
  const items=service.concat(sale).sort((a,b)=>String(a.data).localeCompare(String(b.data)));return {items,total:round2V181(items.reduce((s,x)=>s+x.comissao,0)),advances:await openAdvancesV181(profId,end)};
}
async function commissionPrepareItemsV181(profId:string,items:any[]){
  const [ai,vi]=await Promise.all([allRowsV181("atendimento_itens"),allRowsV181("venda_itens")]),am:any={},vm:any={};ai.forEach(x=>am[String(x.id)]=x);vi.forEach(x=>vm[String(x.id)]=x);
  let serviceTotal=0,feeTotal=0,baseTotal=0,commissionTotal=0;const normalized:any[]=[];
  for(const x of items||[]){
    const source=String(x.source_type||"SERVICO"),original=source==="VENDA_PRODUTO"?vm[String(x.item_id)]:am[String(x.item_id)];
    if(!original)throw new Error("Item de comissão não encontrado.");if(String(original.profissional_id)!==String(profId))throw new Error("Há item de outra profissional na seleção.");
    if(String(original.comissao_status||"PENDENTE").toUpperCase()!=="PENDENTE")throw new Error("Há item já utilizado em outro fechamento.");if(!(source==="VENDA_PRODUTO"?saleItemActiveV181(original):attendanceRowActiveV181(original)))throw new Error("Há item editado/cancelado. Atualize a tela.");
    const informational=!!x.informational,value=informational?0:round2V181(x.valor_referencia),base=informational?0:round2V181(x.base),pct=informational?0:numV181(x.percentual),comm=informational?0:round2V181(base*pct),fee=informational?0:round2V181(x.taxa);
    serviceTotal+=value;feeTotal+=fee;baseTotal+=base;commissionTotal+=comm;normalized.push({source,original,value,base,pct,comm,fee,data:dateOnlyV181(x.data),cliente:x.cliente||"",descricao:x.descricao||"",informational,observacoes:x.observacoes||""});
  }
  return {normalized,serviceTotal:round2V181(serviceTotal),feeTotal:round2V181(feeTotal),baseTotal:round2V181(baseTotal),commissionTotal:round2V181(commissionTotal)};
}
async function commissionUseAdvancesV181(profId:string,gross:number,requested:any[],restored:any={}) {
  const all=await allRowsV181("vales_adiantamentos"),updates:any[]=[],inserts:any[]=[];let total=0;
  for(const req of requested||[]){if(total>=gross-0.005)break;const v=all.find(x=>String(x.id)===String(req.id)&&String(x.profissional_id)===String(profId));if(!v||String(v.status||"").toUpperCase()==="CANCELADO")continue;const balance=round2V181(numV181(v.saldo_aberto)+numV181(restored[String(v.id)]||0));if(balance<=0)continue;const use=round2V181(Math.min(Math.max(0,numV181(req.valor)),balance,gross-total));if(use<=0)continue;total=round2V181(total+use);const nb=round2V181(balance-use);updates.push({id:v.id,saldo_aberto:nb,status:nb<=0.005?"COMPENSADO":"PARCIAL"});inserts.push({id:uidV181("VAC"),vale_id:v.id,fechamento_id:"",profissional_id:profId,valor_compensado:use,criado_em:nowIsoV181()});}
  return {total,updates,inserts};
}
async function commissionSaveV181(user:any,payload:any){
  const prof=await rowByIdV181("profissionais",String(payload?.profissional_id||""));if(!prof)throw new Error("Profissional inválida.");if(!payload?.start||!payload?.end||!payload?.items?.length)throw new Error("Não há itens selecionados.");
  const prep=await commissionPrepareItemsV181(prof.id,payload.items),adjustments=(payload.adjustments||[]).map((a:any)=>({tipo:a.tipo||"AJUSTE",descricao:a.descricao||"",valor:round2V181(a.valor)})),adj=round2V181(adjustments.reduce((s:any,a:any)=>s+a.valor,0)),gross=round2V181(prep.commissionTotal+adj);if(gross<0)throw new Error("O total da comissão não pode ficar negativo.");
  const id=uidV181("COM"),adv=await commissionUseAdvancesV181(prof.id,gross,payload.advances||[]);adv.inserts.forEach(x=>x.fechamento_id=id);const net=round2V181(Math.max(0,gross-adv.total)),payNow=!!payload.payNow;
  const closing={id,profissional_id:prof.id,profissional_nome:prof.nome,periodo_inicio:dateOnlyV181(payload.start),periodo_fim:dateOnlyV181(payload.end),valor_servicos:prep.serviceTotal,taxas_consideradas:prep.feeTotal,base_total:prep.baseTotal,ajustes:adj,total_comissao:net,status:payNow?"PAGO":"CALCULADO",data_pagamento:payNow?dateOnlyV181(payload.payment_date||todayV181()):null,forma_pagamento:payNow?String(payload.payment_method||"Pix"):"",observacoes:String(payload.observacoes||""),usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),valor_comissao_bruta:gross,vales_descontados:adv.total,total_liquido:net};
  const itemIns=prep.normalized.map(x=>({id:uidV181("COI"),fechamento_id:id,atendimento_item_id:x.source==="SERVICO"?x.original.id:"",data_servico:x.data,cliente_nome:x.cliente,servico_nome:x.descricao,valor_original:round2V181(x.original.valor_bruto),valor_referencia:x.value,taxa_considerada:x.fee,valor_liquido:round2V181(x.original.valor_liquido),base_comissao:x.base,percentual:x.pct,valor_comissao:x.comm,editado:Math.abs(x.value-numV181(x.original.valor_bruto))>0.01||Math.abs(x.base-numV181(x.original.base_comissao))>0.01||Math.abs(x.pct-numV181(x.original.percentual_comissao))>0.0001,observacoes:x.observacoes,origem_tipo:x.source,origem_item_id:x.original.id}));
  const attUpd=prep.normalized.filter(x=>x.source!=="VENDA_PRODUTO").map(x=>({id:x.original.id,comissao_status:payNow?"PAGO":"FECHADO"})),saleUpd=prep.normalized.filter(x=>x.source==="VENDA_PRODUTO").map(x=>({id:x.original.id,comissao_status:payNow?"PAGO":"FECHADO"})),adjIns=adjustments.map(a=>({id:uidV181("COA"),fechamento_id:id,tipo:a.tipo,descricao:a.descricao,valor:a.valor,criado_em:nowIsoV181()})),cash:any[]=[];
  if(payNow&&net>0){const acc=await accountForMethodV181(payload.payment_method||"Pix");if(!acc)throw new Error("Não há conta financeira para o pagamento da comissão.");cash.push({id:uidV181("MOV"),data:dateOnlyV181(payload.payment_date||todayV181()),competencia:dateOnlyV181(payload.end),tipo:"COMISSAO",origem:"COMISSAO",origem_id:id,descricao:"Comissão - "+prof.nome,valor:-net,status:"REALIZADO",forma_pagamento:String(payload.payment_method||"Pix"),criado_em:nowIsoV181(),conta_financeira_id:acc.id,conta_financeira_nome:acc.nome,impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""});}
  await commissionTxV181("CREATE_CLOSING",{closing,commission_item_inserts:itemIns,adjustment_inserts:adjIns,advance_updates:adv.updates,compensation_inserts:adv.inserts,attendance_updates:attUpd,sale_updates:saleUpd,cash,audit:[commissionAuditV181(user,payNow?"FECHAR_E_PAGAR":"FECHAR",id,{profissional:prof.nome,bruto:gross,vales:adv.total,liquido:net,itens:itemIns.length})]},user);
  return {ok:true,id,total:net,gross,advances:adv.total,message:await commissionMessageV181(id)};
}
async function commissionHistoryV181(filters:any){
  filters=filters||{};const rows=await allRowsV181("comissoes_fechamentos"),out:any[]=[];
  for(const c of rows.filter(c=>(!filters.profissional_id||String(c.profissional_id)===String(filters.profissional_id))&&(!filters.start||dateOnlyV181(c.periodo_fim)>=dateOnlyV181(filters.start))&&(!filters.end||dateOnlyV181(c.periodo_inicio)<=dateOnlyV181(filters.end))).sort((a,b)=>String(b.criado_em||"").localeCompare(String(a.criado_em||"")))){
    const gross=c.valor_comissao_bruta!=null?round2V181(c.valor_comissao_bruta):round2V181(c.total_comissao),vales=c.vales_descontados!=null?round2V181(c.vales_descontados):0,net=c.total_liquido!=null?round2V181(c.total_liquido):round2V181(c.total_comissao);
    out.push({id:c.id,profissional_id:c.profissional_id,profissional:c.profissional_nome,inicio:dateOnlyV181(c.periodo_inicio),fim:dateOnlyV181(c.periodo_fim),bruto:gross,vales,total:net,status:c.status,data_pagamento:dateOnlyV181(c.data_pagamento),forma:c.forma_pagamento||"",message:await commissionMessageV181(c.id)});
  }return out;
}
async function commissionHistoryProfessionalsV181(){
  const [closings,profs]=await Promise.all([allRowsV181("comissoes_fechamentos"),allRowsV181("profissionais")]),pm:any={};profs.forEach(p=>pm[String(p.id)]=p);const ids=[...new Set(closings.map(c=>String(c.profissional_id||"")).filter(Boolean))];
  return ids.map(id=>({id,nome:pm[id]?.nome||closings.find(c=>String(c.profissional_id)===id)?.profissional_nome||id})).sort((a,b)=>String(a.nome).localeCompare(String(b.nome),"pt-BR"));
}
async function commissionGetClosingV181(id:string){
  const c=await rowByIdV181("comissoes_fechamentos",id);if(!c)throw new Error("Fechamento não encontrado.");if(String(c.status||"").toUpperCase()==="PAGO")throw new Error("Fechamento pago não pode ser editado.");
  const [items,adjs,uses,adv]=await Promise.all([allRowsV181("comissoes_itens"),allRowsV181("comissoes_ajustes"),allRowsV181("vales_compensacoes"),allRowsV181("vales_adiantamentos")]),am:any={};adv.forEach(v=>am[String(v.id)]=v);
  const its=items.filter(x=>String(x.fechamento_id)===id).map(x=>({source_type:x.origem_tipo||"SERVICO",item_id:x.origem_item_id||x.atendimento_item_id,data:dateOnlyV181(x.data_servico),cliente:x.cliente_nome,descricao:x.servico_nome,valor_original:round2V181(x.valor_original),valor_referencia:round2V181(x.valor_referencia),taxa:round2V181(x.taxa_considerada),valor_liquido:round2V181(x.valor_liquido),base:round2V181(x.base_comissao),percentual:numV181(x.percentual),comissao:round2V181(x.valor_comissao),informational:round2V181(x.valor_comissao)===0&&normalizeTextV181(x.observacoes).includes("cortesia"),observacoes:x.observacoes||""}));
  const aa=adjs.filter(x=>String(x.fechamento_id)===id),uu=uses.filter(x=>String(x.fechamento_id)===id&&numV181(x.valor_compensado)>0).map(x=>{const v=am[String(x.vale_id)]||{};return {id:x.vale_id,data:dateOnlyV181(v.data),observacoes:v.observacoes||"Vale / adiantamento",saldo:round2V181(numV181(v.saldo_aberto)+numV181(x.valor_compensado)),used:round2V181(x.valor_compensado)};});
  return {id:c.id,profissional_id:c.profissional_id,start:dateOnlyV181(c.periodo_inicio),end:dateOnlyV181(c.periodo_fim),items:its,advances:uu,adjustment:round2V181(aa.reduce((s,a)=>s+numV181(a.valor),0)),adjustment_desc:aa.map(a=>a.descricao||a.tipo).filter(Boolean).join(" / ")};
}
async function commissionUpdateClosingV181(user:any,payload:any){
  const c=await rowByIdV181("comissoes_fechamentos",String(payload?.id||""));if(!c)throw new Error("Fechamento não encontrado.");if(String(c.status||"").toUpperCase()==="PAGO")throw new Error("Fechamento pago não pode ser editado.");
  const [rows,adjs,comps,advances]=await Promise.all([allRowsV181("comissoes_itens"),allRowsV181("comissoes_ajustes"),allRowsV181("vales_compensacoes"),allRowsV181("vales_adiantamentos")]),existing=rows.filter(x=>String(x.fechamento_id)===String(c.id)),emap:any={};existing.forEach(x=>emap[String(x.origem_item_id||x.atendimento_item_id)]=x);
  if(!(payload.items||[]).length||payload.items.length!==existing.length)throw new Error("Na edição ajuste somente os itens já salvos.");
  let service=0,fees=0,base=0,comm=0;const itemUpdates:any[]=[];
  for(const x of payload.items){const old=emap[String(x.item_id)];if(!old)throw new Error("Na edição só é permitido ajustar itens já salvos.");const info=!!x.informational,v=info?0:round2V181(x.valor_referencia),b=info?0:round2V181(x.base),pct=info?0:numV181(x.percentual),co=info?0:round2V181(b*pct),fee=info?0:round2V181(x.taxa);service+=v;fees+=fee;base+=b;comm+=co;itemUpdates.push({id:old.id,valor_referencia:v,taxa_considerada:fee,base_comissao:b,percentual:pct,valor_comissao:co,editado:true,observacoes:x.observacoes||old.observacoes||""});}
  const adjustment=round2V181(payload.adjustment),gross=round2V181(comm+adjustment);if(gross<0)throw new Error("O total da comissão não pode ficar negativo.");
  const oldUses=comps.filter(x=>String(x.fechamento_id)===String(c.id)&&numV181(x.valor_compensado)>0),restored:any={},compUpdates:any[]=[];oldUses.forEach(x=>{restored[String(x.vale_id)]=(restored[String(x.vale_id)]||0)+numV181(x.valor_compensado);compUpdates.push({id:x.id,valor_compensado:0});});
  const adv=await commissionUseAdvancesV181(c.profissional_id,gross,payload.advances||[],restored);adv.inserts.forEach(x=>x.fechamento_id=c.id);
  const advUpdateMap:any={};for(const v of advances){const r=numV181(restored[String(v.id)]||0);if(r>0)advUpdateMap[String(v.id)]={id:v.id,saldo_aberto:round2V181(numV181(v.saldo_aberto)+r),status:"ABERTO"};}for(const u of adv.updates)advUpdateMap[String(u.id)]=u;
  const net=round2V181(Math.max(0,gross-adv.total)),closing={...c,valor_servicos:round2V181(service),taxas_consideradas:round2V181(fees),base_total:round2V181(base),ajustes:adjustment,total_comissao:net,valor_comissao_bruta:gross,vales_descontados:adv.total,total_liquido:net};
  const currentAdj=adjs.filter(x=>String(x.fechamento_id)===String(c.id)),adjUpdates:any[]=[],adjInserts:any[]=[];if(currentAdj.length){currentAdj.forEach((a,i)=>adjUpdates.push({id:a.id,valor:i===0?adjustment:0,descricao:i===0?(payload.adjustment_desc||"Ajuste manual"):a.descricao}));}else if(Math.abs(adjustment)>0.004)adjInserts.push({id:uidV181("COA"),fechamento_id:c.id,tipo:adjustment<0?"DESCONTO":"BONUS",descricao:payload.adjustment_desc||"Ajuste manual",valor:adjustment,criado_em:nowIsoV181()});
  await commissionTxV181("UPDATE_CLOSING",{closing,commission_item_updates:itemUpdates,adjustment_updates:adjUpdates,adjustment_inserts:adjInserts,advance_updates:Object.values(advUpdateMap),compensation_updates:compUpdates,compensation_inserts:adv.inserts,audit:[commissionAuditV181(user,"ALTERAR",c.id,{bruto:gross,vales:adv.total,liquido:net})]},user);
  return {ok:true,id:c.id,total:net,message:await commissionMessageV181(c.id)};
}
async function commissionPayV181(user:any,id:string,date:any,method:any){
  const c=await rowByIdV181("comissoes_fechamentos",id);if(!c)throw new Error("Fechamento não encontrado.");if(String(c.status||"").toUpperCase()==="PAGO")throw new Error("Esta comissão já foi paga.");
  const rows=(await allRowsV181("comissoes_itens")).filter(x=>String(x.fechamento_id)===id),att:any[]=[],sale:any[]=[];rows.forEach(x=>{const source=String(x.origem_tipo||"SERVICO"),iid=x.origem_item_id||x.atendimento_item_id;if(!iid)return;(source==="VENDA_PRODUTO"?sale:att).push({id:iid,comissao_status:"PAGO"});});
  const net=round2V181(c.total_liquido!=null?c.total_liquido:c.total_comissao),payDate=dateOnlyV181(date||todayV181()),payMethod=String(method||"Pix"),closing={...c,status:"PAGO",data_pagamento:payDate,forma_pagamento:payMethod},cash:any[]=[];
  if(net>0){const acc=await accountForMethodV181(payMethod);if(!acc)throw new Error("Não há conta financeira para o pagamento da comissão.");cash.push({id:uidV181("MOV"),data:payDate,competencia:dateOnlyV181(c.periodo_fim),tipo:"COMISSAO",origem:"COMISSAO",origem_id:id,descricao:"Comissão - "+c.profissional_nome,valor:-net,status:"REALIZADO",forma_pagamento:payMethod,criado_em:nowIsoV181(),conta_financeira_id:acc.id,conta_financeira_nome:acc.nome,impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""});}
  await commissionTxV181("PAY_CLOSING",{closing,attendance_updates:att,sale_updates:sale,cash,audit:[commissionAuditV181(user,"PAGAR",id,{total:net})]},user);return {ok:true,message:await commissionMessageV181(id)};
}
async function advanceListV181(filters:any){
  filters=filters||{};const [rows,comps]=await Promise.all([allRowsV181("vales_adiantamentos"),allRowsV181("vales_compensacoes")]);
  return rows.filter(v=>(!filters.profissional_id||String(v.profissional_id)===String(filters.profissional_id))&&(!filters.start||dateOnlyV181(v.data)>=dateOnlyV181(filters.start))&&(!filters.end||dateOnlyV181(v.data)<=dateOnlyV181(filters.end))).sort((a,b)=>String(b.data).localeCompare(String(a.data))||String(b.criado_em||"").localeCompare(String(a.criado_em||""))).map(v=>({id:v.id,profissional_id:v.profissional_id,profissional:v.profissional_nome,data:dateOnlyV181(v.data),valor:round2V181(v.valor_original),saldo:round2V181(v.saldo_aberto),compensado:round2V181(comps.filter(c=>String(c.vale_id)===String(v.id)).reduce((s,c)=>s+numV181(c.valor_compensado),0)),status:v.status||"ABERTO",observacoes:v.observacoes||""}));
}
async function advanceSaveV181(user:any,payload:any){
  const prof=await rowByIdV181("profissionais",String(payload?.profissional_id||"")),value=round2V181(payload?.valor),date=dateOnlyV181(payload?.data||todayV181());if(!prof||!isActiveV181(prof.ativo))throw new Error("Selecione uma profissional ativa.");if(value<=0)throw new Error("Informe um valor maior que zero.");
  const id=uidV181("VAL"),row={id,profissional_id:prof.id,profissional_nome:prof.nome,data,valor_original:value,saldo_aberto:value,status:"ABERTO",observacoes:String(payload?.observacoes||""),usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),cancelado_em:null,cancelado_por:""},acc=await accountForMethodV181(payload?.forma_pagamento||"Pix");if(!acc)throw new Error("Conta financeira não encontrada.");
  const cash=[{id:uidV181("MOV"),data,competencia:date,tipo:"ADIANTAMENTO_PROFISSIONAL",origem:"VALE",origem_id:id,descricao:"Vale / Adiantamento - "+prof.nome,valor:-value,status:"REALIZADO",forma_pagamento:String(payload?.forma_pagamento||"Pix"),criado_em:nowIsoV181(),conta_financeira_id:acc.id,conta_financeira_nome:acc.nome,impacto_resultado:false,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""}];
  await commissionTxV181("ADVANCE_CREATE",{advance:row,cash,audit:[{id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user.id,usuario_nome:user.nome,acao:"CRIAR",entidade:"VALE_ADIANTAMENTO",entidade_id:id,detalhes:JSON.stringify({profissional:prof.nome,valor:value,data})}]},user);return {ok:true,id};
}
async function advanceCancelV181(user:any,id:string){
  const v=await rowByIdV181("vales_adiantamentos",id);if(!v||String(v.status||"").toUpperCase()==="CANCELADO")throw new Error("Vale/adiantamento não encontrado ou já cancelado.");const used=(await allRowsV181("vales_compensacoes")).filter(c=>String(c.vale_id)===id).reduce((s,c)=>s+numV181(c.valor_compensado),0);if(used>0.005)throw new Error("Este vale já foi utilizado em fechamento de comissão e não pode ser cancelado.");
  const cash=(await allRowsV181("mov_caixa")).filter(m=>String(m.origem)==="VALE"&&String(m.origem_id)===id&&String(m.status||"").toUpperCase()==="REALIZADO").map(m=>({id:m.id,status:"ESTORNADO"})),row={...v,saldo_aberto:0,status:"CANCELADO",cancelado_em:nowIsoV181(),cancelado_por:user.nome,atualizado_em:nowIsoV181()};
  await commissionTxV181("ADVANCE_CANCEL",{advance:row,cash_status_updates:cash,audit:[{id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user.id,usuario_nome:user.nome,acao:"CANCELAR",entidade:"VALE_ADIANTAMENTO",entidade_id:id,detalhes:JSON.stringify({valor:v.valor_original,profissional:v.profissional_nome})}]},user);return true;
}
// ============================= fim Comissões / Vales =============================


// ============================= v1.8.1 — Ativos completos =============================
function assetMonthsV181(from:any,to:any){
  const a=dateOnlyV181(from),b=dateOnlyV181(to);if(!a||!b)return 0;
  const [ay,am,ad]=a.split("-").map(Number),[by,bm,bd]=b.split("-").map(Number);
  return Math.max(0,(by-ay)*12+(bm-am)-(bd<ad?1:0));
}
function assetCalcV181(a:any,date:any=todayV181()){
  const base=Math.max(0,numV181(a.valor_base_inicial)),residual=Math.max(0,Math.min(base,numV181(a.valor_residual))),life=Math.max(1,Math.floor(numV181(a.vida_util_remanescente_meses)||1)),elapsed=Math.min(life,assetMonthsV181(a.data_base,date));
  const dep=round2V181(Math.min(base-residual,(base-residual)/life*elapsed)),current=round2V181(Math.max(residual,base-dep)),remaining=Math.max(0,life-elapsed);
  return {valor_atual:current,depreciacao_acumulada:dep,vida_restante_meses:remaining};
}
function assetAuditV181(user:any,action:string,id:string,details:any){return {id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user.id,usuario_nome:user.nome,acao:action,entidade:"ATIVO",entidade_id:id,detalhes:JSON.stringify(details||{})};}
async function assetTxV181(action:string,payload:any,user:any){const r=await db.rpc("studio_asset_tx_v181",{p_action:action,p_payload:payload,p_user:{id:user.id,nome:user.nome}});if(r.error)throw new Error(r.error.message);return r.data;}
async function assetDomainsV181(){
  const cats=(await allRowsV181("categorias_ativos")).filter(c=>isActiveV181(c.ativo)).sort((a,b)=>String(a.nome).localeCompare(String(b.nome),"pt-BR"));
  return {categories:cats.map(c=>({id:c.id,nome:c.nome,vida_util_meses_padrao:Number(c.vida_util_meses_padrao||60),residual_percentual_padrao:numV181(c.residual_percentual_padrao)}))};
}
async function assetListV181(filters:any){
  filters=filters||{};let rows=await allRowsV181("ativos");
  const q=normalizeTextV181(filters.q||""),cat=normalizeTextV181(filters.categoria||""),status=String(filters.status||"").toUpperCase();
  if(q)rows=rows.filter(a=>normalizeTextV181([a.nome,a.marca_modelo,a.categoria,a.observacoes].join(" ")).includes(q));
  if(cat)rows=rows.filter(a=>normalizeTextV181(a.categoria)===cat);
  if(status)rows=rows.filter(a=>String(a.status||"").toUpperCase()===status);
  const mapped=rows.map(a=>({...a,...assetCalcV181(a),quantidade:round2V181(a.quantidade),valor_pago_historico:round2V181(a.valor_pago_historico),valor_mercado_aquisicao:round2V181(a.valor_mercado_aquisicao),valor_base_inicial:round2V181(a.valor_base_inicial),valor_residual_percentual:round2V181(a.valor_residual_percentual),valor_residual:round2V181(a.valor_residual),data_base:dateOnlyV181(a.data_base)}))
    .sort((a,b)=>String(a.nome).localeCompare(String(b.nome),"pt-BR"));
  const active=mapped.filter(a=>!["VENDIDO","BAIXADO"].includes(String(a.status||"").toUpperCase()));
  return {summary:{quantidade:round2V181(active.reduce((s,a)=>s+numV181(a.quantidade),0)),valor_base:round2V181(active.reduce((s,a)=>s+numV181(a.valor_base_inicial),0)),valor_atual:round2V181(active.reduce((s,a)=>s+numV181(a.valor_atual),0)),vendidos:round2V181(mapped.filter(a=>String(a.status||"").toUpperCase()==="VENDIDO").reduce((s,a)=>s+Math.max(1,numV181(a.quantidade)),0))},rows:mapped};
}
async function assetGetV181(id:string){const a=await rowByIdV181("ativos",id);if(!a)throw new Error("Ativo não encontrado.");return {...a,...assetCalcV181(a),data_base:dateOnlyV181(a.data_base)};}
async function assetSaveV181(user:any,payload:any){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Gestão de ativos é exclusiva do administrador.");
  const existing=payload?.id?await rowByIdV181("ativos",String(payload.id)):null,cats=await allRowsV181("categorias_ativos"),cat=cats.find(c=>String(c.id)===String(payload?.categoria_ativo_id)&&isActiveV181(c.ativo));
  if(!cat)throw new Error("Selecione uma categoria do ativo.");const qty=Math.max(1,Math.floor(numV181(payload?.quantidade)||1)),base=round2V181(payload?.valor_base_inicial),resPct=Math.max(0,Math.min(100,numV181(payload?.valor_residual_percentual))),id=existing?.id||uidV181("ATV");
  if(!String(payload?.nome||"").trim())throw new Error("Informe o nome do ativo.");if(base<0)throw new Error("Valor-base inválido.");
  const row={id,nome:titleV181(payload.nome),categoria_ativo_id:cat.id,categoria:cat.nome,marca_modelo:String(payload.marca_modelo||""),quantidade:qty,origem:String(payload.origem||"STUDIO"),data_base:dateOnlyV181(payload.data_base||todayV181()),valor_pago_historico:round2V181(payload.valor_pago_historico),valor_mercado_aquisicao:round2V181(payload.valor_mercado_aquisicao),valor_base_inicial:base,vida_util_remanescente_meses:Math.max(1,Math.floor(numV181(payload.vida_util_remanescente_meses)||Number(cat.vida_util_meses_padrao||60))),valor_residual_percentual:resPct,valor_residual:round2V181(base*resPct/100),status:String(payload.status||"EM_USO").toUpperCase(),observacoes:String(payload.observacoes||""),substituido_por_id:existing?.substituido_por_id||null,criado_em:existing?.criado_em||nowIsoV181(),atualizado_em:nowIsoV181(),editado_por:user.nome};
  const movements=existing?[]:[{id:uidV181("ATM"),ativo_id:id,data:row.data_base,tipo:"ENTRADA",descricao:"Cadastro do ativo",valor:base,comprador:null,forma_pagamento:null,ativo_relacionado_id:null,usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181()}];
  await assetTxV181("SAVE",{asset:row,movements,audit:[assetAuditV181(user,existing?"ALTERAR":"CRIAR",id,{nome:row.nome,quantidade:qty,valor_base:base})]},user);return {ok:true,id};
}
async function assetHistoryV181(id:string){
  const asset=await assetGetV181(id),rows=(await allRowsV181("ativos_movimentos")).filter(m=>String(m.ativo_id)===String(id)).sort((a,b)=>String(b.data).localeCompare(String(a.data))||String(b.criado_em||"").localeCompare(String(a.criado_em||"")));
  return {asset,rows:rows.map(m=>({data:dateOnlyV181(m.data),tipo:m.tipo,descricao:m.descricao||"",valor:round2V181(m.valor),comprador:m.comprador||"",forma_pagamento:m.forma_pagamento||"",ativo_relacionado_id:m.ativo_relacionado_id||""}))};
}
async function assetImportListV181(){
  return (await allRowsV181("ativos_importacao")).filter(x=>!boolV181(x.importado,false)).sort((a,b)=>numV181(a.linha_origem)-numV181(b.linha_origem)).map(x=>({...x,quantidade:round2V181(x.quantidade),valor_pago_historico:round2V181(x.valor_pago_historico),valor_mercado:round2V181(x.valor_mercado),vida_util_meses_sugerida:Number(x.vida_util_meses_sugerida||60),residual_percentual_sugerido:round2V181(x.residual_percentual_sugerido),importar_sugerido:boolV181(x.importar_sugerido,true)}));
}
async function assetImportV181(user:any,ids:any[]){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Importação de ativos é exclusiva do administrador.");
  const wanted=(ids||[]).map(String),pending=(await allRowsV181("ativos_importacao")).filter(x=>wanted.includes(String(x.id))&&!boolV181(x.importado,false)),cats=(await allRowsV181("categorias_ativos")).filter(c=>isActiveV181(c.ativo)),assets:any[]=[],movements:any[]=[],updates:any[]=[],audit:any[]=[];
  for(const x of pending){const cat=cats.find(c=>normalizeTextV181(c.nome)===normalizeTextV181(x.categoria_sugerida))||cats[0];if(!cat)throw new Error("Não há categoria ativa para importar ativos.");const id=uidV181("ATV"),base=round2V181(x.valor_mercado),resPct=numV181(x.residual_percentual_sugerido||cat.residual_percentual_padrao),date="2026-08-01";
    const a={id,nome:titleV181(x.item||"Ativo"),categoria_ativo_id:cat.id,categoria:cat.nome,marca_modelo:"",quantidade:Math.max(1,numV181(x.quantidade)),origem:"AQUISICAO_ESTABELECIMENTO",data_base:date,valor_pago_historico:round2V181(x.valor_pago_historico),valor_mercado_aquisicao:base,valor_base_inicial:base,vida_util_remanescente_meses:Math.max(1,Number(x.vida_util_meses_sugerida||cat.vida_util_meses_padrao||60)),valor_residual_percentual:resPct,valor_residual:round2V181(base*resPct/100),status:String(x.status_sugerido||"EM_USO"),observacoes:String(x.observacoes||""),substituido_por_id:null,criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),editado_por:user.nome};
    assets.push(a);movements.push({id:uidV181("ATM"),ativo_id:id,data:date,tipo:"ENTRADA_INVENTARIO",descricao:"Entrada no inventário por aquisição do estabelecimento",valor:base,comprador:null,forma_pagamento:null,ativo_relacionado_id:null,usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181()});updates.push({id:x.id,ativo_id:id});audit.push(assetAuditV181(user,"IMPORTAR",id,{origem_importacao:x.id,nome:a.nome,valor_base:base}));}
  await assetTxV181("IMPORT",{assets,movements,import_updates:updates,audit},user);return {ok:true,created:assets.length};
}
async function assetDeleteImportV181(user:any,ids:any[]){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Exclusão da fila é exclusiva do administrador.");const before=(await allRowsV181("ativos_importacao")).filter(x=>(ids||[]).map(String).includes(String(x.id))&&!boolV181(x.importado,false));
  await assetTxV181("DELETE_IMPORT",{import_ids:(ids||[]).map(String),audit:[assetAuditV181(user,"EXCLUIR_IMPORTACAO","FILA",{ids:before.map(x=>x.id),deleted:before.length})]},user);return {ok:true,deleted:before.length};
}
async function assetDisposeV181(user:any,payload:any,kind:string){
  if(String(user?.perfil||"").toUpperCase()!=="ADMIN")throw new Error("Operação de ativos é exclusiva do administrador.");
  const a=await rowByIdV181("ativos",String(payload?.id||""));if(!a||["VENDIDO","BAIXADO"].includes(String(a.status||"").toUpperCase()))throw new Error("Ativo não disponível.");
  const currentQty=numV181(a.quantidade),qty=Math.max(1,Math.floor(numV181(payload?.quantidade)||1));if(qty>currentQty)throw new Error("Quantidade superior ao saldo do ativo.");
  const date=dateOnlyV181(payload?.data||todayV181()),calc=assetCalcV181(a,date),ratio=qty/currentQty,disposedCurrent=round2V181(calc.valor_atual*ratio),remaining=currentQty-qty;
  const row={...a,quantidade:round2V181(remaining),valor_pago_historico:round2V181(numV181(a.valor_pago_historico)*(1-ratio)),valor_mercado_aquisicao:round2V181(numV181(a.valor_mercado_aquisicao)*(1-ratio)),valor_base_inicial:round2V181(numV181(a.valor_base_inicial)*(1-ratio)),valor_residual:round2V181(numV181(a.valor_residual)*(1-ratio)),status:remaining<=0?(kind==="SELL"?"VENDIDO":"BAIXADO"):String(a.status||"EM_USO"),substituido_por_id:payload?.ativo_relacionado_id||a.substituido_por_id||null,atualizado_em:nowIsoV181(),editado_por:user.nome};
  const movements:any[]=[],revenues:any[]=[],revenue_parcels:any[]=[],cash:any[]=[];
  if(kind==="WRITEOFF"){
    movements.push({id:uidV181("ATM"),ativo_id:a.id,data:date,tipo:remaining<=0?"BAIXA":"BAIXA_PARCIAL",descricao:(remaining<=0?"Baixa total":"Baixa parcial - "+qty+" de "+currentQty+" unidade(s)")+(payload?.motivo?" · "+payload.motivo:""),valor:disposedCurrent,comprador:null,forma_pagamento:null,ativo_relacionado_id:null,usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181()});
  }else{
    const value=round2V181(payload?.valor);if(value<=0)throw new Error("Informe o valor da venda do ativo.");const forms=(await allRowsV181("formas_pagamento")).filter(f=>isActiveV181(f.ativo)),form=forms.find(f=>String(f.id)===String(payload?.forma_pagamento))||forms.find(f=>normalizeTextV181(f.nome)===normalizeTextV181(payload?.forma_pagamento));if(!form)throw new Error("Forma de pagamento inválida.");
    const rate=await resolveRateAttendanceV181(form.id,date,{}),fee=round2V181(value*numV181(rate.percentual)+numV181(rate.taxa_fixa)),account=await paymentAccountAttendanceV181(form.id),rid=uidV181("REC"),pid=uidV181("RCP");
    movements.push({id:uidV181("ATM"),ativo_id:a.id,data:date,tipo:remaining<=0?"VENDA":"VENDA_PARCIAL",descricao:(remaining<=0?"Venda do ativo":"Venda parcial - "+qty+" de "+currentQty+" unidade(s)")+(payload?.observacoes?" · "+payload.observacoes:""),valor:value,comprador:String(payload?.comprador||""),forma_pagamento:form.nome,ativo_relacionado_id:payload?.ativo_relacionado_id||null,usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181()});
    revenues.push({id:rid,descricao:"Venda de ativo - "+a.nome,cliente_id:"",cliente_nome:String(payload?.comprador||""),data_competencia:date,categoria_receita_id:"CRV-F87D13E6",subcategoria_receita_id:null,categoria:"Outras Receitas",subcategoria:"",natureza:"OPERACIONAL",valor_total:value,forma_id:form.id,forma_pagamento:form.nome,qtd_parcelas:1,data_primeiro_recebimento:date,status:"RECEBIDA",recorrente:false,recorrencia_meses:1,observacoes:String(payload?.observacoes||""),origem:"ATIVO",usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),editado_por:"",excluido:false});
    revenue_parcels.push({id:pid,receita_id:rid,parcela_num:1,total_parcelas:1,vencimento:date,valor_bruto:value,taxa_percentual:numV181(rate.percentual),taxa_fixa:numV181(rate.taxa_fixa),valor_taxa:fee,valor_liquido:round2V181(value-fee),status:"RECEBIDA",data_recebimento:date,criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),mov_caixa_id:null});
    cash.push({id:uidV181("MOV"),data:date,competencia:date,tipo:"RECEITA_ATIVO",origem:"ATIVO",origem_id:a.id,descricao:"Venda de ativo - "+a.nome,valor:value,status:"REALIZADO",forma_pagamento:form.nome,criado_em:nowIsoV181(),conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""});
    if(fee>0)cash.push({id:uidV181("MOV"),data:date,competencia:date,tipo:"TAXA_FINANCEIRA",origem:"ATIVO",origem_id:a.id,descricao:"Taxa "+form.nome+" - venda de ativo",valor:-fee,status:"REALIZADO",forma_pagamento:form.nome,criado_em:nowIsoV181(),conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""});
  }
  await assetTxV181(kind,{asset:row,movements,revenues,revenue_parcels,cash,audit:[assetAuditV181(user,kind==="SELL"?"VENDER":"BAIXAR",a.id,{quantidade:qty,restante:remaining,valor_referencia:disposedCurrent,valor_venda:kind==="SELL"?round2V181(payload.valor):0})]},user);return {ok:true,id:a.id,remaining};
}
// ============================= fim Ativos completos =============================


// ============================= v1.8.1 — Financeiro / Conciliação =============================
function financialAuditV181(user:any,action:string,entity:string,id:string,details:any){return {id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user.id,usuario_nome:user.nome,acao:action,entidade:entity,entidade_id:id,detalhes:JSON.stringify(details||{})};}
async function financialOpV181(action:string,payload:any,user:any){const r=await db.rpc("studio_financial_ops_v181",{p_action:action,p_payload:payload,p_user:{id:user.id,nome:user.nome}});if(r.error)throw new Error(r.error.message);return r.data;}
async function cardReceivablesV181(filters:any){
  filters=filters||{};return (await allRowsV181("recebiveis_cartao")).filter(r=>!filters.status||String(r.status||"").toUpperCase()===String(filters.status).toUpperCase()).sort((a,b)=>String(b.data_venda).localeCompare(String(a.data_venda))||String(b.criado_em||"").localeCompare(String(a.criado_em||""))).map(r=>({id:r.id,origem_tipo:r.origem_tipo||"",origem_pagamento_id:r.origem_pagamento_id||"",origem_id:r.origem_id||"",data_venda:dateOnlyV181(r.data_venda),forma_id:r.forma_id||"",forma_pagamento:r.forma_pagamento||"",valor_bruto:round2V181(r.valor_bruto),taxa_estimada:round2V181(r.taxa_estimada),liquido_estimado:round2V181(r.liquido_estimado),conta_origem_id:r.conta_origem_id||"",status:r.status||"ABERTO",data_prevista:dateOnlyV181(r.data_prevista),data_liquidacao:dateOnlyV181(r.data_liquidacao),taxa_real:round2V181(r.taxa_real),liquido_real:round2V181(r.liquido_real),conta_destino_id:r.conta_destino_id||"",transferencia_id:r.transferencia_id||"",ajuste_taxa:round2V181(r.ajuste_taxa)}));
}
async function settleCardReceivableV181(user:any,id:string,payload:any){
  const r=await rowByIdV181("recebiveis_cartao",id);if(!r||String(r.status||"").toUpperCase()!=="ABERTO")throw new Error("Recebível aberto não encontrado.");
  const from=await rowByIdV181("contas_financeiras",String(r.conta_origem_id||"")),to=await rowByIdV181("contas_financeiras",String(payload?.conta_destino_id||""));if(!from||!to)throw new Error("Conta financeira inválida.");
  const date=dateOnlyV181(payload?.data_liquidacao||todayV181()),realNet=round2V181(payload?.liquido_real),realFee=round2V181(payload?.taxa_real);if(realNet<0||realFee<0)throw new Error("Valores de liquidação inválidos.");
  const transfers:any[]=[],cash:any[]=[];let transferId="";
  if(String(from.id)!==String(to.id)&&realNet>0){transferId=uidV181("TRF");const outId=uidV181("MOV"),inId=uidV181("MOV"),desc="Liquidação de cartão - "+String(r.forma_pagamento||"");
    cash.push({id:outId,data,competencia:date,tipo:"TRANSFERENCIA_CARTAO",origem:"RECEBIVEL_CARTAO",origem_id:id,descricao:desc,valor:-realNet,status:"REALIZADO",forma_pagamento:r.forma_pagamento||"",criado_em:nowIsoV181(),conta_financeira_id:from.id,conta_financeira_nome:from.nome,impacto_resultado:false,conciliado:false,conciliacao_id:"",movimento_financeiro_id:transferId});
    cash.push({id:inId,data,competencia:date,tipo:"TRANSFERENCIA_CARTAO",origem:"RECEBIVEL_CARTAO",origem_id:id,descricao:desc,valor:realNet,status:"REALIZADO",forma_pagamento:r.forma_pagamento||"",criado_em:nowIsoV181(),conta_financeira_id:to.id,conta_financeira_nome:to.nome,impacto_resultado:false,conciliado:false,conciliacao_id:"",movimento_financeiro_id:transferId});
    transfers.push({id:transferId,data,conta_origem_id:from.id,conta_origem_nome:from.nome,conta_destino_id:to.id,conta_destino_nome:to.nome,valor:realNet,descricao:desc,mov_saida_id:outId,mov_entrada_id:inId,status:"REALIZADO",usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()});
  }
  const adjust=round2V181(numV181(r.taxa_estimada)-realFee);if(Math.abs(adjust)>0.004)cash.push({id:uidV181("MOV"),data,competencia:dateOnlyV181(r.data_venda),tipo:"AJUSTE_TAXA_CARTAO",origem:"RECEBIVEL_CARTAO",origem_id:id,descricao:"Ajuste de taxa real - "+String(r.forma_pagamento||""),valor:adjust,status:"REALIZADO",forma_pagamento:r.forma_pagamento||"",criado_em:nowIsoV181(),conta_financeira_id:String(from.id)===String(to.id)?to.id:from.id,conta_financeira_nome:String(from.id)===String(to.id)?to.nome:from.nome,impacto_resultado:true,conciliado:false,conciliacao_id:"",movimento_financeiro_id:transferId});
  const row={...r,status:"LIQUIDADO",data_liquidacao:date,taxa_real:realFee,liquido_real:realNet,conta_destino_id:to.id,transferencia_id:transferId||null,ajuste_taxa:adjust,atualizado_em:nowIsoV181()};
  await financialOpV181("CARD_SETTLE",{receivable:row,transfers,cash,audit:[financialAuditV181(user,"LIQUIDAR","RECEBIVEL_CARTAO",id,{liquido_real:realNet,taxa_real:realFee,conta:to.nome,ajuste:adjust})]},user);return true;
}
async function thirdPartyListV181(){return (await allRowsV181("repasses_terceiros")).sort((a,b)=>String(b.data_origem).localeCompare(String(a.data_origem))||String(b.criado_em||"").localeCompare(String(a.criado_em||""))).map(r=>({...r,data_origem:dateOnlyV181(r.data_origem),valor_bruto:round2V181(r.valor_bruto),taxa_cartao:round2V181(r.taxa_cartao),valor_liquido:round2V181(r.valor_liquido),data_pagamento:dateOnlyV181(r.data_pagamento)}));}
async function thirdPartySaveV181(user:any,p:any){
  const gross=round2V181(p?.valor),fee=Math.max(0,round2V181(p?.taxa_cartao)),studioAbsorbs=String(p?.absorve_taxa||"TERCEIRO").toUpperCase()==="STUDIO";if(!String(p?.beneficiario||"").trim()||gross<=0)throw new Error("Informe beneficiário e valor bruto.");if(fee>gross)throw new Error("A taxa não pode superar o valor bruto.");
  const account=await rowByIdV181("contas_financeiras",String(p?.conta_recebimento_id||""));if(!account||!isActiveV181(account.ativo))throw new Error("Conta de recebimento inválida.");
  const id=uidV181("RPT"),date=dateOnlyV181(p?.data||todayV181()),payable=studioAbsorbs?gross:round2V181(gross-fee),cash:any[]=[];let inId:any=null,feeId:any=null;
  if(!!p?.registrar_entrada){inId=uidV181("MOV");cash.push({id:inId,data,competencia:date,tipo:"TERCEIRO_ENTRADA",origem:"REPASSE_TERCEIRO",origem_id:id,descricao:"Valor de terceiro - "+String(p.beneficiario),valor:gross,status:"REALIZADO",forma_pagamento:String(p.forma_origem||""),criado_em:nowIsoV181(),conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:false,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""});
    if(fee>0){feeId=uidV181("MOV");cash.push({id:feeId,data,competencia:date,tipo:"TAXA_TERCEIRO",origem:"REPASSE_TERCEIRO",origem_id:id,descricao:"Taxa de cartão - valor de terceiro",valor:-fee,status:"REALIZADO",forma_pagamento:String(p.forma_origem||""),criado_em:nowIsoV181(),conta_financeira_id:account.id,conta_financeira_nome:account.nome,impacto_resultado:studioAbsorbs,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""});}
  }
  const row={id,data_origem:date,beneficiario:titleV181(p.beneficiario),descricao:String(p.descricao||""),forma_origem:String(p.forma_origem||""),conta_recebimento_id:account.id,conta_recebimento_nome:account.nome,valor_bruto:gross,taxa_cartao:fee,absorve_taxa:studioAbsorbs,valor_liquido:payable,registrar_entrada:!!p.registrar_entrada,mov_entrada_id:inId,mov_taxa_id:feeId,status:"PENDENTE",data_pagamento:null,conta_pagamento_id:null,conta_pagamento_nome:"",mov_pagamento_id:null,usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()};
  await financialOpV181("THIRD_CREATE",{third:row,cash,audit:[financialAuditV181(user,"CRIAR","REPASSE_TERCEIRO",id,{beneficiario:row.beneficiario,bruto:gross,taxa:fee,a_repassar:payable,studio_absorve_taxa:studioAbsorbs})]},user);return {ok:true,id};
}
async function thirdPartyPayV181(user:any,id:string,p:any){
  const r=await rowByIdV181("repasses_terceiros",id);if(!r||String(r.status||"").toUpperCase()==="PAGO")throw new Error("Repasse não encontrado ou já pago.");const acc=await rowByIdV181("contas_financeiras",String(p?.conta_financeira_id||""));if(!acc||!isActiveV181(acc.ativo))throw new Error("Conta de pagamento inválida.");const date=dateOnlyV181(p?.data||todayV181()),mid=uidV181("MOV"),amount=round2V181(r.valor_liquido);
  const cash=[{id:mid,data,competencia:dateOnlyV181(r.data_origem),tipo:"REPASSE_TERCEIRO",origem:"REPASSE_TERCEIRO",origem_id:id,descricao:"Repasse a terceiro - "+r.beneficiario,valor:-amount,status:"REALIZADO",forma_pagamento:"",criado_em:nowIsoV181(),conta_financeira_id:acc.id,conta_financeira_nome:acc.nome,impacto_resultado:false,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""}],row={...r,status:"PAGO",data_pagamento:date,conta_pagamento_id:acc.id,conta_pagamento_nome:acc.nome,mov_pagamento_id:mid,atualizado_em:nowIsoV181()};
  await financialOpV181("THIRD_PAY",{third:row,cash,audit:[financialAuditV181(user,"PAGAR","REPASSE_TERCEIRO",id,{beneficiario:r.beneficiario,valor:amount,conta:acc.nome})]},user);return true;
}
async function reconcileAccountV181(user:any,p:any){
  const acc=await rowByIdV181("contas_financeiras",String(p?.conta_financeira_id||""));if(!acc||!boolV181(acc.permite_conciliacao,true))throw new Error("Conta inválida para conciliação.");const date=dateOnlyV181(p?.data_referencia||todayV181()),system=await accountBalanceAtV181(acc,date),external=round2V181(p?.saldo_externo),diff=round2V181(external-system),status=Math.abs(diff)<=0.01?"CONCILIADO":"DIVERGENTE",id=uidV181("CON");
  const row={id,conta_financeira_id:acc.id,conta_financeira_nome:acc.nome,data_referencia:date,saldo_sistema:system,saldo_externo:external,diferenca:diff,status,observacoes:String(p?.observacoes||""),usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181()};
  await financialOpV181("RECONCILE",{reconciliation:row,audit:[financialAuditV181(user,"CONCILIAR","CONTA_FINANCEIRA",acc.id,{data:date,sistema:system,externo:external,diferenca:diff,status})]},user);return {id,status,system,external,difference:diff};
}
async function reconciliationListV181(filters:any){filters=filters||{};return (await allRowsV181("conciliacoes_financeiras")).filter(r=>!filters.account_id||String(r.conta_financeira_id)===String(filters.account_id)).sort((a,b)=>String(b.data_referencia).localeCompare(String(a.data_referencia))||String(b.criado_em||"").localeCompare(String(a.criado_em||""))).map(r=>({...r,data_referencia:dateOnlyV181(r.data_referencia),saldo_sistema:round2V181(r.saldo_sistema),saldo_externo:round2V181(r.saldo_externo),diferenca:round2V181(r.diferenca)}));}
function statementDateV181(v:any){const s=String(v||"").trim();if(/^\d{4}-\d{2}-\d{2}/.test(s))return s.slice(0,10);let m=s.match(/^(\d{2})[\/-](\d{2})[\/-](\d{4})/);if(m)return m[3]+"-"+m[2]+"-"+m[1];m=s.match(/^(\d{4})(\d{2})(\d{2})/);if(m)return m[1]+"-"+m[2]+"-"+m[3];return "";}
function statementNumberV181(v:any){let s=String(v??"").trim().replace(/[R$\s]/g,"");if(!s)return 0;if(s.includes(",")&&s.includes(".")){if(s.lastIndexOf(",")>s.lastIndexOf("."))s=s.replace(/\./g,"").replace(",",".");else s=s.replace(/,/g,"");}else if(s.includes(","))s=s.replace(",",".");return Number(s.replace(/[^\d.-]/g,""))||0;}
async function sha256V181(s:string){const b=new TextEncoder().encode(s),h=await crypto.subtle.digest("SHA-256",b);return Array.from(new Uint8Array(h)).map(x=>x.toString(16).padStart(2,"0")).join("");}
function parseStatementV181(text:any,type:any){
  const raw=String(text||""),kind=String(type||"CSV").toUpperCase(),out:any[]=[];
  if(kind==="OFX"||/<STMTTRN>/i.test(raw)){for(const block of raw.split(/<STMTTRN>/i).slice(1)){const g=(tag:string)=>{const m=block.match(new RegExp("<"+tag+">([^<\\r\\n]+)","i"));return m?m[1].trim():"";},date=statementDateV181(g("DTPOSTED")),value=statementNumberV181(g("TRNAMT")),desc=[g("NAME"),g("MEMO")].filter(Boolean).join(" - ");if(date&&value)out.push({data:date,descricao:desc||"Movimento OFX",valor:value});}return out;}
  const lines=raw.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);if(!lines.length)return out;const first=lines[0],delims=[";","\t",","],delim=delims.sort((a,b)=>first.split(b).length-first.split(a).length)[0],rows=lines.map(l=>l.split(delim).map(x=>x.trim().replace(/^"|"$/g,""))),headers=rows[0].map(normalizeTextV181);
  const idx=(names:string[])=>headers.findIndex(h=>names.some(n=>h===n||h.includes(n))),di=idx(["data","date"]),xi=idx(["descricao","historico","memo","description","lancamento"]),vi=idx(["valor","amount","value"]),debi=idx(["debito","debit"]),credi=idx(["credito","credit"]);const start=di>=0&&(vi>=0||debi>=0||credi>=0)?1:0;
  for(let i=start;i<rows.length;i++){const r=rows[i],date=statementDateV181(r[di>=0?di:0]);let value=vi>=0?statementNumberV181(r[vi]):0;if(vi<0){const cr=credi>=0?statementNumberV181(r[credi]):0,dbt=debi>=0?statementNumberV181(r[debi]):0;value=cr-Math.abs(dbt);}const desc=xi>=0?r[xi]:r.filter((_,j)=>j!==(di>=0?di:0)&&j!==vi&&j!==debi&&j!==credi).join(" ");if(date&&Math.abs(value)>0.0001)out.push({data:date,descricao:desc||"Movimento de extrato",valor:round2V181(value)});}return out;
}
function statementDaysV181(a:any,b:any){const x=Date.parse(dateOnlyV181(a)+"T12:00:00Z"),y=Date.parse(dateOnlyV181(b)+"T12:00:00Z");return Math.abs(Math.round((x-y)/86400000));}
async function statementCandidatesV181(statement:any){
  const rows=(await allRowsV181("mov_caixa")).filter(m=>String(m.status||"").toUpperCase()==="REALIZADO"&&!boolV181(m.conciliado,false)&&String(m.conta_financeira_id||"")===String(statement.conta_financeira_id)&&Math.abs(numV181(m.valor)-numV181(statement.valor))<=0.01&&statementDaysV181(m.data,statement.data)<=7);
  return rows.sort((a,b)=>statementDaysV181(a.data,statement.data)-statementDaysV181(b.data,statement.data)||String(a.criado_em||"").localeCompare(String(b.criado_em||"")));
}
async function importStatementV181(user:any,p:any){
  const acc=await rowByIdV181("contas_financeiras",String(p?.conta_financeira_id||""));if(!acc||!boolV181(acc.permite_conciliacao,true))throw new Error("Conta inválida para importação.");const parsed=parseStatementV181(p?.text,p?.tipo);if(!parsed.length)throw new Error("Nenhum movimento válido encontrado no arquivo.");
  const existing=await allRowsV181("extratos_financeiros"),statements:any[]=[];let duplicated=0,matched=0;
  for(let i=0;i<parsed.length;i++){const x=parsed[i],hash=await sha256V181([acc.id,x.data,round2V181(x.valor).toFixed(2),normalizeTextV181(x.descricao)].join("|"));if(existing.some(e=>String(e.hash)===hash&&String(e.conta_financeira_id)===String(acc.id))){duplicated++;continue;}
    const temp={conta_financeira_id:acc.id,data:x.data,valor:x.valor},cand=await statementCandidatesV181(temp),match=cand[0]||null,id=uidV181("EXT");if(match)matched++;
    statements.push({id,conta_financeira_id:acc.id,conta_financeira_nome:acc.nome,arquivo:String(p?.filename||""),linha_origem:i+1,data:x.data,descricao:x.descricao,valor:round2V181(x.valor),hash,status:match?"CONCILIADO":"PENDENTE",mov_caixa_id:match?.id||null,conciliado_em:match?nowIsoV181():null,ignorado_em:null,usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()});
  }
  await financialOpV181("STATEMENT_IMPORT",{statements,audit:[financialAuditV181(user,"IMPORTAR_EXTRATO","EXTRATO",acc.id,{arquivo:String(p?.filename||""),novos:statements.length,duplicados:duplicated,conciliados:matched})]},user);
  for(const s of statements.filter(x=>x.mov_caixa_id))await updateV181("mov_caixa",s.mov_caixa_id,{conciliado:true,conciliacao_id:s.id});
  return {newCount:statements.length,matched,duplicated};
}
async function statementListV181(filters:any){filters=filters||{};return (await allRowsV181("extratos_financeiros")).filter(x=>(!filters.account_id||String(x.conta_financeira_id)===String(filters.account_id))&&(!filters.status||String(x.status||"").toUpperCase()===String(filters.status).toUpperCase())).sort((a,b)=>String(b.data).localeCompare(String(a.data))||String(b.criado_em||"").localeCompare(String(a.criado_em||""))).map(x=>({...x,data:dateOnlyV181(x.data),valor:round2V181(x.valor)}));}
async function statementMatchCandidatesV181(id:string){const s=await rowByIdV181("extratos_financeiros",id);if(!s||String(s.status||"").toUpperCase()!=="PENDENTE")throw new Error("Movimento pendente do extrato não encontrado.");return (await statementCandidatesV181(s)).map(m=>({id:m.id,data:dateOnlyV181(m.data),valor:round2V181(m.valor),descricao:m.descricao||"",conta:m.conta_financeira_nome||""}));}
async function statementMatchV181(user:any,id:string,movementId:string){const s=await rowByIdV181("extratos_financeiros",id),m=await rowByIdV181("mov_caixa",movementId);if(!s||String(s.status||"").toUpperCase()!=="PENDENTE"||!m)throw new Error("Movimento inválido.");if(String(m.conta_financeira_id)!==String(s.conta_financeira_id)||Math.abs(numV181(m.valor)-numV181(s.valor))>0.01||statementDaysV181(m.data,s.data)>7)throw new Error("Movimento incompatível com o extrato.");const row={...s,status:"CONCILIADO",mov_caixa_id:m.id,conciliado_em:nowIsoV181(),atualizado_em:nowIsoV181()};await financialOpV181("STATEMENT_MATCH",{statement:row,audit:[financialAuditV181(user,"VINCULAR_EXTRATO","EXTRATO",id,{mov_caixa_id:m.id})]},user);return true;}
async function statementIgnoreV181(user:any,id:string){const s=await rowByIdV181("extratos_financeiros",id);if(!s||String(s.status||"").toUpperCase()!=="PENDENTE")throw new Error("Movimento pendente não encontrado.");const row={...s,status:"IGNORADO",ignorado_em:nowIsoV181(),atualizado_em:nowIsoV181()};await financialOpV181("STATEMENT_IGNORE",{statement:row,audit:[financialAuditV181(user,"IGNORAR_EXTRATO","EXTRATO",id,{})]},user);return true;}
async function statementClassifyV181(user:any,id:string,p:any){
  const s=await rowByIdV181("extratos_financeiros",id);if(!s||String(s.status||"").toUpperCase()!=="PENDENTE")throw new Error("Movimento pendente não encontrado.");const acc=await rowByIdV181("contas_financeiras",s.conta_financeira_id);if(!acc)throw new Error("Conta financeira não encontrada.");const type=String(p?.tipo||"AJUSTE").toUpperCase(),desc=String(p?.descricao||"Conciliação bancária"),mid=uidV181("MOV"),impact=["DESPESA","RECEITA"].includes(type);
  if(type==="DESPESA"&&numV181(s.valor)>=0)throw new Error("Uma despesa deve corresponder a uma saída negativa no extrato.");if(type==="RECEITA"&&numV181(s.valor)<=0)throw new Error("Uma receita deve corresponder a uma entrada positiva no extrato.");
  const cash=[{id:mid,data:dateOnlyV181(s.data),competencia:dateOnlyV181(s.data),tipo:type==="APORTE"?"APORTE_SOCIO":type==="DESPESA"?"DESPESA":type==="RECEITA"?"RECEITA_MANUAL":"AJUSTE_CONCILIACAO",origem:"EXTRATO",origem_id:id,descricao:desc,valor:round2V181(s.valor),status:"REALIZADO",forma_pagamento:"",criado_em:nowIsoV181(),conta_financeira_id:acc.id,conta_financeira_nome:acc.nome,impacto_resultado:impact,conciliado:true,conciliacao_id:id,movimento_financeiro_id:""}],expenses:any[]=[],expense_parcels:any[]=[],revenues:any[]=[],revenue_parcels:any[]=[];
  if(type==="DESPESA"){const cat=await rowByIdV181("categorias_despesas",String(p?.categoria_id||""));if(!cat||!isActiveV181(cat.ativo))throw new Error("Categoria de despesa inválida.");const sub=p?.subcategoria_id?await rowByIdV181("subcategorias_despesas",String(p.subcategoria_id)):null,eid=uidV181("DES"),pid=uidV181("DSP"),val=Math.abs(round2V181(s.valor));expenses.push({id:eid,descricao:desc,data_compra:dateOnlyV181(s.data),categoria_id:null,categoria_despesa_id:cat.id,subcategoria_despesa_id:sub?.id||null,categoria:cat.nome,subcategoria:sub?.nome||"",valor_total:val,forma_pagamento:"Extrato bancário",qtd_parcelas:1,data_primeiro_vencimento:dateOnlyV181(s.data),status:"PAGO",recorrente:false,recorrencia_meses:1,observacoes:"Classificado a partir de extrato",origem:"EXTRATO",usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),editado_por:""});expense_parcels.push({id:pid,despesa_id:eid,parcela_num:1,total_parcelas:1,vencimento:dateOnlyV181(s.data),valor:val,status:"PAGO",data_pagamento:dateOnlyV181(s.data),criado_em:nowIsoV181(),atualizado_em:nowIsoV181()});}
  if(type==="RECEITA"){const cat=await rowByIdV181("categorias_receitas",String(p?.categoria_id||""));if(!cat||!isActiveV181(cat.ativo))throw new Error("Categoria de receita inválida.");const sub=p?.subcategoria_id?await rowByIdV181("subcategorias_receitas",String(p.subcategoria_id)):null,rid=uidV181("REC"),pid=uidV181("RCP"),val=round2V181(s.valor);revenues.push({id:rid,descricao:desc,cliente_id:"",cliente_nome:"",data_competencia:dateOnlyV181(s.data),categoria_receita_id:cat.id,subcategoria_receita_id:sub?.id||null,categoria:cat.nome,subcategoria:sub?.nome||"",natureza:"OPERACIONAL",valor_total:val,forma_id:"",forma_pagamento:"Extrato bancário",qtd_parcelas:1,data_primeiro_recebimento:dateOnlyV181(s.data),status:"RECEBIDA",recorrente:false,recorrencia_meses:1,observacoes:"Classificado a partir de extrato",origem:"EXTRATO",usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),editado_por:"",excluido:false});revenue_parcels.push({id:pid,receita_id:rid,parcela_num:1,total_parcelas:1,vencimento:dateOnlyV181(s.data),valor_bruto:val,taxa_percentual:0,taxa_fixa:0,valor_taxa:0,valor_liquido:val,status:"RECEBIDA",data_recebimento:dateOnlyV181(s.data),criado_em:nowIsoV181(),atualizado_em:nowIsoV181(),mov_caixa_id:mid});}
  const row={...s,status:"CONCILIADO",mov_caixa_id:mid,conciliado_em:nowIsoV181(),atualizado_em:nowIsoV181()};await financialOpV181("STATEMENT_CLASSIFY",{statement:row,cash,expenses,expense_parcels,revenues,revenue_parcels,audit:[financialAuditV181(user,"CLASSIFICAR_EXTRATO","EXTRATO",id,{tipo:type,descricao:desc,mov_caixa_id:mid})]},user);return true;
}
async function saveContributionV181(user:any,p:any){const acc=await rowByIdV181("contas_financeiras",String(p?.conta_financeira_id||"")),value=round2V181(p?.valor),date=dateOnlyV181(p?.data||todayV181());if(!acc||!isActiveV181(acc.ativo))throw new Error("Conta financeira inválida.");if(value<=0)throw new Error("Informe um valor maior que zero.");const id=uidV181("MOV"),cash=[{id,data,competencia:date,tipo:"APORTE_SOCIO",origem:"APORTE",origem_id:id,descricao:String(p?.descricao||"Aporte de sócio"),valor:value,status:"REALIZADO",forma_pagamento:"",criado_em:nowIsoV181(),conta_financeira_id:acc.id,conta_financeira_nome:acc.nome,impacto_resultado:false,conciliado:false,conciliacao_id:"",movimento_financeiro_id:""}];await financialOpV181("CONTRIBUTION",{cash,audit:[financialAuditV181(user,"CRIAR","APORTE",id,{valor:value,conta:acc.nome,data})]},user);return {ok:true,id};}
async function reclassifyCashV181(user:any,id:string,accountId:string){const m=await rowByIdV181("mov_caixa",id),a=await rowByIdV181("contas_financeiras",accountId);if(!m||!a||!isActiveV181(a.ativo))throw new Error("Movimento ou conta inválida.");await financialOpV181("RECLASSIFY",{movement_id:id,account_id:a.id,account_name:a.nome,audit:[financialAuditV181(user,"RECLASSIFICAR_CONTA","MOV_CAIXA",id,{antes:m.conta_financeira_nome,depois:a.nome})]},user);return true;}
// ============================= fim Financeiro / Conciliação =============================


// ============================= v1.8.1 — Compatibilidade final / relatórios =============================
function bytesBase64V181(bytes:Uint8Array){
  let out="";const step=0x8000;
  for(let i=0;i<bytes.length;i+=step)out+=String.fromCharCode(...bytes.subarray(i,Math.min(bytes.length,i+step)));
  return btoa(out);
}
function utf8Base64V181(text:any){return bytesBase64V181(new TextEncoder().encode(String(text??"")));}
function xmlEscV181(v:any){return String(v??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&apos;");}
function asciiV181(v:any){
  return String(v??"").normalize("NFD").replace(/[\u0300-\u036f]/g,"")
    .replace(/[^\x20-\x7E]/g," ").replace(/\s+/g," ").trim();
}
function pdfEscV181(v:any){return asciiV181(v).replace(/\\/g,"\\\\").replace(/\(/g,"\\(").replace(/\)/g,"\\)");}
function pdfMoneyV181(v:any){return "R$ "+round2V181(v).toFixed(2).replace(".",",");}
function pdfDateV181(v:any){const s=dateOnlyV181(v);return /^\d{4}-\d{2}-\d{2}$/.test(s)?s.slice(8,10)+"/"+s.slice(5,7)+"/"+s.slice(0,4):s;}
function wrapLineV181(v:any,max=92){
  const words=asciiV181(v).split(/\s+/).filter(Boolean),out:string[]=[];let line="";
  for(const w of words){if(!line)line=w;else if((line+" "+w).length<=max)line+=" "+w;else{out.push(line);line=w;}}
  if(line)out.push(line);return out.length?out:[""];
}
function simplePdfV181(lines:any[],title="Studio Essence"){
  const txt:string[]=[];for(const raw of lines||[])txt.push(...wrapLineV181(raw,96));
  const maxLines=48,shown=txt.slice(0,maxLines);
  let content="BT\n/F1 10 Tf\n50 790 Td\n";
  shown.forEach((line,i)=>{if(i>0)content+="0 -15 Td\n";content+="("+pdfEscV181(line)+") Tj\n";});
  content+="ET";
  const objs=[
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    "<< /Length "+new TextEncoder().encode(content).length+" >>\nstream\n"+content+"\nendstream"
  ];
  let pdf="%PDF-1.4\n",offsets=[0];
  for(let i=0;i<objs.length;i++){offsets.push(new TextEncoder().encode(pdf).length);pdf+=(i+1)+" 0 obj\n"+objs[i]+"\nendobj\n";}
  const xref=new TextEncoder().encode(pdf).length;pdf+="xref\n0 "+(objs.length+1)+"\n0000000000 65535 f \n";
  for(let i=1;i<offsets.length;i++)pdf+=String(offsets[i]).padStart(10,"0")+" 00000 n \n";
  pdf+="trailer\n<< /Size "+(objs.length+1)+" /Root 1 0 R /Info << /Title ("+pdfEscV181(title)+") >> >>\nstartxref\n"+xref+"\n%%EOF";
  return utf8Base64V181(pdf);
}
function crc32V181(bytes:Uint8Array){
  let c=0xffffffff;
  for(const b of bytes){c^=b;for(let k=0;k<8;k++)c=(c>>>1)^((c&1)?0xedb88320:0);}
  return (c^0xffffffff)>>>0;
}
function pushU16V181(a:number[],v:number){a.push(v&255,(v>>>8)&255);}
function pushU32V181(a:number[],v:number){a.push(v&255,(v>>>8)&255,(v>>>16)&255,(v>>>24)&255);}
function zipStoreV181(files:{name:string,data:string|Uint8Array}[]){
  const enc=new TextEncoder(),local:number[]=[],central:number[]=[];let offset=0;
  for(const f of files){
    const name=enc.encode(f.name),data=typeof f.data==="string"?enc.encode(f.data):f.data,crc=crc32V181(data),start=offset,lh:number[]=[];
    pushU32V181(lh,0x04034b50);pushU16V181(lh,20);pushU16V181(lh,0x0800);pushU16V181(lh,0);pushU16V181(lh,0);pushU16V181(lh,0);
    pushU32V181(lh,crc);pushU32V181(lh,data.length);pushU32V181(lh,data.length);pushU16V181(lh,name.length);pushU16V181(lh,0);
    local.push(...lh,...name,...data);offset+=lh.length+name.length+data.length;
    const ch:number[]=[];pushU32V181(ch,0x02014b50);pushU16V181(ch,20);pushU16V181(ch,20);pushU16V181(ch,0x0800);pushU16V181(ch,0);pushU16V181(ch,0);pushU16V181(ch,0);
    pushU32V181(ch,crc);pushU32V181(ch,data.length);pushU32V181(ch,data.length);pushU16V181(ch,name.length);pushU16V181(ch,0);pushU16V181(ch,0);pushU16V181(ch,0);pushU16V181(ch,0);pushU32V181(ch,0);pushU32V181(ch,start);
    central.push(...ch,...name);
  }
  const cdOffset=local.length,all:number[]=[...local,...central],e:number[]=[];pushU32V181(e,0x06054b50);pushU16V181(e,0);pushU16V181(e,0);pushU16V181(e,files.length);pushU16V181(e,files.length);pushU32V181(e,central.length);pushU32V181(e,cdOffset);pushU16V181(e,0);all.push(...e);return new Uint8Array(all);
}
function xlsxColV181(n:number){let s="";while(n>0){n--;s=String.fromCharCode(65+n%26)+s;n=Math.floor(n/26);}return s;}
function xlsxCellV181(ref:string,v:any,numeric=false){
  if(numeric&&Number.isFinite(Number(v)))return '<c r="'+ref+'"><v>'+Number(v)+'</v></c>';
  return '<c r="'+ref+'" t="inlineStr"><is><t xml:space="preserve">'+xmlEscV181(v)+'</t></is></c>';
}
function attendanceXlsxV181(rows:any[]){
  const headers=["Data","Cliente","Profissional","Serviço","Valor total","Forma de pagamento","Status","Observações","Origem"];
  const matrix:any[][]=[headers,...rows.map(x=>[pdfDateV181(x.data),x.cliente||"",x.profissionais||"",x.servicos||"",round2V181(x.total),x.pagamentos||"",x.status||"",x.observacoes||"",x.origem||""])];
  const sheetRows=matrix.map((r,ri)=>'<row r="'+(ri+1)+'">'+r.map((v,ci)=>xlsxCellV181(xlsxColV181(ci+1)+(ri+1),v,ri>0&&ci===4)).join("")+'</row>').join("");
  const files=[
    {name:"[Content_Types].xml",data:'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'},
    {name:"_rels/.rels",data:'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'},
    {name:"xl/workbook.xml",data:'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Atendimentos" sheetId="1" r:id="rId1"/></sheets></workbook>'},
    {name:"xl/_rels/workbook.xml.rels",data:'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'},
    {name:"xl/worksheets/sheet1.xml",data:'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetData>'+sheetRows+'</sheetData></worksheet>'}
  ];
  return zipStoreV181(files);
}
async function bootstrapAdminCompatV181(payload:any){
  const users=await allRowsV181("usuarios");if(users.length>0)throw new Error("O administrador inicial já foi configurado.");
  payload=payload||{};const nome=String(payload.nome||"").trim(),ident=normalize(payload.identificador),pin=String(payload.pin||"").trim();
  if(!nome||!ident||pin.length<4)throw new Error("Informe nome, identificador e um PIN com pelo menos 4 dígitos.");
  const row:any={id:uidV181("USR"),nome,identificador:ident,pin_hash:await sha256("studio-essence|"+pin),perfil:"ADMIN",ativo:true,criado_em:nowIsoV181(),ultimo_login:nowIsoV181(),atualizado_em:nowIsoV181(),visualizar_atendimentos_dias:99999,editar_atendimentos_dias:99999,cancelar_atendimentos_dias:99999};
  await insertV181("usuarios",row);await auditV181(row,"CRIAR","USUARIO",row.id,{perfil:"ADMIN",bootstrap:true});
  const token=crypto.randomUUID()+crypto.randomUUID(),expires=new Date(Date.now()+SESSION_HOURS*3600_000).toISOString();
  await insertV181("migration_sessions",{token,usuario_id:row.id,expires_at:expires});
  return JSON.stringify({ok:true,token,user:publicUser(row)});
}
async function attendanceManagerReportV181(user:any,filters:any){
  const listed=await listAttendancesV181(user,filters||{}),ids=new Set(listed.map((a:any)=>String(a.id))),items=(await allRowsV181("atendimento_itens")).filter(i=>ids.has(String(i.atendimento_id))&&attendanceRowActiveV181(i));
  const campaign:any={};for(const i of items.filter(i=>i.campanha_id)){const k=String(i.campanha_id),r=campaign[k]||(campaign[k]={id:k,nome:i.campanha_nome||"Campanha",atendimentos:new Set<string>(),servicos:0,valor_tabela:0,valor_cobrado:0,desconto:0});r.atendimentos.add(String(i.atendimento_id));r.servicos++;r.valor_tabela+=numV181(i.valor_tabela);r.valor_cobrado+=numV181(i.valor_bruto);r.desconto+=numV181(i.desconto_valor);}
  const campaigns=Object.values(campaign).map((r:any)=>({id:r.id,nome:r.nome,atendimentos:r.atendimentos.size,servicos:r.servicos,valor_tabela:round2V181(r.valor_tabela),valor_cobrado:round2V181(r.valor_cobrado),desconto:round2V181(r.desconto)})).sort((a:any,b:any)=>b.valor_cobrado-a.valor_cobrado);
  const courtesy:any={com_comissao:{set:new Set<string>(),servicos:0,valor_referencia:0,comissao:0},sem_comissao:{set:new Set<string>(),servicos:0,valor_referencia:0,comissao:0}};
  for(const i of items){const t=String(i.cortesia_tipo||"").toUpperCase();if(!t)continue;const r=(t==="CORTESIA_SEM_COMISSAO"||t==="CORTESIA_PACOTE")?courtesy.sem_comissao:courtesy.com_comissao;r.set.add(String(i.atendimento_id));r.servicos++;r.valor_referencia+=numV181(i.valor_referencia_comissao||i.valor_tabela);r.comissao+=numV181(i.valor_comissao);}
  const clean=(r:any)=>({atendimentos:r.set.size,servicos:r.servicos,valor_referencia:round2V181(r.valor_referencia),comissao:round2V181(r.comissao)});
  return {campaigns,courtesy:{com_comissao:clean(courtesy.com_comissao),sem_comissao:clean(courtesy.sem_comissao)}};
}
async function commissionPdfV181(id:string){
  const c=await rowByIdV181("comissoes_fechamentos",id);if(!c)throw new Error("Fechamento não encontrado.");
  const [items,adjs]=await Promise.all([allRowsV181("comissoes_itens"),allRowsV181("comissoes_ajustes")]),its=items.filter(x=>String(x.fechamento_id)===id),aa=adjs.filter(x=>String(x.fechamento_id)===id);
  const gross=c.valor_comissao_bruta!=null?round2V181(c.valor_comissao_bruta):round2V181(c.total_comissao),adv=c.vales_descontados!=null?round2V181(c.vales_descontados):0,net=c.total_liquido!=null?round2V181(c.total_liquido):round2V181(c.total_comissao);
  const lines:any[]=["STUDIO ESSENCE","DEMONSTRATIVO DE COMISSAO","Profissional: "+c.profissional_nome,"Periodo: "+pdfDateV181(c.periodo_inicio)+" a "+pdfDateV181(c.periodo_fim)+" | Status: "+c.status,""];
  its.forEach(i=>lines.push(pdfDateV181(i.data_servico)+" | "+(i.cliente_nome||"")+" | "+(i.servico_nome||"")+" | Ref. "+pdfMoneyV181(i.valor_referencia)+" | "+round2V181(numV181(i.percentual)*100).toFixed(2)+"% | Comissao "+pdfMoneyV181(i.valor_comissao)));
  lines.push("");lines.push("Comissao antes dos vales: "+pdfMoneyV181(gross));aa.forEach(a=>lines.push((a.descricao||a.tipo)+": "+pdfMoneyV181(a.valor)));if(adv>0)lines.push("Vales / adiantamentos: -"+pdfMoneyV181(adv));lines.push("TOTAL A RECEBER: "+pdfMoneyV181(net));lines.push("");lines.push("Documento interno, sem valor fiscal.");
  const safe=asciiV181(c.profissional_nome||"Profissional").replace(/[^A-Za-z0-9_-]+/g,"_");
  return {filename:"Comissao_"+safe+"_"+dateOnlyV181(c.periodo_inicio)+"_a_"+dateOnlyV181(c.periodo_fim)+".pdf",mimeType:"application/pdf",base64:simplePdfV181(lines,"Comissao Studio Essence")};
}
async function revenueReportRowV181(user:any,rowId:string){
  const all=(await automaticRevenueRowsV181()).concat(await manualRevenueRowsV181(user,true)),row=all.find(x=>String(x.row_id)===String(rowId));if(!row)throw new Error("Receita não encontrada.");
  let clientId="";
  const [kind,subId]=String(rowId||"").split(":");
  if(kind==="ATENDIMENTO"){const p=await rowByIdV181("pagamentos_receita",subId),a=p?await rowByIdV181("atendimentos",p.atendimento_id):null;clientId=a?.cliente_id||"";}
  else if(kind==="VENDA"){const p=await rowByIdV181("pagamentos_venda",subId),s=p?await rowByIdV181("vendas",p.venda_id):null;clientId=s?.cliente_id||"";}
  else if(kind==="PACOTE"){const p=await rowByIdV181("pacote_pagamentos",subId),x=p?await rowByIdV181("pacotes",p.pacote_id):null;clientId=x?.cliente_id||x?.beneficiario_id||"";}
  else if(kind==="MANUAL"||kind==="MANUAL-CANCELADA"){const r=await rowByIdV181("receitas",row.record_id);clientId=r?.cliente_id||"";}
  const client=clientId?await rowByIdV181("clientes",clientId):null;
  return {...row,client_id:clientId,phone:client?.telefone||""};
}
async function revenuePdfV181(user:any,rowId:string){
  const r=await revenueReportRowV181(user,rowId),lines=["STUDIO ESSENCE","COMPROVANTE / DEMONSTRATIVO DE RECEITA","Data: "+pdfDateV181(r.data),"Competencia: "+pdfDateV181(r.competencia),"Descricao: "+r.descricao,"Cliente: "+(r.cliente||"—"),"Categoria: "+r.categoria+(r.subcategoria?" / "+r.subcategoria:""),"Origem: "+r.origem,"Forma: "+(r.forma||"—"),"Status: "+r.status,"Valor bruto: "+pdfMoneyV181(r.valor_bruto),"Taxas: "+pdfMoneyV181(r.taxa),"Valor liquido: "+pdfMoneyV181(r.valor_liquido),"","Documento interno, sem valor fiscal."];
  return {filename:"Receita_Studio_Essence_"+dateOnlyV181(r.data)+"_"+asciiV181(r.origem).replace(/[^A-Za-z0-9_-]+/g,"_")+".pdf",mimeType:"application/pdf",base64:simplePdfV181(lines,"Receita Studio Essence")};
}
async function revenueWhatsappV181(user:any,rowId:string){
  const r=await revenueReportRowV181(user,rowId),phone=String(r.phone||"").replace(/\D/g,"");const brPhone=phone?(phone.startsWith("55")?phone:"55"+phone):"";
  const text="Olá"+(r.cliente?", "+r.cliente:"")+"! Segue o demonstrativo do Studio Essence referente a "+r.descricao+", no valor de "+pdfMoneyV181(r.valor_bruto)+". Data: "+pdfDateV181(r.data)+".";
  return {phone:brPhone,text};
}
async function globalSearchV181(user:any,q:any){
  const raw=String(q||"").trim(),nq=normalizeTextV181(raw),digits=raw.replace(/\D/g,"");if(nq.length<2&&digits.length<2)return [];
  const [clients,profs,atts,items,pkgs,sales,saleItems,revs,expenses,products,assets]=await Promise.all([
    allRowsV181("clientes"),allRowsV181("profissionais"),allRowsV181("atendimentos"),allRowsV181("atendimento_itens"),allRowsV181("pacotes"),allRowsV181("vendas"),allRowsV181("venda_itens"),allRowsV181("receitas"),allRowsV181("despesas"),allRowsV181("produtos"),allRowsV181("ativos")
  ]);
  const out:any[]=[];const match=(...vals:any[])=>normalizeTextV181(vals.join(" ")).includes(nq)||(digits.length>=2&&vals.some(v=>String(v||"").replace(/\D/g,"").includes(digits)));
  clients.filter(c=>isActiveV181(c.ativo)&&match(clientNameV181(c),c.telefone,c.email)).slice(0,8).forEach(c=>out.push({group:"Clientes",type:"CLIENTE",id:c.id,title:clientNameV181(c),subtitle:c.telefone||""}));
  profs.filter(p=>!professionalDeletedV181(p)&&match(p.nome,p.telefone,p.especialidade)).slice(0,8).forEach(p=>out.push({group:"Profissionais",type:"PROFISSIONAL",id:p.id,title:p.nome,subtitle:p.especialidade||""}));
  const byAtt:any={};items.filter(attendanceRowActiveV181).forEach(i=>(byAtt[String(i.atendimento_id)]??=[]).push(i));
  atts.filter(a=>String(a.status||"").toUpperCase()!=="CANCELADO"&&match(a.cliente_nome,a.observacoes,(byAtt[String(a.id)]||[]).map((i:any)=>i.servico_nome).join(" "),(byAtt[String(a.id)]||[]).map((i:any)=>i.profissional_nome).join(" "))).slice(0,8).forEach(a=>out.push({group:"Atendimentos",type:"ATENDIMENTO",id:a.id,title:a.cliente_nome||"Atendimento",subtitle:pdfDateV181(a.data)+" · "+(byAtt[String(a.id)]||[]).map((i:any)=>i.servico_nome).join(", "),date:dateOnlyV181(a.data),can_edit:canEditAttendanceV181(user,a.data)}));
  pkgs.filter(p=>String(p.status||"").toUpperCase()!=="CANCELADO"&&match(p.cliente_nome,p.comprador_nome,p.beneficiario_nome,p.vale_codigo,p.presente_para)).slice(0,8).forEach(p=>out.push({group:"Pacotes",type:"PACOTE",id:p.id,title:p.beneficiario_nome||p.cliente_nome||p.comprador_nome||"Pacote",subtitle:(p.tipo_pacote==="VALE_PRESENTE"?"Vale Presente · ":"")+pdfMoneyV181(p.valor_negociado)}));
  const bySale:any={};saleItems.filter(saleItemActiveV181).forEach(i=>(bySale[String(i.venda_id)]??=[]).push(i));
  sales.filter(s=>String(s.status||"").toUpperCase()!=="CANCELADO"&&match(s.cliente_nome,s.vendedor_profissional_nome,(bySale[String(s.id)]||[]).map((i:any)=>i.produto_nome).join(" "))).slice(0,8).forEach(s=>out.push({group:"Vendas",type:"VENDA",id:s.id,title:s.cliente_nome||"Venda de produtos",subtitle:pdfDateV181(s.data)+" · "+(bySale[String(s.id)]||[]).map((i:any)=>i.produto_nome).join(", "),can_edit:saleCanEditV181(user,s.data)}));
  revs.filter(r=>!revenueDeletedV181(r)&&match(r.descricao,r.cliente_nome,r.categoria,r.subcategoria)).slice(0,8).forEach(r=>out.push({group:"Receitas",type:"RECEITA",id:r.id,title:r.descricao||"Receita",subtitle:(r.cliente_nome||"")+" · "+pdfMoneyV181(r.valor_total),can_edit:String(r.origem||"MANUAL").toUpperCase()==="MANUAL"&&revenueCanEditV181(user,r.data_competencia)}));
  expenses.filter(d=>String(d.status||"").toUpperCase()!=="CANCELADO"&&match(d.descricao,d.categoria,d.subcategoria,d.forma_pagamento)).slice(0,8).forEach(d=>out.push({group:"Despesas",type:"DESPESA",id:d.id,title:d.descricao||"Despesa",subtitle:(d.categoria||"")+" · "+pdfMoneyV181(d.valor_total),can_edit:String(user?.perfil||"").toUpperCase()==="ADMIN"||dateOnlyV181(d.data_compra)===todayV181()}));
  products.filter(p=>!productDeletedV181(p)&&match(p.produto,p.marca,p.categoria,p.fornecedor,p.representante_fornecedor)).slice(0,8).forEach(p=>out.push({group:"Produtos",type:"PRODUTO",id:p.id,title:p.produto,subtitle:(p.categoria||"")+" · estoque "+numV181(p.estoque_atual)}));
  assets.filter(a=>match(a.nome||a.item,a.categoria,a.marca,a.modelo,a.numero_serie)).slice(0,8).forEach(a=>out.push({group:"Ativos",type:"ATIVO",id:a.id,title:a.nome||a.item||"Ativo",subtitle:a.categoria||""}));
  return out.slice(0,50);
}
async function rebuildAttendanceIndexV181(user:any){
  const [atts,items,pays,clients]=await Promise.all([allRowsV181("atendimentos"),allRowsV181("atendimento_itens"),allRowsV181("pagamentos_receita"),allRowsV181("clientes")]),im:any={},pm:any={},cm:any={};
  items.filter(attendanceRowActiveV181).forEach(i=>(im[String(i.atendimento_id)]??=[]).push(i));pays.filter(attendanceRowActiveV181).forEach(p=>(pm[String(p.atendimento_id)]??=[]).push(p));clients.forEach(c=>cm[String(c.id)]=c);
  const rows=atts.map(a=>{const its=im[String(a.id)]||[],ps=pm[String(a.id)]||[],locked=its.some((i:any)=>!attendanceCommissionEditableV181(i));return {id:a.id,data:dateOnlyV181(a.data),cliente_id:a.cliente_id||"",cliente_nome:a.cliente_nome||"",cliente_telefone:cm[String(a.cliente_id)]?.telefone||"",total:round2V181(its.reduce((s:any,i:any)=>s+numV181(i.valor_bruto),0)),servicos:its.map((i:any)=>i.servico_nome).join(", "),profissionais:[...new Set(its.map((i:any)=>i.profissional_nome).filter(Boolean))].join(", "),pagamentos:[...new Set(ps.map((p:any)=>p.forma_nome).filter(Boolean))].join(", "),observacoes:a.observacoes||"",status:a.status||"CONCLUIDO",origem:a.origem||"",natureza:a.natureza||"NORMAL",cortesia_comissao_pagador:a.cortesia_comissao_pagador||"",cortesia_motivo:a.cortesia_motivo||"",usa_pacote:its.some((i:any)=>!!i.pacote_item_id),profissional_ids:[...new Set(its.map((i:any)=>i.profissional_id).filter(Boolean))].join(","),servico_ids:[...new Set(its.map((i:any)=>i.servico_id).filter(Boolean))].join(","),comissao_bloqueada:locked,comissao_editavel:its.some(attendanceCommissionEditableV181),atualizado_em:nowIsoV181()};});
  // O índice é derivado de ATENDIMENTOS. Upsert é suficiente porque atendimentos são preservados logicamente; evita uma janela de índice vazio.\n  for(let i=0;i<rows.length;i+=200){const {error}=await db.from("idx_atendimentos").upsert(rows.slice(i,i+200),{onConflict:"id"});if(error)throw new Error(error.message);}
  await auditV181(user,"RECONSTRUIR","IDX_ATENDIMENTOS","ALL",{registros:rows.length});return {ok:true,rebuilt:rows.length,mode:"SUPABASE"};
}
async function productHistoryPreviewV181(productId:string){
  const [p,items,reps]=await Promise.all([rowByIdV181("produtos",productId),allRowsV181("venda_itens"),allRowsV181("consignacao_repasses")]);if(!p||String(p.finalidade||"").toUpperCase()!=="VENDA")return null;
  const pending=items.filter(i=>String(i.produto_id)===String(productId)&&saleItemActiveV181(i)&&(!i.finalidade||String(i.finalidade).toUpperCase()!=="VENDA"||!i.modelo_comercial)).filter(i=>!reps.some(r=>String(r.origem_item_id)===String(i.id)&&!["CANCELADO","SUBSTITUIDO"].includes(String(r.status||"").toUpperCase())));
  if(!pending.length)return null;const consign=String(p.modelo_comercial||"NORMAL").toUpperCase()==="CONSIGNADO",total=consign?round2V181(pending.reduce((s,i)=>s+numV181(p.valor_repasse_fornecedor)*numV181(i.quantidade),0)):0;
  return {count:pending.length,modelo_comercial:p.modelo_comercial||"NORMAL",fornecedor:p.fornecedor||"",total_repasse:total};
}
async function regularizeProductHistoryV181(user:any,productId:string){
  const p=await rowByIdV181("produtos",productId);if(!p)throw new Error("Produto não encontrado.");const [items,reps,sales]=await Promise.all([allRowsV181("venda_itens"),allRowsV181("consignacao_repasses"),allRowsV181("vendas")]),sm:any={};sales.forEach(s=>sm[String(s.id)]=s);
  const targets=items.filter(i=>String(i.produto_id)===String(productId)&&saleItemActiveV181(i)&&(!i.finalidade||String(i.finalidade).toUpperCase()!=="VENDA"||!i.modelo_comercial)),updates:any[]=[],newReps:any[]=[];
  for(const i of targets){const s=sm[String(i.venda_id)]||{},dest=i.destino||s.destino||"CLIENTE",unit=String(p.modelo_comercial||"NORMAL").toUpperCase()==="CONSIGNADO"?numV181(p.valor_repasse_fornecedor):0;
    updates.push({id:i.id,finalidade:"VENDA",modelo_comercial:p.modelo_comercial||"NORMAL",fornecedor:p.fornecedor||"",custo_unitario_snapshot:numV181(p.custo_unitario),valor_repasse_fornecedor_snapshot:unit,preco_referencia_venda:numV181(p.preco_venda),destino:dest});
    if(unit>0&&!reps.some(r=>String(r.origem_item_id)===String(i.id)&&!["CANCELADO","SUBSTITUIDO"].includes(String(r.status||"").toUpperCase()))){const total=round2V181(unit*numV181(i.quantidade)),saleVal=numV181(i.valor_bruto);newReps.push({id:uidV181("CRP"),data:dateOnlyV181(s.data),produto_id:p.id,produto_nome:p.produto,fornecedor:p.fornecedor||"",origem_tipo:"VENDA",origem_id:i.venda_id,origem_item_id:i.id,destino:dest,quantidade:numV181(i.quantidade),valor_unitario_repasse:unit,valor_total_repasse:total,valor_venda_total:saleVal,resultado_bruto:round2V181(saleVal-total),status:"PENDENTE",data_pagamento:null,forma_pagamento:null,fechamento_id:null,observacoes:"Regularização retroativa v1.8.1",usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()});}}
  if(updates.length){const audit=[{id:uidV181("AUD"),data_hora:nowIsoV181(),usuario_id:user.id,usuario_nome:user.nome,acao:"REGULARIZAR",entidade:"PRODUTO_HISTORICO",entidade_id:productId,detalhes:JSON.stringify({updated:updates.length,repasses:newReps.length})}],x=await db.rpc("studio_consignment_tx_v181",{p_action:"REGULARIZE",p_payload:{repasses:newReps,item_updates:updates,audit},p_user:{id:user.id,nome:user.nome}});if(x.error)throw new Error(x.error.message);}
  return {ok:true,updated:updates.length,repasses_criados:newReps.length};
}
// ============================= fim Compatibilidade final / relatórios =============================

async function dispatch(fn: string, args: any[]) {
  switch (fn) {
    case "apiAppState": {
      const { count } = await db.from("usuarios").select("id", { count: "exact", head: true }).eq("ativo", true);
      return { version: VERSION, needsBootstrap: Number(count || 0) === 0, seeded: false };
    }
    case "apiBootstrapAdminV112": {
      return await bootstrapAdminCompatV181(args?.[0]||{});
    }
    case "apiLoginV112": {
      const payload = args?.[0] || {};
      const ident = normalize(payload.identificador);
      const pin = String(payload.pin || "");
      if (!ident || !pin) throw new Error("Informe usuário/e-mail e PIN.");
      const { data: user, error } = await db.from("usuarios").select("*").eq("identificador", ident).eq("ativo", true).maybeSingle();
      if (error || !user) throw new Error("Usuário ou PIN inválido.");
      if (user.primeiro_acesso_pendente) throw new Error("FIRST_ACCESS_REQUIRED");
      const hash = await sha256("studio-essence|" + pin);
      if (String(user.pin_hash || "") !== hash) throw new Error("Usuário ou PIN inválido.");
      const token = crypto.randomUUID() + crypto.randomUUID();
      const expires = new Date(Date.now() + SESSION_HOURS * 3600_000).toISOString();
      await db.from("migration_sessions").insert({ token, usuario_id: user.id, expires_at: expires });
      await db.from("usuarios").update({ ultimo_login: new Date().toISOString(), atualizado_em: new Date().toISOString() }).eq("id", user.id);
      return JSON.stringify({ ok: true, token, user: publicUser({...user,ultimo_login:new Date().toISOString()}) });
    }
    case "apiGenerateTemporaryAccessV181": {
      const admin=await requireAuth(String(args?.[0]||""),true);
      return await generateTemporaryAccessV181(admin,args?.[1]);
    }
    case "apiActivateMigratedUserV181": {
      return await activateMigratedUserV181(args?.[0]||{});
    }
    case "apiSessionBootstrapV154":
    case "apiSessionBootstrapV146":
    case "apiSessionBootstrapV120":
    case "apiSessionBootstrapV112": {
      const user = await requireAuth(String(args?.[0] || ""), false);
      return JSON.stringify(emptyBootstrap(user));
    }
    case "apiLogout": {
      const token = String(args?.[0] || "");
      if (token) await db.from("migration_sessions").delete().eq("token", token);
      return true;
    }
    case "apiForceRefreshCachesV158HF1": {
      await requireAuth(String(args?.[0] || ""), false);
      return { ok:true, cache_cleared:false, mode:"SUPABASE_DIRECT_READ" };
    }
    case "apiDashboard":
    case "apiDashboardV146":
    case "apiDashboardV149":
    case "apiDashboardV180": {
      const user = await requireAuth(String(args?.[0] || ""), false);
      return await dashboardSnapshotV181(user,args?.[1]||{});
    }
    case "apiDashboardMonthlyV159":
    case "apiDashboardMonthlyV181": {
      await requireAuth(String(args?.[0] || ""), true);
      return await dashboardMonthlyDataV181(args?.[1]);
    }
    case "apiBirthdays": {
      await requireAuth(String(args?.[0]||""),false);const month=Math.max(1,Math.min(12,Math.floor(numV181(args?.[1])||Number(todayV181().slice(5,7))))),[clients,atts]=await Promise.all([allRowsV181("clientes"),allRowsV181("atendimentos")]),last={};atts.filter(a=>String(a.status)!=="CANCELADO").forEach(a=>{const d=dateOnlyV181(a.data);if(!last[a.cliente_id]||d>last[a.cliente_id])last[a.cliente_id]=d;});return clients.filter(c=>isActiveV181(c.ativo)&&numV181(c.aniversario_mes)===month).map(c=>{const la=last[c.id]||"",days=la?Math.max(0,Math.floor((new Date(todayV181()+"T12:00:00-03:00")-new Date(la+"T12:00:00-03:00"))/86400000)):null;return {id:c.id,nome:clientNameV181(c),dia:numV181(c.aniversario_dia),mes:month,telefone:c.telefone||"",ultimo_atendimento:la,dias_desde_ultimo:days};}).sort((a,b)=>a.dia-b.dia||String(a.nome).localeCompare(String(b.nome),"pt-BR"));
    }
    case "apiPaymentFinancialAccountsV172": {
      await requireAuth(String(args?.[0]||""),false);const a=(await allRowsV181("contas_financeiras")).filter(x=>isActiveV181(x.ativo));return a.map(x=>({id:x.id,nome:x.nome,tipo:x.tipo,transitoria:boolV181(x.transitoria,false)}));
    }
    case "apiReferenceDataV154": {
      const user = await requireAuth(String(args?.[0] || ""), false);
      return JSON.stringify(await referenceDataV181(user,false));
    }
    case "apiGlobalSearchV150HF3": {
      const user=await requireAuth(String(args?.[0]||""),false); return await globalSearchV181(user,args?.[1]);
    }
    case "apiRebuildPerformanceIndexesV156":
    case "apiRebuildPerformanceIndexesV157": {
      const user=await requireAuth(String(args?.[0]||""),true); return await rebuildAttendanceIndexV181(user);
    }
    case "apiRegularizeProductHistoryV153HF1": {
      const user=await requireAuth(String(args?.[0]||""),true); return await regularizeProductHistoryV181(user,String(args?.[1]?.product_id||args?.[1]||""));
    }
    case "apiSaveClient": { const user=await requireAuth(String(args?.[0]||""),false); return await saveClientV181(user,args?.[1]||{}); }
    case "apiSaveService": { const user=await requireAuth(String(args?.[0]||""),true); return await saveServiceV181(user,args?.[1]||{}); }
    case "apiSaveProfessional": { const user=await requireAuth(String(args?.[0]||""),true); return await saveProfessionalV181(user,args?.[1]||{}); }
    case "apiSaveProduct": { const user=await requireAuth(String(args?.[0]||""),true); return await saveProductV181(user,args?.[1]||{}); }
    case "apiSaveSpecialty": { const user=await requireAuth(String(args?.[0]||""),true); return await saveSpecialtyV181(user,args?.[1]||{}); }
    case "apiSavePaymentMethod": { const user=await requireAuth(String(args?.[0]||""),true); return await savePaymentMethodV181(user,args?.[1]||{}); }
    case "apiSaveServiceCategory": { const user=await requireAuth(String(args?.[0]||""),true); const id=await saveSimpleCategoryV181(user,"categorias_servicos","CSV","CATEGORIA_SERVICO",args?.[1]||{}); const cat=await rowByIdV181("categorias_servicos",id); if(cat){const sv=await allRowsV181("servicos");for(const s of sv.filter(x=>String(x.categoria_servico_id)===String(id)))await updateV181("servicos",s.id,{categoria:cat.nome,atualizado_em:nowIsoV181()});const pl=await allRowsV181("profissional_servicos");for(const r of pl.filter(x=>String(x.categoria_servico_id)===String(id)))await updateV181("profissional_servicos",r.id,{categoria:cat.nome,atualizado_em:nowIsoV181()});} return id; }
    case "apiSaveExpenseCategory": { const user=await requireAuth(String(args?.[0]||""),true); return await saveSimpleCategoryV181(user,"categorias_despesas","CDP","CATEGORIA_DESPESA",args?.[1]||{}); }
    case "apiSaveExpenseSubcategory": { const user=await requireAuth(String(args?.[0]||""),true); return await saveExpenseSubcategoryV181(user,args?.[1]||{}); }
    case "apiSaveProductCategory": { const user=await requireAuth(String(args?.[0]||""),true); const id=await saveSimpleCategoryV181(user,"categorias_produtos","CPR","CATEGORIA_PRODUTO",args?.[1]||{}); const cat=await rowByIdV181("categorias_produtos",id); if(cat){const ps=await allRowsV181("produtos");for(const p of ps.filter(x=>String(x.categoria_produto_id)===String(id)))await updateV181("produtos",p.id,{categoria:cat.nome,atualizado_em:nowIsoV181()});} return id; }
    case "apiSaveCampaign": { const user=await requireAuth(String(args?.[0]||""),true); return await saveCampaignV181(user,args?.[1]||{}); }
    case "apiCreateUser": { const user=await requireAuth(String(args?.[0]||""),true); return await createUserV181(user,args?.[1]||{}); }
    case "apiUpdateUser": { const user=await requireAuth(String(args?.[0]||""),true); return await updateUserV181(user,args?.[1]||{}); }
    case "apiResetUserPin": { const user=await requireAuth(String(args?.[0]||""),true); const id=String(args?.[1]||""),pin=validatePinV181(args?.[2]); await updateV181("usuarios",id,{pin_hash:await sha256("studio-essence|"+pin),primeiro_acesso_pendente:false,codigo_ativacao_hash:null,codigo_ativacao_expira_em:null,ativacao_tentativas:0,ativacao_bloqueado_ate:null,atualizado_em:nowIsoV181()}); await auditV181(user,"ALTERAR_PIN","USUARIO",id,{}); return true; }
    case "apiChangeOwnPin": { const user=await requireAuth(String(args?.[0]||""),false),p=args?.[1]||{}; const current=String(p.current_pin||"").trim(),next=validatePinV181(p.new_pin),confirm=String(p.confirm_pin||"").trim(); if(String(user.pin_hash||"")!==await sha256("studio-essence|"+current))throw new Error("A senha atual está incorreta.");if(next!==confirm)throw new Error("A confirmação da nova senha não confere.");if(await sha256("studio-essence|"+next)===String(user.pin_hash||""))throw new Error("A nova senha deve ser diferente da senha atual.");await updateV181("usuarios",user.id,{pin_hash:await sha256("studio-essence|"+next),atualizado_em:nowIsoV181()});await auditV181(user,"ALTERAR_PROPRIA_SENHA","USUARIO",user.id,{});return true; }
    case "apiSetActive": { const user=await requireAuth(String(args?.[0]||""),true); return await setActiveV181(user,args?.[1],args?.[2],!!args?.[3]); }
    case "apiDeleteProfessional": { const user=await requireAuth(String(args?.[0]||""),true),id=String(args?.[1]||""),p=await rowByIdV181("profissionais",id);if(!p||professionalDeletedV181(p))throw new Error("Profissional não encontrada.");await updateV181("profissionais",id,{ativo:false,excluido:true,atualizado_em:nowIsoV181()});await auditV181(user,"EXCLUIR_LOGICO","PROFISSIONAL",id,{nome:p.nome,observacao:"Histórico preservado"});return true; }
    case "apiDeleteProduct": { const user=await requireAuth(String(args?.[0]||""),true),id=String(args?.[1]||""),p=await rowByIdV181("produtos",id);if(!p||productDeletedV181(p))throw new Error("Produto não encontrado.");await updateV181("produtos",id,{ativo:false,excluido:true,atualizado_em:nowIsoV181()});await auditV181(user,"EXCLUIR_LOGICO","PRODUTO",id,{produto:p.produto,observacao:"Histórico preservado"});return true; }
    case "apiSetServiceEquivalent": { const user=await requireAuth(String(args?.[0]||""),true),p=args?.[1]||{},legacy=await rowByIdV181("servicos",p.legacy_id);if(!legacy||catalogStatusV181(legacy)!=="LEGADO")throw new Error("Serviço legado inválido.");let current=null;if(p.current_id){current=await rowByIdV181("servicos",p.current_id);if(!current||catalogStatusV181(current)!=="ATUAL"||!isActiveV181(current.ativo))throw new Error("Selecione um serviço atual válido.");}await updateV181("servicos",legacy.id,{equivalente_atual_id:current?current.id:"",atualizado_em:nowIsoV181()});await auditV181(user,"VINCULAR_EQUIVALENTE","SERVICO",legacy.id,{legado:legacy.nome,equivalente_atual:current?current.nome:""});return true; }
    case "apiSetProfessionalFeePolicyV148": { const user=await requireAuth(String(args?.[0]||""),true),id=String(args?.[1]||""),discount=!!args?.[2],prof=await rowByIdV181("profissionais",id);if(!prof)throw new Error("Profissional não encontrada.");const forms=(await allRowsV181("formas_pagamento")).filter(f=>isActiveV181(f.ativo)),rules=await allRowsV181("profissional_regras_taxa");for(const f of forms){const r=rules.find(x=>String(x.profissional_id)===id&&String(x.forma_id)===String(f.id)),patch={profissional_nome:prof.nome,forma_nome:f.nome,desconta_taxa:discount,ativo:true,atualizado_em:nowIsoV181()};if(r)await updateV181("profissional_regras_taxa",r.id,patch);else await insertV181("profissional_regras_taxa",{id:uidV181("RGR"),profissional_id:id,forma_id:f.id,criado_em:nowIsoV181(),...patch});}await auditV181(user,"ALTERAR","REGRA_TAXA_PROFISSIONAL_GLOBAL",id,{profissional:prof.nome,desconta_taxas:discount});return true; }
    case "apiSaveRate": { const user=await requireAuth(String(args?.[0]||""),true); return await saveRateV181(user,args?.[1]||{}); }
    case "apiSaveFeeRule": { const user=await requireAuth(String(args?.[0]||""),true); return await saveFeeRuleV181(user,args?.[1]||{}); }
    case "apiSetRateActiveHF172": { const user=await requireAuth(String(args?.[0]||""),true),id=String(args?.[1]||""),active=!!args?.[2],r=await rowByIdV181("taxas_pagamento",id);if(!r)throw new Error("Taxa não encontrada.");if(!active){if(!isActiveV181(r.ativo))return true;await updateV181("taxas_pagamento",id,{ativo:false,vigencia_fim:previousDayV181(todayV181()),atualizado_em:nowIsoV181()});await auditV181(user,"INATIVAR","TAXA_PAGAMENTO",id,r);return true;}return await saveRateV181(user,{id:r.id,forma_id:r.forma_id,bandeira:r.bandeira||"",condicao:r.condicao||"QUALQUER",percentual:numV181(r.percentual)*100,taxa_fixa:r.taxa_fixa,vigencia_inicio:todayV181(),vigencia_fim:""}); }
    case "apiSetFeeRuleActiveHF172": { const user=await requireAuth(String(args?.[0]||""),true),id=String(args?.[1]||""),active=!!args?.[2],r=await rowByIdV181("profissional_regras_taxa",id);if(!r)throw new Error("Regra não encontrada.");if(!active){if(!isActiveV181(r.ativo))return true;await updateV181("profissional_regras_taxa",id,{ativo:false,vigencia_fim:previousDayV181(todayV181()),atualizado_em:nowIsoV181()});await auditV181(user,"INATIVAR","REGRA_TAXA_PROFISSIONAL",id,r);return true;}return await saveFeeRuleV181(user,{id:r.id,profissional_id:r.profissional_id,forma_id:r.forma_id,desconta_taxa:!!r.desconta_taxa,vigencia_inicio:todayV181(),vigencia_fim:""}); }
    case "apiListClients": {
      await requireAuth(String(args?.[0]||""),false); const f=args?.[1]||{},q=normalizeTextV181(String(f.q||"").trim()),qid=String(f.client_id||""),rows=await allRowsV181("clientes");
      return rows.filter(c=>{if(!isActiveV181(c.ativo))return false;const d=dateOnlyV181(c.data_cadastro||c.criado_em);if(f.start&&d<dateOnlyV181(f.start))return false;if(f.end&&d>dateOnlyV181(f.end))return false;if(qid&&String(c.id)!==qid)return false;if(q&&normalizeTextV181([clientNameV181(c),c.telefone,c.id].join(" ")).indexOf(q)<0)return false;return true;}).map(c=>({id:c.id,nome:c.nome,sobrenome:c.sobrenome||"",nome_completo:clientNameV181(c),telefone:c.telefone||"",aniversario_dia:numV181(c.aniversario_dia),aniversario_mes:numV181(c.aniversario_mes),data_cadastro:dateOnlyV181(c.data_cadastro||c.criado_em),observacoes:c.observacoes||""})).sort((a,b)=>String(b.data_cadastro).localeCompare(String(a.data_cadastro))||String(a.nome_completo).localeCompare(String(b.nome_completo),"pt-BR"));
    }
    case "apiListStockMoves": {
      await requireAuth(String(args?.[0]||""),false);const f=args?.[1]||{},rows=await allRowsV181("estoque_movimentos");return rows.filter(m=>{const st=String(m.status||"").toUpperCase();if(st&& !["ATIVO","REALIZADO","CONCLUIDO"].includes(st))return false;const d=dateOnlyV181(m.data);if(f.start&&d<dateOnlyV181(f.start))return false;if(f.end&&d>dateOnlyV181(f.end))return false;if(f.produto_id&&String(m.produto_id)!==String(f.produto_id))return false;return true;}).sort((a,b)=>String(b.data||"").localeCompare(String(a.data||""))).slice(0,500).map(m=>({data:dateOnlyV181(m.data),produto:m.produto_nome,tipo:m.tipo,quantidade:numV181(m.quantidade),profissional:m.profissional_nome||"",usuario:m.usuario_nome||"",observacoes:m.observacoes||""}));
    }
    case "apiSaveCategory": {
      const user=await requireAuth(String(args?.[0]||""),true),p=args?.[1]||{},type=String(p.tipo||"DESPESA").toUpperCase();
      if(type==="SERVICO")return await saveSimpleCategoryV181(user,"categorias_servicos","CSV","CATEGORIA_SERVICO",{id:p.id,nome:p.categoria});
      if(p.subcategoria)return await saveExpenseSubcategoryV181(user,{id:p.id,categoria_despesa_id:p.categoria_id,nome:p.subcategoria});
      return await saveSimpleCategoryV181(user,"categorias_despesas","CDP","CATEGORIA_DESPESA",{id:p.id,nome:p.categoria});
    }
    case "apiSaveStockMove": {
      const user=await requireAuth(String(args?.[0]||""),false),p=args?.[1]||{},prod=await rowByIdV181("produtos",p.produto_id);if(!prod||!isActiveV181(prod.ativo)||productDeletedV181(prod))throw new Error("Produto não encontrado ou inativo.");
      const type=String(p.tipo||"RETIRADA").toUpperCase(),purpose=String(prod.finalidade||"OPERACIONAL").toUpperCase()==="VENDA"?"VENDA":"OPERACIONAL";if(!["ENTRADA","RETIRADA","PERDA","AJUSTE"].includes(type))throw new Error("Tipo de movimentação inválido.");if(purpose==="VENDA"&&type==="RETIRADA")throw new Error("Retirada é permitida somente para Estoque Operacional. Produtos para Venda saem pelo módulo de Vendas.");
      const q=Math.abs(numV181(p.quantidade));if(q<=0)throw new Error("Informe a quantidade.");if(type==="RETIRADA"&&!p.profissional_id)throw new Error("Informe a profissional que solicitou a retirada.");const current=round2V181(prod.estoque_atual);let delta=type==="ENTRADA"?q:-q;if(type==="AJUSTE")delta=numV181(p.quantidade);if((type==="RETIRADA"||type==="PERDA")&&q>current)throw new Error("Estoque insuficiente. Disponível: "+current+" "+String(prod.unidade||"unidade")+".");const newStock=round2V181(current+delta);if(newStock<0&&type!=="AJUSTE")throw new Error("Estoque insuficiente.");
      const prof=p.profissional_id?await rowByIdV181("profissionais",p.profissional_id):null;if(p.profissional_id&&(!prof||!isActiveV181(prof.ativo)))throw new Error("Profissional não encontrada ou inativa.");await updateV181("produtos",prod.id,{estoque_atual:newStock,atualizado_em:nowIsoV181()});const id=uidV181("EST"),row={id,data:dateOnlyV181(p.data||todayV181()),produto_id:prod.id,produto_nome:prod.produto,tipo:type,quantidade:delta,profissional_id:prof?prof.id:"",profissional_nome:prof?prof.nome:"",custo_total:round2V181(p.custo_total),observacoes:String(p.observacoes||""),usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),referencia_tipo:"MANUAL",referencia_id:"",status:"ATIVO"};await insertV181("estoque_movimentos",row);await auditV181(user,"MOVIMENTAR","ESTOQUE",id,{produto:prod.produto,finalidade:purpose,tipo:type,quantidade:delta,estoque_anterior:current,estoque_atual:newStock});return {ok:true,produto_id:prod.id,estoque:newStock,unidade:prod.unidade||"unidade"};
    }
    case "apiFinancialPositionV172":
    case "apiFinancialPositionV170": { await requireAuth(String(args?.[0]||""),true); return await financialPositionV181(); }
    case "apiSaveContributionV172": { const user=await requireAuth(String(args?.[0]||""),true);return await saveContributionV181(user,args?.[1]||{}); }
    case "apiListCardReceivablesV172": { await requireAuth(String(args?.[0]||""),true);return await cardReceivablesV181(args?.[1]||{}); }
    case "apiSettleCardReceivableV172": { const user=await requireAuth(String(args?.[0]||""),true);return await settleCardReceivableV181(user,String(args?.[1]||""),args?.[2]||{}); }
    case "apiListThirdPartyV172": { await requireAuth(String(args?.[0]||""),true);return await thirdPartyListV181(); }
    case "apiSaveThirdPartyV172": { const user=await requireAuth(String(args?.[0]||""),true);return await thirdPartySaveV181(user,args?.[1]||{}); }
    case "apiPayThirdPartyV172": { const user=await requireAuth(String(args?.[0]||""),true);return await thirdPartyPayV181(user,String(args?.[1]||""),args?.[2]||{}); }
    case "apiReconcileAccountV172": { const user=await requireAuth(String(args?.[0]||""),true);return await reconcileAccountV181(user,args?.[1]||{}); }
    case "apiListReconciliationsV172": { await requireAuth(String(args?.[0]||""),true);return await reconciliationListV181(args?.[1]||{}); }
    case "apiImportStatementV172": { const user=await requireAuth(String(args?.[0]||""),true);return await importStatementV181(user,args?.[1]||{}); }
    case "apiListStatementV172": { await requireAuth(String(args?.[0]||""),true);return await statementListV181(args?.[1]||{}); }
    case "apiStatementMatchCandidatesV172": { await requireAuth(String(args?.[0]||""),true);return await statementMatchCandidatesV181(String(args?.[1]||"")); }
    case "apiMatchStatementV172": { const user=await requireAuth(String(args?.[0]||""),true);return await statementMatchV181(user,String(args?.[1]||""),String(args?.[2]||"")); }
    case "apiCreateAdjustmentFromStatementV172": { const user=await requireAuth(String(args?.[0]||""),true);return await statementClassifyV181(user,String(args?.[1]||""),args?.[2]||{}); }
    case "apiIgnoreStatementV172": { const user=await requireAuth(String(args?.[0]||""),true);return await statementIgnoreV181(user,String(args?.[1]||"")); }
    case "apiReclassifyCashAccountV172": { const user=await requireAuth(String(args?.[0]||""),true);return await reclassifyCashV181(user,String(args?.[1]||""),String(args?.[2]||"")); }

    case "apiFinancialBootstrapV172": {
      await requireAuth(String(args?.[0]||""),true);const [pos,maps,pays,ec,es,rc,rs]=await Promise.all([financialPositionV181(),allRowsV181("forma_conta_financeira"),allRowsV181("formas_pagamento"),allRowsV181("categorias_despesas"),allRowsV181("subcategorias_despesas"),allRowsV181("categorias_receitas"),allRowsV181("subcategorias_receitas")]);return {accounts:pos.accounts,position:pos,mappings:maps.filter(m=>isActiveV181(m.ativo)).map(m=>({forma_id:m.forma_id,forma_nome:m.forma_nome,conta_financeira_id:m.conta_financeira_id,conta_financeira_nome:m.conta_financeira_nome})),paymentMethods:pays.filter(x=>isActiveV181(x.ativo)).map(x=>({id:x.id,nome:x.nome})),expenseCategories:ec.filter(x=>isActiveV181(x.ativo)).map(x=>({id:x.id,nome:x.nome})),expenseSubcategories:es.filter(x=>isActiveV181(x.ativo)).map(x=>({id:x.id,categoria_id:x.categoria_despesa_id,nome:x.nome})),revenueCategories:rc.filter(x=>isActiveV181(x.ativo)).map(x=>({id:x.id,nome:x.nome})),revenueSubcategories:rs.filter(x=>isActiveV181(x.ativo)).map(x=>({id:x.id,categoria_id:x.categoria_receita_id,nome:x.nome}))};
    }
    case "apiSaveFinancialAccountV172": { const user=await requireAuth(String(args?.[0]||""),true);return await saveFinancialAccountV181(user,args?.[1]||{}); }
    case "apiSavePaymentAccountMapV172": { const user=await requireAuth(String(args?.[0]||""),true),p=args?.[1]||{},f=await rowByIdV181("formas_pagamento",p.forma_id),a=await rowByIdV181("contas_financeiras",p.conta_financeira_id);if(!f||!isActiveV181(f.ativo))throw new Error("Forma de pagamento inválida.");if(!a)throw new Error("Conta financeira não encontrada.");const maps=await allRowsV181("forma_conta_financeira"),old=maps.find(x=>String(x.forma_id)===String(f.id)),patch={forma_id:f.id,forma_nome:f.nome,conta_financeira_id:a.id,conta_financeira_nome:a.nome,ativo:true,atualizado_em:nowIsoV181()};if(old)await updateV181("forma_conta_financeira",old.id,patch);else await insertV181("forma_conta_financeira",{id:uidV181("FCF"),...patch,criado_em:nowIsoV181()});await auditV181(user,"MAPEAR","FORMA_CONTA",f.id,{forma:f.nome,conta:a.nome});return true; }
    case "apiFinancialLedgerV172": { await requireAuth(String(args?.[0]||""),true);const f=args?.[1]||{},aid=String(f.account_id||""),start=dateOnlyV181(f.start||"1900-01-01"),end=dateOnlyV181(f.end||todayV181()),accounts=await allRowsV181("contas_financeiras"),selected=aid?accounts.filter(a=>String(a.id)===aid):accounts,mov=await allRowsV181("mov_caixa"),out=[];for(const a of selected){const d=new Date(start+"T12:00:00-03:00");d.setDate(d.getDate()-1);let bal=await accountBalanceAtV181(a,new Intl.DateTimeFormat("en-CA",{timeZone:"America/Sao_Paulo",year:"numeric",month:"2-digit",day:"2-digit"}).format(d));const rows=mov.filter(m=>String(m.status||"").toUpperCase()==="REALIZADO"&&String(m.conta_financeira_id||"")===String(a.id)&&dateOnlyV181(m.data)>=start&&dateOnlyV181(m.data)<=end).sort((x,y)=>String(x.data||"").localeCompare(String(y.data||""))||String(x.criado_em||"").localeCompare(String(y.criado_em||"")));for(const m of rows){bal=round2V181(bal+numV181(m.valor));out.push({id:m.id,data:dateOnlyV181(m.data),conta_id:a.id,conta:a.nome,tipo:m.tipo||"",descricao:m.descricao||"",impacto_resultado:boolV181(m.impacto_resultado,true),conciliado:boolV181(m.conciliado,false),valor:round2V181(m.valor),saldo:bal});}}return out.sort((a,b)=>String(b.data).localeCompare(String(a.data))||String(b.id).localeCompare(String(a.id))); }
    case "apiTransferFinancialV172": { const user=await requireAuth(String(args?.[0]||""),true),p=args?.[1]||{},from=await rowByIdV181("contas_financeiras",p.conta_origem_id),to=await rowByIdV181("contas_financeiras",p.conta_destino_id),value=round2V181(p.valor),date=dateOnlyV181(p.data||todayV181());if(!from||!to)throw new Error("Conta financeira não encontrada.");if(String(from.id)===String(to.id))throw new Error("Origem e destino devem ser contas diferentes.");if(value<=0)throw new Error("Informe um valor maior que zero.");const id=uidV181("TRF"),desc=String(p.descricao||"Transferência entre contas"),outId=await addCashV181(date,date,"TRANSFERENCIA","TRANSFERENCIA",id,desc,-value,"REALIZADO","",from.id,false,id),inId=await addCashV181(date,date,"TRANSFERENCIA","TRANSFERENCIA",id,desc,value,"REALIZADO","",to.id,false,id);await insertV181("transferencias_financeiras",{id,data:date,conta_origem_id:from.id,conta_origem_nome:from.nome,conta_destino_id:to.id,conta_destino_nome:to.nome,valor:value,descricao:desc,mov_saida_id:outId,mov_entrada_id:inId,status:"REALIZADO",usuario_id:user.id,usuario_nome:user.nome,criado_em:nowIsoV181(),atualizado_em:nowIsoV181()});await auditV181(user,"TRANSFERIR","CONTA_FINANCEIRA",id,p);return {id,outId,inId}; }
    case "apiListTransfersV172": { await requireAuth(String(args?.[0]||""),true);const f=args?.[1]||{},rows=await allRowsV181("transferencias_financeiras");return rows.filter(x=>String(x.status||"")!=="ESTORNADO"&&(!f.start||dateOnlyV181(x.data)>=dateOnlyV181(f.start))&&(!f.end||dateOnlyV181(x.data)<=dateOnlyV181(f.end))).sort((a,b)=>String(b.data).localeCompare(String(a.data))).map(x=>({id:x.id,data:dateOnlyV181(x.data),conta_origem_id:x.conta_origem_id,conta_origem_nome:x.conta_origem_nome,conta_destino_id:x.conta_destino_id,conta_destino_nome:x.conta_destino_nome,descricao:x.descricao||"",valor:round2V181(x.valor)})); }

    case "apiAuditListV170": {
      await requireAuth(String(args?.[0]||''),true);
      const f=args?.[1]||{}, start=dateOnlyV181(f.start), end=dateOnlyV181(f.end);
      const action=normalizeTextV181(f.action||''), entity=normalizeTextV181(f.entity||''), q=normalizeTextV181(f.text||'');
      const rows=await allRowsV181('auditoria');
      return rows.filter(a=>{
        const d=dateOnlyV181(a.data_hora);
        if(start&&d<start)return false; if(end&&d>end)return false;
        if(action&&normalizeTextV181(a.acao).indexOf(action)<0)return false;
        if(entity&&normalizeTextV181(a.entidade).indexOf(entity)<0)return false;
        if(q&&normalizeTextV181([a.usuario_nome,a.acao,a.entidade,a.entidade_id,a.detalhes].join(' ')).indexOf(q)<0)return false;
        return true;
      }).sort((a,b)=>String(b.data_hora||'').localeCompare(String(a.data_hora||''))).slice(0,1000)
        .map(a=>({id:a.id,data_hora:String(a.data_hora||''),usuario:a.usuario_nome||'',acao:a.acao||'',entidade:a.entidade||'',entidade_id:a.entidade_id||'',detalhes:a.detalhes||''}));
    }
    case "apiAuditExportV170": {
      const user=await requireAuth(String(args?.[0]||''),false), p=args?.[1]||{};
      await auditV181(user,'EXPORTAR_EXCEL',String(p.section||'TABELA').toUpperCase(),'',{titulo:String(p.title||''),formato:'XLS'});
      return true;
    }
    case "apiValidateStockIntegrityV170": {
      const user=await requireAuth(String(args?.[0]||''),true);
      const [products,moves]=await Promise.all([allRowsV181('produtos'),allRowsV181('estoque_movimentos')]);
      const valid=products.filter(p=>!productDeletedV181(p)), by={}, issues=[], sums={};
      valid.forEach(p=>by[String(p.id)]=p);
      moves.filter(m=>['','ATIVO','REALIZADO','CONCLUIDO'].includes(String(m.status||'').toUpperCase())).forEach(m=>{
        const pid=String(m.produto_id||'');
        if(!by[pid]){ issues.push({severity:'ERRO',product:m.produto_nome||'',message:'Movimentação ativa sem produto válido: '+String(m.id||'')+'.'}); return; }
        const qty=numV181(m.quantidade);
        if(Math.abs(qty)<0.000001) issues.push({severity:'ALERTA',product:by[pid].produto||'',message:'Movimentação ativa com quantidade zero: '+String(m.id||'')+'.'});
        sums[pid]=(sums[pid]||0)+qty;
      });
      valid.forEach(p=>{
        const stock=round2V181(p.estoque_atual), min=round2V181(p.estoque_minimo), sum=round2V181(sums[String(p.id)]||0);
        if(stock<0)issues.push({severity:'ERRO',product:p.produto||'',message:'Estoque atual negativo: '+stock+'.'});
        if(min<0)issues.push({severity:'ERRO',product:p.produto||'',message:'Estoque mínimo negativo.'});
        if(stock>=0&&min>0&&stock<=min)issues.push({severity:'ALERTA',product:p.produto||'',message:'Estoque no mínimo ou abaixo: '+stock+' / mínimo '+min+'.'});
        if(Math.abs(stock-sum)>0.01)issues.push({severity:'ALERTA',product:p.produto||'',message:'Saldo cadastrado ('+stock+') difere da soma das movimentações ativas ('+sum+'). Revisar histórico; nenhuma correção foi feita automaticamente.'});
        if(numV181(p.preco_venda)<0)issues.push({severity:'ERRO',product:p.produto||'',message:'Preço de venda negativo.'});
        if(numV181(p.custo_unitario)<0||numV181(p.valor_repasse_fornecedor)<0)issues.push({severity:'ERRO',product:p.produto||'',message:'Custo ou repasse negativo.'});
      });
      const summary={errors:issues.filter(x=>x.severity==='ERRO').length,warnings:issues.filter(x=>x.severity==='ALERTA').length,ok:issues.length===0};
      await auditV181(user,'VALIDAR','ESTOQUE','',{erros:summary.errors,alertas:summary.warnings,modo:'SOMENTE_LEITURA'});
      return {summary,issues};
    }
    case "apiRecordPerformanceBatchV157": {
      await requireAuth(String(args?.[0] || ""), false); return true;
    }
    case "apiProductsSnapshot": {
      const user=await requireAuth(String(args?.[0]||""),false); return await productsSnapshotV181(user);
    }
    case "apiClientsSnapshot": {
      await requireAuth(String(args?.[0]||""),false); const rows=await allRowsV181("clientes"); return rows.filter(r=>isActiveV181(r.ativo)).map(r=>({id:r.id,nome:r.nome,sobrenome:r.sobrenome||"",nome_completo:clientNameV181(r),telefone:r.telefone||"",aniversario_dia:Number(r.aniversario_dia||0),aniversario_mes:Number(r.aniversario_mes||0),data_cadastro:dateOnlyV181(r.data_cadastro)||dateOnlyV181(r.criado_em),observacoes:r.observacoes||"",ativo:true})).sort((a,b)=>String(a.nome_completo).localeCompare(String(b.nome_completo),"pt-BR"));
    }
    case "apiSettingsSnapshotV154": {
      const user = await requireAuth(String(args?.[0] || ""), true);
      return JSON.stringify(await referenceDataV181(user,true));
    }
    case "apiSaveAttendance": {
      const user=await requireAuth(String(args?.[0]||""),false),p=args?.[1]||{},id=uidV181("ATD");
      const prepared=await prepareAttendanceTxV181(user,p,id);
      return await attendanceRpcV181("CREATE",prepared,user);
    }
    case "apiGetAttendance": {
      const user=await requireAuth(String(args?.[0]||""),false);
      return await getAttendanceV181(user,String(args?.[1]||""));
    }
    case "apiUpdateAttendance": {
      const user=await requireAuth(String(args?.[0]||""),false),p=args?.[1]||{},a=await rowByIdV181("atendimentos",p.id);
      if(!a||String(a.status).toUpperCase()==="CANCELADO")throw new Error("Atendimento não encontrado.");
      if(!canViewAttendanceV181(user,a.data)||!canEditAttendanceV181(user,a.data))throw new Error("Seu usuário não possui permissão para editar atendimentos desta data.");
      const current=await getAttendanceV181(user,a.id);
      if(current.partial_edit){
        const partial=await partialAttendancePayloadV181(user,p,a);
        return await attendanceRpcV181("UPDATE_PARTIAL",partial,user);
      }
      if(!canEditAttendanceV181(user,p.data))throw new Error("A nova data está fora do período permitido para edição.");
      const prepared=await prepareAttendanceTxV181(user,p,a.id);
      return await attendanceRpcV181("UPDATE_FULL",prepared,user);
    }
    case "apiCancelAttendance": {
      const user=await requireAuth(String(args?.[0]||""),false),id=String(args?.[1]||""),a=await rowByIdV181("atendimentos",id);
      if(!a||String(a.status).toUpperCase()==="CANCELADO")throw new Error("Atendimento não encontrado ou já cancelado.");
      if(!canViewAttendanceV181(user,a.data)||!canCancelAttendanceV181(user,a.data))throw new Error("Seu usuário não possui permissão para cancelar atendimentos desta data.");
      const current=await getAttendanceV181(user,id);if(current.comissao_bloqueada)throw new Error("Este atendimento possui item já incluído em fechamento de comissão.");
      await attendanceRpcV181("CANCEL",{id},user);return true;
    }
    case "apiListAttendances": {
      const user=await requireAuth(String(args?.[0]||""),false);
      return await listAttendancesV181(user,args?.[1]||{});
    }
    case "apiAttendanceManagerReport": {
      const user=await requireAuth(String(args?.[0]||""),true); return await attendanceManagerReportV181(user,args?.[1]||{});
    }
    case "apiExportAttendancesXlsx": {
      const user=await requireAuth(String(args?.[0]||""),true); const rows=await listAttendancesV181(user,args?.[1]||{}),file=attendanceXlsxV181(rows);
      const start=dateOnlyV181(args?.[1]?.start||"1900-01-01"),end=dateOnlyV181(args?.[1]?.end||todayV181());
      return {filename:"Atendimentos_Studio_Essence_"+start+"_a_"+end+".xlsx",mimeType:"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",base64:bytesBase64V181(file)};
    }
    case "apiClientActivePackages": {
      await requireAuth(String(args?.[0]||""),false);
      return await clientActivePackagesV181(String(args?.[1]||""));
    }
    case "apiListPackages": {
      const user=await requireAuth(String(args?.[0]||""),false); return await packageListV181(user,args?.[1]||{});
    }
    case "apiGetPackage": {
      const user=await requireAuth(String(args?.[0]||""),false); return await packageGetV181(user,String(args?.[1]||""));
    }
    case "apiSavePackage": {
      const user=await requireAuth(String(args?.[0]||""),false); return await packageSaveV181(user,args?.[1]||{});
    }
    case "apiUpdatePackageProtectedV152": {
      const user=await requireAuth(String(args?.[0]||""),true); return await packageProtectedUpdateV181(user,args?.[1]||{});
    }
    case "apiDeletePackageV152": {
      const user=await requireAuth(String(args?.[0]||""),true); return await packageDeleteV181(user,String(args?.[1]||""));
    }
    case "apiCancelPackageWithRefundV152": {
      const user=await requireAuth(String(args?.[0]||""),true); return await packageCancelRefundV181(user,String(args?.[1]||""),args?.[2]);
    }
    case "apiPayPackageRefundV152": {
      const user=await requireAuth(String(args?.[0]||""),true); return await packagePayRefundV181(user,args?.[1]||{});
    }
    case "apiAssignPackageBeneficiaryV158": {
      const user=await requireAuth(String(args?.[0]||""),false); return await packageAssignBeneficiaryV181(user,args?.[1]||{});
    }
    case "apiClientPackageHistory": {
      const user=await requireAuth(String(args?.[0]||""),false); return await packageClientHistoryV181(user,String(args?.[1]||""));
    }
    case "apiPackageStatementV148": {
      const user=await requireAuth(String(args?.[0]||""),false); return await packageStatementV181(user,String(args?.[1]||""));
    }
    case "apiCalculatePackageRefundV152": {
      await requireAuth(String(args?.[0]||""),false); return await packageRefundCalcV181(String(args?.[1]||""));
    }
    case "apiListExpenses": {
      const user=await requireAuth(String(args?.[0]||""),false); return await expenseListV181(user,args?.[1]||{});
    }
    case "apiCommissionPreview": {
      await requireAuth(String(args?.[0]||""),true); return await commissionPreviewV181(args?.[1]||{});
    }
    case "apiSaveCommission": {
      const user=await requireAuth(String(args?.[0]||""),true); return await commissionSaveV181(user,args?.[1]||{});
    }
    case "apiCommissionHistory": {
      await requireAuth(String(args?.[0]||""),true); return await commissionHistoryV181(args?.[1]||{});
    }
    case "apiCommissionPdf": {
      await requireAuth(String(args?.[0]||""),true); return await commissionPdfV181(String(args?.[1]||""));
    }
    case "apiCommissionHistoryProfessionalsV160": {
      await requireAuth(String(args?.[0]||""),true); return await commissionHistoryProfessionalsV181();
    }
    case "apiGetCommissionClosingV148": {
      await requireAuth(String(args?.[0]||""),true); return await commissionGetClosingV181(String(args?.[1]||""));
    }
    case "apiUpdateCommissionClosingV148": {
      const user=await requireAuth(String(args?.[0]||""),true); return await commissionUpdateClosingV181(user,args?.[1]||{});
    }
    case "apiPayCommission": {
      const user=await requireAuth(String(args?.[0]||""),true); return await commissionPayV181(user,String(args?.[1]||""),args?.[2],args?.[3]);
    }
    case "apiListAdvances": {
      await requireAuth(String(args?.[0]||""),true); return await advanceListV181(args?.[1]||{});
    }
    case "apiSaveAdvance": {
      const user=await requireAuth(String(args?.[0]||""),true); return await advanceSaveV181(user,args?.[1]||{});
    }
    case "apiCancelAdvance": {
      const user=await requireAuth(String(args?.[0]||""),true); return await advanceCancelV181(user,String(args?.[1]||""));
    }
    case "apiGetExpense": {
      const user=await requireAuth(String(args?.[0]||""),false); return await expenseGetV181(user,String(args?.[1]||""));
    }
    case "apiSaveExpense": {
      const user=await requireAuth(String(args?.[0]||""),true); return await expenseSaveV181(user,args?.[1]||{});
    }
    case "apiUpdateExpense": {
      const user=await requireAuth(String(args?.[0]||""),false); return await expenseUpdateV181(user,args?.[1]||{});
    }
    case "apiPayExpenseParcel": {
      const user=await requireAuth(String(args?.[0]||""),true); return await expensePayV181(user,String(args?.[1]||""),args?.[2],args?.[3]);
    }
    case "apiSettleExpenseCardB4": {
      const user=await requireAuth(String(args?.[0]||""),true); return await expenseSettleCardV181(user,String(args?.[1]||""),args?.[2]||{});
    }
    case "apiCancelExpenseV150": {
      const user=await requireAuth(String(args?.[0]||""),true); return await expenseCancelV181(user,String(args?.[1]||""));
    }
    case "apiDeleteExpenseV150": {
      const user=await requireAuth(String(args?.[0]||""),true); return await expenseDeleteV181(user,String(args?.[1]||""));
    }
    case "apiListConsignmentRepaymentsV153": {
      await requireAuth(String(args?.[0]||""),false); return await consignmentListV181(args?.[1]||{});
    }
    case "apiPayConsignmentRepaymentsV153": {
      const user=await requireAuth(String(args?.[0]||""),true); return await consignmentPayV181(user,args?.[1]||{});
    }
    case "apiPreviewConsignmentRegularizationV153HF1": {
      await requireAuth(String(args?.[0]||""),true); return await consignmentPreviewRegularizationV181(args?.[1]||{});
    }
    case "apiRegularizeConsignmentHistoryV153HF1": {
      const user=await requireAuth(String(args?.[0]||""),true); return await consignmentRegularizeV181(user,args?.[1]||{});
    }
    case "apiSalesPageV159": {
      const user=await requireAuth(String(args?.[0]||""),false); return await salesPageV181(user,args?.[1]||{});
    }
    case "apiListSales": {
      const user=await requireAuth(String(args?.[0]||""),false); return await saleRowsV181(user,args?.[1]||{});
    }
    case "apiGetSale": {
      const user=await requireAuth(String(args?.[0]||""),false); return await saleGetV181(user,String(args?.[1]||""));
    }
    case "apiSaveSale": {
      const user=await requireAuth(String(args?.[0]||""),false); return await saleSaveV181(user,args?.[1]||{});
    }
    case "apiUpdateSale": {
      const user=await requireAuth(String(args?.[0]||""),false); return await saleUpdateV181(user,args?.[1]||{});
    }
    case "apiCancelSale": {
      const user=await requireAuth(String(args?.[0]||""),true); return await saleCancelV181(user,String(args?.[1]||""));
    }
    case "apiRevenueDomainsV149": {
      await requireAuth(String(args?.[0] || ""), false);
      return await revenueDomainsV181();
    }
    case "apiListRevenuesV149": {
      const user=await requireAuth(String(args?.[0] || ""), false);
      return await listRevenuesV181(user,args?.[1]||{});
    }
    case "apiRevenuePdfV170": {
      const user=await requireAuth(String(args?.[0]||""),false); return await revenuePdfV181(user,String(args?.[1]||""));
    }
    case "apiRevenueWhatsappV170": {
      const user=await requireAuth(String(args?.[0]||""),false); return await revenueWhatsappV181(user,String(args?.[1]||""));
    }
    case "apiSaveRevenueV149": {
      const user=await requireAuth(String(args?.[0] || ""), true);
      return await saveRevenueV181(user,args?.[1]||{});
    }
    case "apiGetRevenueV149": {
      const user=await requireAuth(String(args?.[0] || ""), false);
      return await getRevenueV181(user,String(args?.[1]||""));
    }
    case "apiUpdateRevenueV149": {
      const user=await requireAuth(String(args?.[0] || ""), false);
      return await updateRevenueV181(user,args?.[1]||{});
    }
    case "apiReceiveRevenueParcelV149": {
      const user=await requireAuth(String(args?.[0] || ""), true);
      return await receiveRevenueV181(user,String(args?.[1]||""),args?.[2]);
    }
    case "apiCancelRevenueV149": {
      const user=await requireAuth(String(args?.[0] || ""), true);
      return await cancelRevenueV181(user,String(args?.[1]||""));
    }
    case "apiDeleteRevenueV149": {
      const user=await requireAuth(String(args?.[0] || ""), true);
      return await deleteRevenueV181(user,String(args?.[1]||""));
    }
    case "apiAssetDomainsV150": {
      await requireAuth(String(args?.[0]||""),true); return await assetDomainsV181();
    }
    case "apiListAssetsV150": {
      await requireAuth(String(args?.[0]||""),true); return await assetListV181(args?.[1]||{});
    }
    case "apiGetAssetV150": {
      await requireAuth(String(args?.[0]||""),true); return await assetGetV181(String(args?.[1]||""));
    }
    case "apiSaveAssetV150": {
      const user=await requireAuth(String(args?.[0]||""),true); return await assetSaveV181(user,args?.[1]||{});
    }
    case "apiAssetHistoryV150": {
      await requireAuth(String(args?.[0]||""),true); return await assetHistoryV181(String(args?.[1]||""));
    }
    case "apiListAssetImportV150": {
      await requireAuth(String(args?.[0]||""),true); return await assetImportListV181();
    }
    case "apiImportInitialAssetsV150": {
      const user=await requireAuth(String(args?.[0]||""),true); return await assetImportV181(user,args?.[1]||[]);
    }
    case "apiDeleteAssetImportRowsV160": {
      const user=await requireAuth(String(args?.[0]||""),true); return await assetDeleteImportV181(user,args?.[1]||[]);
    }
    case "apiSellAssetV151":
    case "apiSellAssetV150": {
      const user=await requireAuth(String(args?.[0]||""),true); return await assetDisposeV181(user,args?.[1]||{},"SELL");
    }
    case "apiWriteOffAssetV151": {
      const user=await requireAuth(String(args?.[0]||""),true); return await assetDisposeV181(user,args?.[1]||{},"WRITEOFF");
    }
    case "apiWriteOffAssetV150": {
      const user=await requireAuth(String(args?.[0]||""),true); return await assetDisposeV181(user,{id:String(args?.[1]||""),quantidade:999999,data:todayV181(),motivo:args?.[2]||""},"WRITEOFF");
    }
    case "apiCustomerRankingV181": {
      await requireAuth(String(args?.[0] || ""), true);
      const d=await rankingRowsDataV181(args?.[1]||{});return {start:d.start,end:d.end,summary:d.summary,rows:d.rows.map(({rows,...r})=>r)};
    }
    case "apiCustomerRankingDetailV181": {
      await requireAuth(String(args?.[0] || ""), true);
      const f=args?.[1]||{},d=await rankingRowsDataV181(f),r=d.rows.find(x=>String(x.client_key)===String(f.client_key||""));
      if(!r)throw new Error("Cliente não encontrada no ranking deste período.");
      return {start:d.start,end:d.end,client:{client_key:r.client_key,client_name:r.client_name,phone:r.phone,revenue:r.revenue,interactions:r.interactions,ticket_average:r.ticket_average},rows:r.rows.slice().sort((a,b)=>String(a.date).localeCompare(String(b.date)))};
    }
    case "apiCommissionGeneratedDetailV181": {
      await requireAuth(String(args?.[0] || ""), true);
      return await commissionGeneratedDetailDataV181(args?.[1]||{});
    }
    case "apiCashFlowV180":
    case "apiCashFlow": {
      await requireAuth(String(args?.[0] || ""), true);
      return await cashFlowDataV181(args?.[1]||{});
    }
    default:
      throw new Error(`API ainda não portada para o preview de migração: ${fn}`);
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return fail("Método não permitido.", 405);
  try {
    const body = await req.json();
    const fn = String(body?.fn || "");
    const args = Array.isArray(body?.args) ? body.args : [];
    if (!fn) return fail("Função não informada.");
    return ok(await dispatch(fn, args));
  } catch (e) {
    return fail(e instanceof Error ? e.message : String(e));
  }
});