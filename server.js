import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const app=express();
app.set('trust proxy', 1);
const PORT=process.env.PORT||3000;
const ADMIN_USER=process.env.ADMIN_USER||'admin';
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD;
const SESSION_SECRET=process.env.SESSION_SECRET;
if(!ADMIN_PASSWORD||!SESSION_SECRET){console.error('ADMIN_PASSWORD ve SESSION_SECRET ortam değişkenleri gerekli.');process.exit(1)}
const passwordHash=bcrypt.hashSync(ADMIN_PASSWORD,12);
const dbPath=path.resolve(process.env.DATA_FILE || 'films.json');
let films=[];
try{films=JSON.parse(fs.readFileSync(dbPath,'utf8'));if(!Array.isArray(films))films=[]}catch{}
const save=()=>fs.writeFileSync(dbPath,JSON.stringify(films,null,2));
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'8mb'}));
app.use(session({secret:SESSION_SECRET,resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:86400000}}));
app.use(express.static('public'));
const admin=(req,res,next)=>req.session.admin?next():res.status(401).json({error:'Yönetici girişi gerekli'});
const safeUrl=(v)=>{try{const u=new URL(v);return ['http:','https:'].includes(u.protocol)?u.href:null}catch{return null}};
const clean=(v,max=200)=>String(v||'').trim().slice(0,max);
const normalize=(f)=>{const title=clean(f.title);const url=safeUrl(f.url);if(!title||!url)return null;return {id:clean(f.id)||crypto.randomUUID(),title,category:clean(f.category||'Diğer',60),description:clean(f.description,1500),poster:safeUrl(f.poster)||'',url,year:clean(f.year,4)}};
app.get('/api/films',(req,res)=>res.json(films));
app.get('/api/me',(req,res)=>res.json({admin:!!req.session.admin}));
app.post('/api/login',(req,res)=>{if(req.body.username===ADMIN_USER&&bcrypt.compareSync(String(req.body.password||''),passwordHash)){req.session.admin=true;return res.json({ok:true})}res.status(401).json({error:'Kullanıcı adı veya şifre yanlış'})});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.post('/api/films',admin,(req,res)=>{const f=normalize(req.body);if(!f)return res.status(400).json({error:'Geçerli film adı ve http(s) video adresi gerekli'});f.id=crypto.randomUUID();films.unshift(f);save();res.json(f)});
app.put('/api/films/:id',admin,(req,res)=>{const i=films.findIndex(f=>f.id===req.params.id);if(i<0)return res.sendStatus(404);const f=normalize({...req.body,id:films[i].id});if(!f)return res.sendStatus(400);films[i]=f;save();res.json(f)});
app.delete('/api/films/:id',admin,(req,res)=>{films=films.filter(f=>f.id!==req.params.id);save();res.json({ok:true})});
function parseM3U(text){const lines=text.replace(/^\uFEFF/,'').split(/\r?\n/);const out=[];let meta=null;for(const raw of lines){const line=raw.trim();if(line.startsWith('#EXTINF:')){const title=line.includes(',')?line.slice(line.indexOf(',')+1).trim():'İsimsiz Film';const attr=(key)=>{const match=line.match(new RegExp(key+'="([^"]*)"','i'));return match?.[1]||''};meta={title:attr('tvg-name')||title,poster:attr('tvg-logo'),category:attr('group-title')||'M3U',description:''}}else if(line&&!line.startsWith('#')&&meta){const f=normalize({...meta,url:line});if(f)out.push(f);meta=null}}return out}
app.post('/api/import-m3u',admin,(req,res)=>{const text=String(req.body.text||'');if(text.length>5_000_000)return res.status(413).json({error:'Liste çok büyük'});const items=parseM3U(text);const existing=new Set(films.map(f=>f.url));let added=0;for(const f of items){if(!existing.has(f.url)){films.push(f);existing.add(f.url);added++}}save();res.json({parsed:items.length,added})});
app.listen(PORT,()=>console.log(`Film Dünyası http://localhost:${PORT}`));
