const CACHE='studio-essence-mobile-v15';const SHELL=['./','./index.html','./manifest.webmanifest','./icon-192.png','./icon.svg'];self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL)));self.skipWaiting()});self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k.startsWith('studio-essence-mobile-')&&k!==CACHE).map(k=>caches.delete(k)))));self.clients.claim()});self.addEventListener('fetch',e=>{const u=new URL(e.request.url);if(e.request.method!=='GET'||u.origin!==self.location.origin)return;if(!u.pathname.startsWith('/mobile/'))return;e.respondWith(fetch(e.request).then(r=>{if(r.ok){const copy=r.clone();caches.open(CACHE).then(c=>c.put(e.request,copy))}return r}).catch(()=>caches.match(e.request)))});
self.addEventListener('push',event=>{
 let payload={title:'Studio Essence',body:'Você tem uma nova notificação.',url:'/mobile/'};
 try{if(event.data)payload={...payload,...event.data.json()}}catch(_){}
 const title=String(payload.title||'Studio Essence').slice(0,100);
 const safeUrl=String(payload.url||'/mobile/');
 const url=safeUrl.startsWith('/mobile/')?safeUrl:'/mobile/';
 event.waitUntil(self.registration.showNotification(title,{
  body:String(payload.body||'').slice(0,240),
  icon:'/mobile/icon-192.png',badge:'/mobile/icon-192.png',
  tag:String(payload.tag||'studio-essence-push'),renotify:false,
  data:{url}
 }));
});
self.addEventListener('notificationclick',event=>{
 event.notification.close();
 event.waitUntil((async()=>{
  const target=new URL(event.notification.data?.url||'/mobile/',self.location.origin);
  const windows=await clients.matchAll({type:'window',includeUncontrolled:true});
  for(const client of windows){if(new URL(client.url).origin===target.origin&&new URL(client.url).pathname.startsWith('/mobile/')){await client.focus();return;}}
  await clients.openWindow(target.href);
 })());
});
