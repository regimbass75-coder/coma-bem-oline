// UniGestor homologacao: shell offline sem interceptar API nem dados de outras empresas.
const CACHE='unigestor-hom-offline-v7';
const SHELL=['/','/manifest.webmanifest','/logo-unigestor.png'];
self.addEventListener('install',event=>{
 event.waitUntil((async()=>{
  const cache=await caches.open(CACHE);
  // A pagina publica e /; /index.html nao existe nesta rota Flask.
  await cache.add(new Request('/',{cache:'reload'}));
  await Promise.allSettled(SHELL.slice(1).map(url=>cache.add(url)));
  await self.skipWaiting();
 })());
});
self.addEventListener('activate',event=>{
 event.waitUntil((async()=>{
  const keys=await caches.keys();
  await Promise.all(keys.filter(k=>k.startsWith('comabem-hom-')||k.startsWith('unigestor-hom-offline-')).filter(k=>k!==CACHE).map(k=>caches.delete(k)));
  await self.clients.claim();
 })());
});
self.addEventListener('fetch',event=>{
 const req=event.request;
 if(req.method!=='GET')return;
 const url=new URL(req.url);
 if(url.origin!==self.location.origin)return;
 if(url.pathname.startsWith('/licenca/')||url.pathname.startsWith('/api/')||url.pathname==='/health')return;
 if(req.mode==='navigate'){
  event.respondWith((async()=>{
   try{
    const response=await fetch(req);
    if(response.ok && response.type==='basic'){
     const cache=await caches.open(CACHE);
     await cache.put('/',response.clone());
    }
    return response;
   }catch(e){
    return await caches.match('/') || Response.error();
   }
  })());
  return;
 }
 if(SHELL.includes(url.pathname)){
  event.respondWith((async()=>{
   const cached=await caches.match(url.pathname);
   if(cached)return cached;
   return fetch(req);
  })());
 }
});
