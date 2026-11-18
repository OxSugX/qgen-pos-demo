const CACHE = 'qgen-shell-v1';
const SHELL = ['/static/app.css','/static/app.js','/manifest.webmanifest'];
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(SHELL)).then(()=>self.skipWaiting()));
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});
self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
  // Only cache the application shell and static assets. Never cache private API or financial data.
  if (new URL(req.url).pathname === '/manifest.webmanifest' || new URL(req.url).pathname.startsWith('/static/')) {
    event.respondWith(fetch(req).then(res=>{
      const copy=res.clone(); caches.open(CACHE).then(cache=>cache.put(req,copy)); return res;
    }).catch(()=>caches.match(req)));
  }
});
