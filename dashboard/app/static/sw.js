// netmon service worker: shows Web Push notifications for urgent alerts. No offline caching.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { title: "netmon", body: e.data ? e.data.text() : "" }; }
  const title = d.title || "netmon alert";
  e.waitUntil(self.registration.showNotification(title, {
    body: d.body || "",
    tag: d.tag || "netmon",
    renotify: true,
    requireInteraction: d.severity === "investigate",
    icon: "/icon-192.png",
    badge: "/icon-192.png",
    data: { url: d.url || "/#/alerts" },
  }));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || "/#/alerts";
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const w of wins) {
      if (new URL(w.url).origin === self.location.origin) { await w.focus(); w.navigate ? w.navigate(url) : null; return; }
    }
    await self.clients.openWindow(url);
  })());
});
