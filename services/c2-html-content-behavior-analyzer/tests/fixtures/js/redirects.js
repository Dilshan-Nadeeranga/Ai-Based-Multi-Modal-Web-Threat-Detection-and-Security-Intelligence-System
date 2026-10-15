// Task 12: navigation from code.
location = "https://a.evil.test/";
location.href = "/same-site";
window.location.href = "https://b.evil.test/";
document.location.assign("https://c.evil.test/");
location.replace("https://d.evil.test/");
top.location.href = "https://e.evil.test/";
parent.location = "/frame";
self.location.replace("/self");
window.open("https://popup.evil.test/");
history.pushState({}, "", "https://f.evil.test/");
history.pushState({}, "", "/spa-route");
var m = document.createElement("meta");
m.httpEquiv = "refresh";
m.setAttribute("http-equiv", "refresh");
// not redirects: reading the address, changing only the fragment
var here = location.href;
location.hash = "#top";
