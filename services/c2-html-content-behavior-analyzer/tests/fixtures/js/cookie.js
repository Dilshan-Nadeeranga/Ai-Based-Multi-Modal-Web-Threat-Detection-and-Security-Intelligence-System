// Task 13: document.cookie read vs write.
var all = document.cookie;
var parts = document.cookie.split(";");
document.cookie = "session=1; path=/";
document.cookie += "; secure";
window.document.cookie = "tracked=yes";
