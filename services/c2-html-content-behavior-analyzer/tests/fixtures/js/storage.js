// Task 14: localStorage / sessionStorage, methods and property / bracket access.
localStorage.setItem("token", token);
var saved = localStorage.getItem("token");
localStorage["user"] = name;
var user = localStorage["user"];
localStorage.removeItem("token");
sessionStorage.clear();
var store = window.sessionStorage;
store.getItem("step");
localStorage.theme = "dark";
var first = sessionStorage.key(0);
