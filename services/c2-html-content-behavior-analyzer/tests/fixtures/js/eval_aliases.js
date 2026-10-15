// Task 5: eval and the ways attackers write it.
eval("1 + 1");
window.eval("2");
window["eval"]("3");
globalThis.eval("4");
self['eval']("5");
top.eval("6");
(0, eval)("7");
var e = eval;
e("8");
eval.call(null, "9");
execScript("10");
setTimeout("alert(1)", 100);
window.setInterval('tick()', 1000);
setTimeout("go(" + id + ")", 5);
// not detections: a callback timer, eval in a string, eval in a comment
setTimeout(function () { done(); }, 100);
var text = "eval(not a call)";
// eval(inside a comment)
