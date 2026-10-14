// Task 8: HTML strings put into elements.
document.getElementById("box").innerHTML = "<b>" + name + "</b>";
panel.innerHTML += row;
card.outerHTML = html;
list.insertAdjacentHTML("beforeend", item);
frame.srcdoc = page;
frame.setAttribute("srcdoc", page);
// not a detection: reading innerHTML
var current = panel.innerHTML;
