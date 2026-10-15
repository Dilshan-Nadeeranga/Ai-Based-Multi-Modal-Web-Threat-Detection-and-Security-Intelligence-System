// Task 15: clipboard APIs.
navigator.clipboard.writeText(walletAddress);
navigator.clipboard.readText().then(function (text) { steal(text); });
document.execCommand("copy");
document.execCommand("paste");
document.addEventListener("copy", function (e) {
  e.clipboardData.setData("text/plain", attackerWallet);
  e.preventDefault();
});
input.oncut = onCut;
var pasted = event.clipboardData.getData("text");
// not clipboard: other editing commands
document.execCommand("bold");
