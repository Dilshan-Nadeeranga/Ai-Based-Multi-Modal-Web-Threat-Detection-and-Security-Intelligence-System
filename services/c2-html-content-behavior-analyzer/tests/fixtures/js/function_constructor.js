// Task 6: functions built from strings.
var f1 = new Function("a", "b", "return a + b");
var f2 = Function("return this")();
[].constructor.constructor("alert(1)")();
obj.constructor("code");
Function.prototype.constructor("payload");
// not a detection: calling an object's constructor with values
this.constructor(a, b);
