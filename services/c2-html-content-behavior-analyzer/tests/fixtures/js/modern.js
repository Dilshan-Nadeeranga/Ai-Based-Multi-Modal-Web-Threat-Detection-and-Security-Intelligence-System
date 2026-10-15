// Modern syntax must parse without errors.
class Account {
  #secret = 1;
  static count = 0;
  get id() { return this.#secret; }
}
const host = config?.api?.host ?? "api.example";
const send = async (payload) => {
  const response = await fetch(`https://${host}/v1/send`, { method: "POST", body: payload });
  return response?.json?.();
};
const [a, { b: [c] }] = [1, { b: [2] }];
for (const item of items) console.log(`${item}`);
export default send;
