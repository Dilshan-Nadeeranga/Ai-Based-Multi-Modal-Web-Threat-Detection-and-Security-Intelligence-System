const app = require("./app");
const { port } = require("./config/env");

app.listen(port, () => {
  console.log(`ScamTrace API Gateway running on port ${port}`);
});
