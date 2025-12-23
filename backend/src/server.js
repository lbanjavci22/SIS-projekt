const app = require('./app');

const port = 4000;

app.listen(port, () => {
  console.log(`Backend sluša na http://localhost:${port}`);
});
