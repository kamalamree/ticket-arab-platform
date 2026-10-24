require("dotenv").config();
const { Client } = require("pg");

const client = new Client({
  connectionString: process.env.DATABASE_URL,
});

client.connect()
  .then(() => {
    console.log("Neon connected successfully ✅");
    return client.end();
  })
  .catch((err) => {
    console.error("Neon connection failed ❌");
    console.error(err.message);
  });