require('dotenv').config();
const readline = require('node:readline/promises');
const { stdin: input, stdout: output } = require('node:process');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

async function main() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is missing');
  const rl = readline.createInterface({ input, output });
  try {
    const email = (await rl.question('Admin email: ')).trim().toLowerCase();
    const password = await rl.question('Admin password (12+ characters): ');
    if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 12) throw new Error('Provide a valid email and a password of at least 12 characters');
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
      await pool.query('INSERT INTO admins(email,password_hash) VALUES($1,$2) ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash', [email, await bcrypt.hash(password, 12)]);
      console.log(`Admin account saved for ${email}`);
    } finally { await pool.end(); }
  } finally { rl.close(); }
}
main().catch(err => { console.error(err.message); process.exitCode = 1; });
