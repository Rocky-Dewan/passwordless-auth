import fs from 'fs';
import path from 'path';
import { Client } from 'pg';
import dotenv from 'dotenv';

// Use process.cwd() — always the project root when run via `npx ts-node scripts/migrate.ts`
// __dirname can resolve to unexpected locations with some ts-node / tsconfig combinations
const ROOT = process.cwd();
dotenv.config({ path: path.join(ROOT, '.env') });

const DB_HOST     = process.env.DB_HOST     || 'localhost';
const DB_PORT     = parseInt(process.env.DB_PORT || '5432', 10);
const DB_USER     = process.env.DB_USER     || 'auth_user';
const DB_PASSWORD = process.env.DB_PASSWORD || 'auth_password';
const DB_NAME     = process.env.DB_NAME     || 'passwordless_auth_db';

// Step 1: connect to the default "postgres" DB to create our DB if missing
async function ensureDatabase(): Promise<void> {
  const admin = new Client({
    host: DB_HOST, port: DB_PORT,
    user: DB_USER, password: DB_PASSWORD,
    database: 'postgres',   // always exists — safe bootstrap DB
  });

  try {
    await admin.connect();
    const { rows } = await admin.query(
      `SELECT 1 FROM pg_database WHERE datname = $1`, [DB_NAME]
    );
    if (rows.length === 0) {
      // identifiers cannot be parameterised — DB_NAME comes from .env, not user input
      await admin.query(`CREATE DATABASE "${DB_NAME}"`);
      console.log(`Created database "${DB_NAME}"`);
    } else {
      console.log(`Database "${DB_NAME}" already exists`);
    }
  } finally {
    await admin.end();
  }
}

// Step 2: connect to our DB and run the SQL schema
async function runMigration(): Promise<void> {
  const client = new Client({
    host: DB_HOST, port: DB_PORT,
    user: DB_USER, password: DB_PASSWORD,
    database: DB_NAME,
  });

  try {
    await client.connect();
    console.log(`Connected to "${DB_NAME}"`);
    const sql = fs.readFileSync(path.join(ROOT, 'scripts', 'migrate.sql'), 'utf8');
    await client.query(sql);
    console.log('Migration completed successfully ✓');
  } finally {
    await client.end();
  }
}

async function main(): Promise<void> {
  try {
    await ensureDatabase();
    await runMigration();
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  }
}

main();
