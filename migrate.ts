import fs from 'node:fs/promises'; import path from 'node:path'; import { fileURLToPath } from 'node:url'; import { pool } from './db.js';
const here=path.dirname(fileURLToPath(import.meta.url));
try{
  await pool.query(`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_type WHERE typname='user_role') THEN
    BEGIN ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'CUSTOMER'; EXCEPTION WHEN duplicate_object THEN NULL; END;
  END IF; END $$;`);
  const sql=await fs.readFile(path.join(here,'../sql/schema.sql'),'utf8');
  await pool.query(sql);
  console.log('Database schema ready.');
}finally{await pool.end();}
