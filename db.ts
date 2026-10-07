import pg from 'pg';
const { Pool } = pg;
export const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : undefined });
export async function q<T=any>(text:string, params:any[]=[]){ return pool.query<T>(text, params); }
export async function withTransaction<T>(fn:(client:pg.PoolClient)=>Promise<T>):Promise<T>{
  const client=await pool.connect();
  try{await client.query('BEGIN');const out=await fn(client);await client.query('COMMIT');return out;}catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
}
