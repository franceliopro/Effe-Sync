import pg from 'pg';


const pool = new pg.Pool({

    connectionString:
        process.env.DATABASE_URL,

    ssl:
        process.env.DATABASE_SSL === 'true'
        ? {
            rejectUnauthorized:true
          }
        : false

});


export default pool;
