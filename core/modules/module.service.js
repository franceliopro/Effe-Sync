import pg from 'pg';

const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === 'true'
        ? { rejectUnauthorized:true }
        : false
});


export async function hasModule(tenantId,moduleKey){

    const result = await pool.query(
        `
        SELECT enabled
        FROM modules
        WHERE tenant_id=$1
        AND module_key=$2
        LIMIT 1
        `,
        [
            tenantId,
            moduleKey
        ]
    );


    if(!result.rowCount){
        return false;
    }


    return result.rows[0].enabled === true;
}



export async function getTenantModules(tenantId){

    const result = await pool.query(
        `
        SELECT
            mc.module_key,
            mc.name,
            mc.description,
            COALESCE(m.enabled,false) enabled

        FROM module_catalog mc

        LEFT JOIN modules m
        ON m.module_key=mc.module_key
        AND m.tenant_id=$1

        ORDER BY mc.name
        `,
        [
            tenantId
        ]
    );


    return result.rows;
}
