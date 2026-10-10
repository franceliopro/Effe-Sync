import pool from '../database/connection.js';


export async function getTenantBranding(tenantId){

    if(!tenantId) return {};


    const result = await pool.query(
        `
        SELECT

            t.name AS tenant_name,

            b.brand_name,
            b.logo_url,
            b.primary_color,
            b.secondary_color,
            b.theme,
            b.favicon_url

        FROM tenants t

        LEFT JOIN tenant_branding b

        ON b.tenant_id=t.id

        WHERE t.id=$1
        `,
        [
            tenantId
        ]
    );


    return result.rows[0] || {};

}



export async function getCompanyContext(companyId){

    if(!companyId) return {};


    const result = await pool.query(
        `
        SELECT

            c.id AS company_id,
            c.name AS company_name,
            c.tenant_id,

            t.name AS tenant_name

        FROM companies c

        LEFT JOIN tenants t

        ON t.id=c.tenant_id

        WHERE c.id=$1
        `,
        [
            companyId
        ]
    );


    if(!result.rowCount)
        return {};


    const company=result.rows[0];


    const branding =
        await getTenantBranding(
            company.tenant_id
        );


    return {
        ...company,
        ...branding
    };

}
