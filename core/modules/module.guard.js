import { hasModule } from './module.service.js';


export function requireModule(moduleKey){

    return async function(req,res,next){

        try{

            const tenantId =
                req.tenant_id ||
                req.user?.tenant_id ||
                req.company?.tenant_id;


            if(!tenantId){

                return res
                .status(403)
                .send('Tenant não identificado');

            }


            const allowed =
                await hasModule(
                    tenantId,
                    moduleKey
                );


            if(!allowed){

                return res
                .status(403)
                .send(
                    `Módulo ${moduleKey} não está ativo para este tenant`
                );

            }


            next();


        }catch(error){

            console.error(
                'Module guard:',
                error.message
            );


            res
            .status(500)
            .send('Erro ao validar módulo');

        }

    };

}
