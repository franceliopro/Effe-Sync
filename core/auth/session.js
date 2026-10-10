import crypto from 'node:crypto';


const sign = value =>
    crypto
    .createHmac(
        'sha256',
        process.env.SESSION_SECRET
    )
    .update(value)
    .digest('hex');



export function current(req){

    const raw =
        String(req.headers.cookie || '')
        .split('; ')
        .find(
            x=>x.startsWith('bc_session=')
        )
        ?.slice(11);


    if(!raw)
        return false;


    const [
        exp,
        signature
    ] = raw.split('.');


    if(
        !/^\d+$/.test(exp) ||
        Number(exp)<Date.now()
    )
        return false;


    const expected =
        sign(exp);


    return (
        signature &&
        signature.length===expected.length &&
        crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expected)
        )
    );

}



export function admin(req,res,next){

    if(!current(req))
        return res.redirect('/login');


    next();

}



export function cookie(
    res,
    name,
    value,
    maxAge
){

    const secure =
        process.env.NODE_ENV==='production'
        ? '; Secure'
        : '';


    res.setHeader(
        'Set-Cookie',
        `${name}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}`
    );

}



export function createToken(){

    return crypto
        .randomBytes(24)
        .toString('hex');

}



export function signToken(value){

    return sign(value);

}
