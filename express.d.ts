import 'express-serve-static-core';
declare module 'express-serve-static-core' { interface Request { user?: { id:string; username:string; role:string; is_active?:boolean }; rawBody?: Buffer; } }
