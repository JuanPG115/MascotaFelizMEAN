import { AuthenticationStrategy } from "@loopback/authentication";
import { service } from "@loopback/core";
import { Request, RedirectRoute, HttpErrors } from "@loopback/rest";
import { UserProfile } from "@loopback/security";
import parseBearerToken from "parse-bearer-token";
//import { ParamsDictionary } from "express-serve-static-core";
//import { ParsedQs } from "qs";
import { AutenticacionService } from '../services/autenticacion.service';

export class EstrategyCliente implements AuthenticationStrategy{
    name: string = 'cliente';

    constructor(
        @service(AutenticacionService)
        public servicioAutenticacion : AutenticacionService
    ){}

    async authenticate(request: Request): Promise<UserProfile | undefined> {
        let token = parseBearerToken(request);

        if(token){
            let datos = this.servicioAutenticacion.ValidarTokenJWT(token);
            if(datos){
                let perfil: UserProfile = Object.assign({
                    nombre: datos.data.nombre
                });
                return perfil;
            }else{
                throw new HttpErrors[401]('El token no es válido');
            }
        }else{
            throw new HttpErrors[401]('No esta incluido el token');
        }
    }
}