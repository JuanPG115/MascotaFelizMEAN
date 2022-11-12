import {injectable, /* inject, */ BindingScope} from '@loopback/core';
import { repository } from '@loopback/repository';
import { LLaves } from '../config/LLaves';
import { Usuario } from '../models';
import { UsuarioRepository } from '../repositories/usuario.repository';
const generador = require('password-generator');
const cryptojs = require('crypto-js');
const jwt = require('jsonwebtoken');

@injectable({scope: BindingScope.TRANSIENT})
export class AutenticacionService {
  constructor(@repository(UsuarioRepository) public UsuarioRepository: UsuarioRepository) {

  }

  GenerarClave(){
    let clave = generador(8, false);
    return clave
  }

  CifrarClave(clave: string){
    let claveCifrada = cryptojs.MD5(clave).toString();
    return claveCifrada;
  }

  IdentificarUsuario(usuario: string, clave: string){
    try{
      let u = this.UsuarioRepository.findOne({where : {correo: usuario, contrasena: clave}});
      if(u){
        return u;
      }
      return false;
    }catch{
      return false;
    }
  }

  GenerarTokenJWT(usuario: Usuario){
    let token = jwt.sign({
      data: {
        id: usuario.id,
        correo: usuario.correo,
        nombre: usuario.nombre
      }
    }, LLaves.claveJWT);
    return token;
  }

  ValidarTokenJWT(token: string){
    try{
      let datos = jwt.verity(token, LLaves.claveJWT);
      if(datos){
        return datos;
      }
      return false;
    }catch{
      return false;
    }
  }

}
