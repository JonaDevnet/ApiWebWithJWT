using AWJWT.Customs;
using AWJWT.DTOs;
using AWJWT.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace AWJWT.Controllers
{
    [Route("api/[controller]")]
    [AllowAnonymous] // no solo usuarios autorizados, no tiene sentido xd
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly BdjwtContext _DbContext;
        private readonly Utilities _Utilities;
        public LoginController(BdjwtContext context, Utilities utilities)
        {
            _DbContext = context;
            _Utilities = utilities;
        }

        [HttpPost]
        [Route("Registrarse")]
        public async Task<IActionResult> Registrarse(UsuarioDTO objecto)
        {
            try
            {
                if (objecto == null || string.IsNullOrEmpty(objecto.Nombre) || string.IsNullOrEmpty(objecto.Clave))
                {
                    return StatusCode(StatusCodes.Status200OK, new { isSuccess = false, message = "Datos inválidos" });
                }

                var modeloUsuario = new Usuario
                {
                    Nombres = objecto.Nombre,
                    Apellidos = objecto.Apellido,
                    Correo = objecto.Correo,
                    Celular = objecto.NumeroCelular,
                    Clave = _Utilities.encriptarSHA256(objecto.Clave),
                };

                await _DbContext.Usuarios.AddAsync(modeloUsuario);
                await _DbContext.SaveChangesAsync();

                if (modeloUsuario.IdUsuario != 0) 
                    return StatusCode(StatusCodes.Status200OK, new { isSuccess = true });
                else 
                    return StatusCode(StatusCodes.Status200OK, new { isSucces = false });
            }
            catch (DbUpdateException ex)
            {
                Console.WriteLine("Error de actualización en la base de datos: " + ex.Message);
                throw;
            }
            catch (SqlException ex)
            {
                Console.WriteLine("Error en el servidor SQL: " + ex.Message);
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine("error inesperado: " + ex.Message);
                throw; 
            }

        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(LoginDTO objeto)
        {
            try
            {
                var usuarioEncontrado = await _DbContext.Usuarios.Where(
                       u =>
                       u.Correo == objeto.Correo &&
                       u.Clave == _Utilities.encriptarSHA256(objeto.Clave))
                        .FirstOrDefaultAsync();
                if (usuarioEncontrado == null)
                    return StatusCode(StatusCodes.Status200OK, new { isSucces = false, token = "" });
                else
                    return StatusCode(StatusCodes.Status200OK, new { isSucces = true, token = _Utilities.generarJWT(usuarioEncontrado) });

            }
            catch (DbUpdateException ex)
            {
                Console.WriteLine("Error de actualización en la base de datos: " + ex.Message);
                throw;
            }
            catch (SqlException ex)
            {
                Console.WriteLine("Error en el servidor SQL: " + ex.Message);
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine("error inesperado: " + ex.Message);
                throw;
            }
        }
    }
}
