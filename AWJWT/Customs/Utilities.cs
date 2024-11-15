using AWJWT.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AWJWT.Customs
{
    public class Utilities
    {
        private readonly IConfiguration _configuration;
        public Utilities(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public string encriptarSHA256(string texto)
        {
            try
            {
                if (texto == null) 
                    throw new ArgumentNullException(nameof(texto), "El texto no puede estar vacio");

                using (SHA256 sha256Hash = SHA256.Create())
                {
                    // Computar el hash
                    byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(texto));

                    // Convertir el array de bytes a string
                    StringBuilder stringBuilder = new StringBuilder();
                    for (int i = 0; i < bytes.Length; i++)
                    {
                        stringBuilder.Append(bytes[i].ToString("x2"));
                    }
                    return stringBuilder.ToString();
                }
            }
            catch (ArgumentNullException ex) // exception si texto es null
            {
                Console.WriteLine("El texto no puede ser null" + ex.Message);
                throw;
            }
            catch (EncoderFallbackException ex) // si el teexto no se puede codificar a utf-8
            {
                Console.WriteLine("Error a codificar el texto a utf-8" + ex.Message);
                throw;
            }
            catch (ObjectDisposedException ex) // si se utiliza sha256 despues de destruirse
            {
                Console.WriteLine("SHA256 se utilizo despues de destruirse" + ex.Message);
                throw;
            }
            catch (Exception ex) 
            {
                Console.WriteLine("Ocurrió un error inesperado: " + ex.Message);
                throw;
            }
        }

        public string generarJWT(Usuario user)
        {
            try
            {

                if (user == null || string.IsNullOrEmpty(user.Correo)) throw new ArgumentNullException(nameof(user), "El usuario no puede ser null.");

                var userClaimans = new[]
                {
                new Claim(ClaimTypes.NameIdentifier, user.IdUsuario.ToString()),
                new Claim(ClaimTypes.Email, user.Correo!)
                };

                string key = _configuration["Jwt:key"]!;
 
                if (string.IsNullOrEmpty(key) || key.Length < 32) throw new ArgumentException("La calve JWT debe tener al menos 32 caracteres");

                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:key"]!));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
                var expiration = double.Parse(_configuration["Jwt:expiresInMinutes"]!);

                //crear detalle del token
                var jwtConfig = new JwtSecurityToken(
                    claims: userClaimans,
                    expires: DateTime.UtcNow.AddMinutes(expiration),
                    signingCredentials: credentials
                    );

                return new JwtSecurityTokenHandler().WriteToken(jwtConfig);
            }
            catch (FormatException ex) // si jwt:expires no puede convertirse a un float
            {
                Console.WriteLine("Error en el formato de configuracion" + ex.Message);
                throw;
            }
            catch (SecurityTokenException ex) // si hay un problema al crear o manejar el token 
            {
                Console.WriteLine("Error al crear el token" + ex.Message);
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Ocurrió un error inesperado: " + ex.Message);
                throw;
            }
        }
    }
}
