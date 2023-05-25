using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace api.eavila.cuentas.Controllers
{
    [AllowAnonymous]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : Controller
    {
        readonly byte[] key = Encoding.ASCII.GetBytes("lkj@jalsd.123@aadll.hhd33esa!qwertyuiop123");

        [HttpPost]
        public IActionResult Autenticar([FromBody]  LoginModel loginModel)
        {
            if(!usuarioAutenticado(loginModel.Username, loginModel.Password))  return Unauthorized();
            var token = crearToken(loginModel.Username);
            return Ok(token);
        }

        private bool usuarioAutenticado(string user, string password)
        {
            return user == "admin" && password == "123456";
        }

        private string crearToken(string user)
        {
            var handlerToken = new JwtSecurityTokenHandler();
            var descriptorToken = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user),
                }),
                Expires
                = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256)

            };

                var token = handlerToken.CreateToken(descriptorToken);

            return handlerToken.WriteToken(token);
        }
    }
        public class LoginModel
        {
            [Required]
            public string Username { get; set; }

            [Required]
            public string Password{ get; set; }
        }
    
}
