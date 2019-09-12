using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using AspNetIdentityLocal.Models;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
namespace AspNetIdentityLocal.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;

        public TokenController(IConfiguration configuration, UserManager<ApplicationUser> userManager){
            _configuration = configuration;
            _userManager = userManager;
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult<AuthResponse>> Login(AuthRequest loginRequest){
            var user = await _userManager.FindByEmailAsync(loginRequest.UserName);
            
            if(user == null){
                return NotFound("El usuario no existe");
            }

            var checkPwd = await _userManager.CheckPasswordAsync(user, loginRequest.Password);

            if(!checkPwd){
                return Unauthorized("Contraseña inválida");
            }

            var claims = new List<Claim>(){
                new Claim(JwtRegisteredClaimNames.Jti, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName)
            };

            var roles = await _userManager.GetRolesAsync(user);
            foreach(string role in roles){
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            DateTime expiration = DateTime.Now.AddMinutes(60);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Tokens:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                _configuration.GetSection("Tokens:Issuer").Get<string>(),
                loginRequest.AudienceKey, 
                claims,
                null,
                expiration, 
                creds);
            AuthResponse response = new AuthResponse(){
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = expiration
            };

            return response;
        }

        [HttpGet("Validate")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public ActionResult<bool> TokenValidate(){
            return true;
        }
    }
}