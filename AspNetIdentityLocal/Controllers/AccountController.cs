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
    [Authorize]
    public class AccountController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;

        public AccountController(IConfiguration configuration, UserManager<ApplicationUser> userManager){
            _configuration = configuration;
            _userManager = userManager;
        }

        [HttpPost("Register")]
        [AllowAnonymous]
        public async Task<ActionResult<ApplicationUser>> Register(RegisterRequest request){
            var checkuser = await _userManager.FindByEmailAsync(request.Email);
            if(checkuser != null){
                return BadRequest("El usuario ya existe");
            }
            
            var user = new ApplicationUser(){
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName
            };

            var createdUser = await _userManager.CreateAsync(user, request.Password);
            if(!createdUser.Succeeded){
                return BadRequest(createdUser.Errors);
            }

            return Created("Register", user);
        }

        [HttpGet]
        public async Task<ActionResult<ApplicationUser>> MyAccount(){
            var user = await _userManager.FindByNameAsync(User.Identity.Name);
            if(user == null){
                return NotFound();
            }

            return user;
        }

    }
}