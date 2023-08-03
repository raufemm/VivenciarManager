using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VivenciarManager.Domain.Interfaces.Infra.Auth;
using VivenciarManager.Domain.Model;

namespace VivenciarManager.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAccessManager _accessManager;

        public AuthController(IAccessManager accessManager)
        {
            _accessManager = accessManager;
        }
        
        [HttpPost]
        [Route("login")]
        [Produces("application/json")]
        public async Task<IActionResult> Login([FromBody] UserLoginInputModel user)
        {
            var currentUser = await _accessManager.ValidateCredentials(user);

            if (currentUser is not null)
                return Ok(await _accessManager.GenerateToken(currentUser));

            return Unauthorized();
        }
    }
}