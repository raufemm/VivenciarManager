using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using VivenciarManager.Domain.Auth;
using VivenciarManager.Domain.Entities;
using VivenciarManager.Domain.Interfaces.Infra.Auth;
using VivenciarManager.Domain.Model;

namespace VivenciarManager.Infra.Auth
{
    public class AccessManager : IAccessManager
    {
        private UserManager<ApplicationUser> _userManager;
        private SignInManager<ApplicationUser> _signInManager;
        private SigningConfigurations _signingConfigurations;
        private TokenConfigurations _tokenConfigurations;
        
        public AccessManager(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            SigningConfigurations signingConfigurations,
            TokenConfigurations tokenConfigurations)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _signingConfigurations = signingConfigurations;
            _tokenConfigurations = tokenConfigurations;
        }

        public async Task<ApplicationUser> GetUser(string userEmail)
        {
            ApplicationUser user = new();

            if (userEmail != null && !string.IsNullOrWhiteSpace(userEmail))
                user = await _userManager.FindByEmailAsync(userEmail);

            return user;
        }
        public async Task<ApplicationUser> ValidateCredentials(UserLoginInputModel user)
        {
            ApplicationUser identityUser = await GetUser(user.Email);

            if (identityUser is not null)
            {
                var result = await _signInManager
                    .CheckPasswordSignInAsync(identityUser, user.Password, false);

                if (result.Succeeded)
                {
                    return identityUser;
                }
            }

            return identityUser;
        }
        public async Task<AcessToken> GenerateToken(ApplicationUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);
            var claims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Email)
            };

            foreach (var role in userRoles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            var identity = new ClaimsIdentity(
                new GenericIdentity(user.Email, "Login"), claims);

            DateTime createAt = DateTime.Now;
            DateTime expirationDate = createAt + TimeSpan.FromSeconds(_tokenConfigurations.Seconds);

            var handler = new JwtSecurityTokenHandler();

            var securityToken = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = _tokenConfigurations.Issuer,
                Audience = _tokenConfigurations.Audience,
                SigningCredentials = _signingConfigurations.SigningCredentials,
                Subject = identity,
                NotBefore = createAt,
                Expires = expirationDate
            });

            var token = handler.WriteToken(securityToken);

            return new AcessToken()
            {
                Authenticated = true,
                Created = createAt.ToString("yyyy-MM-dd HH:mm:ss"),
                Expiration = expirationDate.ToString("yyyy-MM-dd HH:mm:ss"),
                Token = token,
                Message = "OK"
            };
        }
    }
}
