using VivenciarManager.Domain.Auth;
using VivenciarManager.Domain.Entities;
using VivenciarManager.Domain.Model;

namespace VivenciarManager.Domain.Interfaces.Infra.Auth
{
    public interface IAccessManager
    {
        Task<AcessToken> GenerateToken(ApplicationUser user);
        Task<ApplicationUser> ValidateCredentials(UserLoginInputModel user);
    }
}
