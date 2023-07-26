using VivenciarManager.Domain.Auth;
using VivenciarManager.Domain.Entities;
using VivenciarManager.Domain.Model;

namespace VivenciarManager.Domain.Interfaces.Infra.Auth
{
    public interface IAccessManager
    {
        Task<ApplicationUser> CreateUser(UserLogin user, string? role);
        Task<AcessToken> GenerateToken(ApplicationUser user);
        Task<ApplicationUser> ValidateCredentials(UserLogin user);
    }
}
