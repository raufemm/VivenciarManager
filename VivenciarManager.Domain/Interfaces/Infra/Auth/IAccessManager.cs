using VivenciarManager.Domain.Auth;
using VivenciarManager.Domain.Entities;
using VivenciarManager.Domain.Model;

namespace VivenciarManager.Domain.Interfaces.Infra.Auth
{
    public interface IAccessManager
    {
        Task<ApplicationUser> CreateUser(UserLogin user, string? role);
        void DeactivateCurrent(string? name);
        void DeactivateToken(string token, string user);
        Task<AcessToken> GenerateToken(ApplicationUser user);
        bool IsCurrentActiveToken(string? user);
        Task<ApplicationUser> GetUser(string userEmail);
        Task<ApplicationUser> ValidateCredentials(UserLogin user);
    }
}
