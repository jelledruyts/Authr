using System.Threading.Tasks;
using Authr.WebApp.Models;

namespace Authr.WebApp.Services
{
    public interface IUserConfigurationProvider
    {
        public Task<UserConfiguration> GetUserConfigurationAsync(string userId);
        public Task SaveUserConfigurationAsync(UserConfiguration userConfiguration);
    }
}