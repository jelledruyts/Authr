using System.Collections.Generic;
using System.Threading.Tasks;
using Authr.WebApp.Models;

namespace Authr.WebApp.Services
{
    public class InMemoryUserConfigurationProvider : IUserConfigurationProvider
    {
        private static readonly IDictionary<string, UserConfiguration> UserConfigurationCache = new Dictionary<string, UserConfiguration>();

        public Task<UserConfiguration> GetUserConfigurationAsync(string userId)
        {
            if (UserConfigurationCache.ContainsKey(userId))
            {
                return Task.FromResult(UserConfigurationCache[userId]);
            }
            // If there is no container or blob, then return a new user configuration object.
            return Task.FromResult(new UserConfiguration { UserId = userId });
        }

        public Task SaveUserConfigurationAsync(UserConfiguration userConfiguration)
        {
            UserConfigurationCache[userConfiguration.UserId] = userConfiguration;
            return Task.CompletedTask;
        }
    }
}