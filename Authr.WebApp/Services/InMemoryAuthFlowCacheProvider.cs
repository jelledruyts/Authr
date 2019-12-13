using System.Collections.Generic;
using System.Threading.Tasks;
using Authr.WebApp.Models;

namespace Authr.WebApp.Services
{
    public class InMemoryAuthFlowCacheProvider : IAuthFlowCacheProvider
    {
        private static readonly IDictionary<string, AuthFlow> AuthFlowCache = new Dictionary<string, AuthFlow>();

        public Task<AuthFlow> GetAuthFlowAsync(string reference)
        {
            if (AuthFlowCache.ContainsKey(reference))
            {
                return Task.FromResult(AuthFlowCache[reference]);
            }
            return Task.FromResult((AuthFlow)null);
        }

        public Task SetAuthFlowAsync(string reference, AuthFlow flow)
        {
            AuthFlowCache[reference] = flow;
            return Task.CompletedTask;
        }

        public Task RemoveAuthFlowAsync(string reference)
        {
            AuthFlowCache.Remove(reference);
            return Task.CompletedTask;
        }
    }
}