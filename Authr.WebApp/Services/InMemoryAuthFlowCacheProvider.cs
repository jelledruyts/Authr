using System.Collections.Generic;
using System.Threading.Tasks;
using Authr.WebApp.Models;

namespace Authr.WebApp.Services
{
    public class InMemoryAuthFlowCacheProvider : IAuthFlowCacheProvider
    {
        private static readonly IDictionary<string, AuthFlow> AuthFlowCache = new Dictionary<string, AuthFlow>();

        public Task<AuthFlow> GetAuthFlowAsync(string id)
        {
            if (AuthFlowCache.ContainsKey(id))
            {
                return Task.FromResult(AuthFlowCache[id]);
            }
            return Task.FromResult((AuthFlow)null);
        }

        public Task SetAuthFlowAsync(AuthFlow flow)
        {
            AuthFlowCache[flow.Id] = flow;
            return Task.CompletedTask;
        }

        public Task RemoveAuthFlowAsync(string id)
        {
            AuthFlowCache.Remove(id);
            return Task.CompletedTask;
        }
    }
}