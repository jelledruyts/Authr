using System.Threading.Tasks;
using Authr.WebApp.Models;

namespace Authr.WebApp.Services
{
    public interface IAuthFlowCacheProvider
    {
        public Task<AuthFlow> GetAuthFlowAsync(string id);
        public Task SetAuthFlowAsync(AuthFlow flow);
        public Task RemoveAuthFlowAsync(string id);
    }
}