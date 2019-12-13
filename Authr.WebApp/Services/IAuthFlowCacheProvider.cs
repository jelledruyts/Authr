using System.Threading.Tasks;
using Authr.WebApp.Models;

namespace Authr.WebApp.Services
{
    public interface IAuthFlowCacheProvider
    {
        public Task<AuthFlow> GetAuthFlowAsync(string reference);
        public Task SetAuthFlowAsync(string reference, AuthFlow flow);
        public Task RemoveAuthFlowAsync(string reference);
    }
}