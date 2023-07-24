using Authr.WebApp.Controllers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Authr.WebApp.Services
{
    public class AbsoluteUrlProvider
    {
        private readonly LinkGenerator linkGenerator;
        private readonly IHttpContextAccessor accessor;

        public AbsoluteUrlProvider(LinkGenerator linkGenerator, IHttpContextAccessor accessor)
        {
            this.linkGenerator = linkGenerator;
            this.accessor = accessor;
        }

        public string GetAbsoluteRootUrl()
        {
            return GetAbsoluteActionUrl(nameof(HomeController.Index), "Home");
        }

        public string GetAbsoluteActionUrl(string action, string controller)
        {
            return this.linkGenerator.GetUriByAction(this.accessor.HttpContext, action, controller, null, "https");
        }
    }
}