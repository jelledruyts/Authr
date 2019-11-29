using System.Security.Claims;

namespace Authr.WebApp
{
    public static class ExtensionMethods
    {
        public static string GetUserId(this ClaimsPrincipal principal)
        {
            return principal.FindFirst(Constants.ClaimTypes.ObjectId)?.Value;
        }
    }
}