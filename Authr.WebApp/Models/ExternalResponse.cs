using IdentityModel;
using Microsoft.AspNetCore.Mvc;

namespace Authr.WebApp.Models
{
    public class ExternalResponse
    {
        [BindProperty(Name = OidcConstants.AuthorizeResponse.State)]
        public string State { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.Error)]
        public string Error { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.ErrorDescription)]
        public string ErrorDescription { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.Code)]
        public string AuthorizationCode { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.IdentityToken)]
        public string IdToken { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.AccessToken)]
        public string AccessToken { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.TokenType)]
        public string TokenType { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.RefreshToken)]
        public string RefreshToken { get; set; }
    }
}