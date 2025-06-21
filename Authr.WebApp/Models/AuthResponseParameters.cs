using System.Text.Json.Serialization;
using Duende.IdentityModel;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.WsFederation;

namespace Authr.WebApp.Models
{
    public class AuthResponseParameters
    {
        [BindProperty(Name = OidcConstants.AuthorizeResponse.State)]
        [JsonPropertyName(OidcConstants.AuthorizeResponse.State)]
        public string State { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.Error)]
        [JsonPropertyName(OidcConstants.AuthorizeResponse.Error)]
        public string Error { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.ErrorDescription)]
        [JsonPropertyName(OidcConstants.AuthorizeResponse.ErrorDescription)]
        public string ErrorDescription { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.Code)]
        [JsonPropertyName(OidcConstants.AuthorizeResponse.Code)]
        public string AuthorizationCode { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.IdentityToken)]
        [JsonPropertyName(OidcConstants.AuthorizeResponse.IdentityToken)]
        public string IdToken { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.AccessToken)]
        [JsonPropertyName(OidcConstants.AuthorizeResponse.AccessToken)]
        public string AccessToken { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.TokenType)]
        [JsonPropertyName(OidcConstants.AuthorizeResponse.TokenType)]
        public string TokenType { get; set; }

        [BindProperty(Name = OidcConstants.AuthorizeResponse.RefreshToken)]
        [JsonPropertyName(OidcConstants.AuthorizeResponse.RefreshToken)]
        public string RefreshToken { get; set; }

        [BindProperty(Name = Saml2Constants.Message.SamlRequest)]
        [JsonPropertyName(Saml2Constants.Message.SamlRequest)]
        public string SamlRequest { get; set; }

        [BindProperty(Name = Saml2Constants.Message.SamlResponse)]
        [JsonPropertyName(Saml2Constants.Message.SamlResponse)]
        public string SamlResponse { get; set; }

        [BindProperty(Name = Saml2Constants.Message.RelayState)]
        [JsonPropertyName(Saml2Constants.Message.RelayState)]
        public string RelayState { get; set; }

        [BindProperty(Name = WsFederationConstants.WsFederationParameterNames.Wa)]
        [JsonPropertyName(WsFederationConstants.WsFederationParameterNames.Wa)]
        public string Wa { get; set; }

        [BindProperty(Name = WsFederationConstants.WsFederationParameterNames.Wresult)]
        [JsonPropertyName(WsFederationConstants.WsFederationParameterNames.Wresult)]
        public string Wresult { get; set; }

        [BindProperty(Name = WsFederationConstants.WsFederationParameterNames.Wctx)]
        [JsonPropertyName(WsFederationConstants.WsFederationParameterNames.Wctx)]
        public string Wctx { get; set; }

        public bool IsEmpty()
        {
            // Check if any of the relevant properties are set, excluding State, RelayState and Wctx (as just state without anything else is useless).
            return string.IsNullOrWhiteSpace(this.Error + this.ErrorDescription + this.AuthorizationCode + this.IdToken + this.AccessToken + this.TokenType + this.RefreshToken + this.SamlRequest + this.SamlResponse + this.Wa + this.Wresult);
        }
    }
}