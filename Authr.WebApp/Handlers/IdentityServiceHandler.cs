using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using System.Xml;
using Authr.WebApp.Models;
using Microsoft.Extensions.Logging;

namespace Authr.WebApp.Handlers
{
    public class IdentityServiceHandler
    {
        #region Fields

        private readonly ILogger<IdentityServiceHandler> logger;
        private readonly IHttpClientFactory httpClientFactory;

        #endregion

        #region Constructors

        public IdentityServiceHandler(ILogger<IdentityServiceHandler> logger, IHttpClientFactory httpClientFactory)
        {
            this.logger = logger;
            this.httpClientFactory = httpClientFactory;
        }

        #endregion

        #region Import Identity Service

        public async Task<IdentityService> HandleImportIdentityServiceRequestAsync(IdentityServiceImportRequestParameters request)
        {
            if (request == null)
            {
                return null;
            }
            else if (request.ImportType == Constants.IdentityServiceImportTypes.AzureAD && !string.IsNullOrWhiteSpace(request.Tenant))
            {
                var tenant = request.Tenant;
                return new IdentityService
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = tenant,
                    AuthorizationEndpoint = $"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
                    TokenEndpoint = $"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                    DeviceCodeEndpoint = $"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode",
                    SamlSignOnEndpoint = $"https://login.microsoftonline.com/{tenant}/saml2",
                    SamlLogoutEndpoint = $"https://login.microsoftonline.com/{tenant}/saml2",
                    WsFederationSignOnEndpoint = $"https://login.microsoftonline.com/{tenant}/wsfed"
                };
            }
            else if (request.ImportType == Constants.IdentityServiceImportTypes.AzureADB2C && !string.IsNullOrWhiteSpace(request.Tenant) && !string.IsNullOrWhiteSpace(request.PolicyId))
            {
                var tenant = request.Tenant.Replace(".onmicrosoft.com", string.Empty, StringComparison.InvariantCultureIgnoreCase);
                var policyId = HttpUtility.UrlEncode(request.PolicyId);
                return new IdentityService
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = tenant,
                    AuthorizationEndpoint = $"https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policyId}/oauth2/v2.0/authorize",
                    TokenEndpoint = $"https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policyId}/oauth2/v2.0/token",
                    DeviceCodeEndpoint = null, // Not supported by Azure AD B2C.
                    SamlSignOnEndpoint = $"https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policyId}/samlp/sso/login",
                    SamlLogoutEndpoint = $"https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policyId}/samlp/sso/logout",
                    WsFederationSignOnEndpoint = null // Not supported by Azure AD B2C.
                };
            }
            else if (request.ImportType == Constants.IdentityServiceImportTypes.MicrosoftEntraExternalId && !string.IsNullOrWhiteSpace(request.Tenant))
            {
                var tenant = request.Tenant.Replace(".onmicrosoft.com", string.Empty, StringComparison.InvariantCultureIgnoreCase);
                return new IdentityService
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = tenant,
                    AuthorizationEndpoint = $"https://{tenant}.ciamlogin.com/{tenant}.onmicrosoft.com/oauth2/authorize",
                    TokenEndpoint = $"https://{tenant}.ciamlogin.com/{tenant}.onmicrosoft.com/oauth2/token",
                    DeviceCodeEndpoint = $"https://{tenant}.ciamlogin.com/{tenant}.onmicrosoft.com/oauth2/devicecode",
                    SamlSignOnEndpoint = null, // Not supported.
                    SamlLogoutEndpoint = null, // Not supported.
                    WsFederationSignOnEndpoint = null // Not supported.
                };
            }
            else if (!string.IsNullOrWhiteSpace(request.FederationMetadataUrl) || !string.IsNullOrWhiteSpace(request.OpenIdConnectMetadataUrl))
            {
                try
                {
                    var identityService = new IdentityService { Id = Guid.NewGuid().ToString() };
                    var client = this.httpClientFactory.CreateClient();
                    if (!string.IsNullOrWhiteSpace(request.OpenIdConnectMetadataUrl))
                    {
                        var openIdConnectMetadataJson = await client.GetStringAsync(request.OpenIdConnectMetadataUrl);
                        using (var openIdConnectMetadata = JsonDocument.Parse(openIdConnectMetadataJson))
                        {
                            var value = default(JsonElement);
                            if (openIdConnectMetadata.RootElement.TryGetProperty("issuer", out value))
                            {
                                identityService.Name = value.GetString();
                            }
                            if (openIdConnectMetadata.RootElement.TryGetProperty("authorization_endpoint", out value))
                            {
                                identityService.AuthorizationEndpoint = value.GetString();
                            }
                            if (openIdConnectMetadata.RootElement.TryGetProperty("token_endpoint", out value))
                            {
                                identityService.TokenEndpoint = value.GetString();
                            }
                            if (openIdConnectMetadata.RootElement.TryGetProperty("device_authorization_endpoint", out value))
                            {
                                identityService.DeviceCodeEndpoint = value.GetString();
                            }
                        }
                    }
                    if (!string.IsNullOrWhiteSpace(request.FederationMetadataUrl))
                    {
                        var federationMetadataXml = await client.GetStringAsync(request.FederationMetadataUrl);
                        var federationMetadata = new XmlDocument();
                        federationMetadata.LoadXml(federationMetadataXml);
                        var nsmgr = new XmlNamespaceManager(federationMetadata.NameTable);
                        nsmgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:metadata");
                        nsmgr.AddNamespace("fed", "http://docs.oasis-open.org/wsfed/federation/200706");
                        nsmgr.AddNamespace("wsa", "http://www.w3.org/2005/08/addressing");
                        if (string.IsNullOrWhiteSpace(identityService.Name))
                        {
                            identityService.Name = federationMetadata.SelectSingleNode("saml:EntityDescriptor/@entityID", nsmgr)?.Value;
                        }
                        identityService.SamlSignOnEndpoint = federationMetadata.SelectSingleNode("/saml:EntityDescriptor/saml:IDPSSODescriptor/saml:SingleSignOnService[1]/@Location", nsmgr)?.Value;
                        identityService.SamlLogoutEndpoint = federationMetadata.SelectSingleNode("/saml:EntityDescriptor/saml:IDPSSODescriptor/saml:SingleLogoutService[1]/@Location", nsmgr)?.Value;
                        identityService.WsFederationSignOnEndpoint = federationMetadata.SelectSingleNode("/saml:EntityDescriptor/saml:RoleDescriptor/fed:PassiveRequestorEndpoint/wsa:EndpointReference/wsa:Address/text()", nsmgr)?.Value;
                    }
                    return identityService;
                }
                catch (Exception exc)
                {
                    this.logger.LogWarning(exc, "Could not download metadata: " + exc.Message);
                }
            }
            return null;
        }

        #endregion
    }
}