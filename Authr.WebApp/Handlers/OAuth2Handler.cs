using System;
using System.Net.Http;
using System.Threading.Tasks;
using Authr.WebApp.Infrastructure;
using Authr.WebApp.Models;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.Extensions.Logging;

namespace Authr.WebApp.Handlers
{
    public class OAuth2Handler
    {
        #region Fields

        private readonly ILogger<OAuth2Handler> logger;
        private readonly IHttpClientFactory httpClientFactory;

        #endregion

        #region Constructors

        public OAuth2Handler(ILogger<OAuth2Handler> logger, IHttpClientFactory httpClientFactory)
        {
            this.logger = logger;
            this.httpClientFactory = httpClientFactory;
        }

        #endregion

        #region GetAuthorizationEndpointRequestUrl

        public string GetAuthorizationEndpointRequestUrl(AuthRequest request)
        {
            Guard.NotEmpty(request.Parameters.AuthorizationEndpoint, "The authorization endpoint must be specified for an authorization endpoint request.");
            Guard.NotEmpty(request.Parameters.ClientId, "The client id must be specified for an authorization endpoint request.");
            Guard.NotEmpty(request.Parameters.RedirectUri, "The redirect uri must be specified for an authorization endpoint request.");

            var codeChallenge = default(string);
            var codeChallengeMethod = default(string);
            if (request.Parameters.UsePkce && (request.Parameters.RequestType == Constants.RequestTypes.OpenIdConnect || request.Parameters.RequestType == Constants.RequestTypes.AuthorizationCode))
            {
                // Use PKCE and store the code verifier as part of the request so that it can be
                // retrieved later on when redeeming the authorization code.
                request.CodeVerifier = CryptoRandom.CreateUniqueId(64);
                codeChallenge = request.CodeVerifier.ToSha256().TrimEnd('=').Replace('+', '-').Replace('/', '_'); // https://stackoverflow.com/questions/58687154/identityserver4-pkce-error-transformed-code-verifier-does-not-match-code-chall
                codeChallengeMethod = OidcConstants.CodeChallengeMethods.Sha256;
            }

            var urlBuilder = new RequestUrl(request.Parameters.AuthorizationEndpoint);
            return urlBuilder.CreateAuthorizeUrl(
                clientId: request.Parameters.ClientId,
                responseType: request.Parameters.ResponseType,
                scope: request.Parameters.Scope,
                redirectUri: request.Parameters.RedirectUri,
                responseMode: request.Parameters.ResponseMode,
                nonce: request.Nonce,
                codeChallenge: codeChallenge,
                codeChallengeMethod: codeChallengeMethod,
                state: Constants.StatePrefixes.Flow + request.FlowId, // Set the request's "state" parameter to the flow id so it can be correlated when the response comes back.
                extra: request.Parameters.GetAdditionalParameters()
            );
        }

        #endregion

        #region Client Credentials

        public async Task<AuthResponse> HandleClientCredentialsRequestAsync(AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Client Credentials Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Client Credentials Grant.");
            Guard.NotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 Client Credentials Grant.");
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Scope = requestParameters.Scope,
                Parameters = requestParameters.GetAdditionalParameters()
            });
            return AuthResponse.FromTokenResponse(response);
        }

        #endregion

        #region Refresh Token

        public async Task<AuthResponse> HandleRefreshTokenRequestAsync(AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Refresh Token Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Refresh Token Grant.");
            Guard.NotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 Refresh Token Grant.");
            Guard.NotEmpty(requestParameters.RefreshToken, "The refresh token must be specified for an OAuth 2.0 Refresh Token Grant.");
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Scope = requestParameters.Scope,
                RefreshToken = requestParameters.RefreshToken,
                Parameters = requestParameters.GetAdditionalParameters()
            });
            return AuthResponse.FromTokenResponse(response);
        }

        #endregion

        #region Device Code

        public async Task<AuthResponse> HandleDeviceCodeRequestAsync(AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.DeviceCodeEndpoint, "The device code endpoint must be specified for an OAuth 2.0 Device Authorization Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Device Authorization Grant.");
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestDeviceAuthorizationAsync(new DeviceAuthorizationRequest
            {
                Address = requestParameters.DeviceCodeEndpoint,
                ClientId = requestParameters.ClientId,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Scope = requestParameters.Scope,
                Parameters = requestParameters.GetAdditionalParameters()
            });
            return AuthResponse.FromDeviceCodeResponse(response);
        }

        public async Task<AuthResponse> HandleDeviceTokenRequestAsync(AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Device Authorization Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Device Authorization Grant.");
            Guard.NotEmpty(requestParameters.DeviceCode, "The device code must be specified for an OAuth 2.0 Device Authorization Grant.");
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestDeviceTokenAsync(new DeviceTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                DeviceCode = requestParameters.DeviceCode,
                Parameters = requestParameters.GetAdditionalParameters()
            });
            return AuthResponse.FromTokenResponse(response);
        }

        #endregion

        #region Resource Owner Password Credentials

        public async Task<AuthResponse> HandleResourceOwnerPasswordCredentialsRequestAsync(AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            Guard.NotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            Guard.NotEmpty(requestParameters.UserName, "The user name must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            Guard.NotEmpty(requestParameters.Password, "The password must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Scope = requestParameters.Scope,
                UserName = requestParameters.UserName,
                Password = requestParameters.Password,
                Parameters = requestParameters.GetAdditionalParameters()
            });
            return AuthResponse.FromTokenResponse(response);
        }

        #endregion

        #region On Behalf Of

        public async Task<AuthResponse> HandleOnBehalfOfRequestAsync(AuthRequestParameters requestParameters)
        {
            // This implementation may be specific to Azure Active Directory.
            // https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 On-Behalf-Of Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 On-Behalf-Of Grant.");
            Guard.NotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 On-Behalf-Of Grant.");
            Guard.NotEmpty(requestParameters.Scope, "The scope must be specified for an OAuth 2.0 On-Behalf-Of Grant.");
            Guard.NotEmpty(requestParameters.Assertion, "The assertion must be specified for an OAuth 2.0 On-Behalf-Of Grant.");
            var client = this.httpClientFactory.CreateClient();
            var request = new TokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer",
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Parameters = requestParameters.GetAdditionalParameters()
            };
            request.Parameters.Add(OidcConstants.TokenRequest.Scope, requestParameters.Scope);
            request.Parameters.Add(OidcConstants.TokenRequest.Assertion, requestParameters.Assertion);
            request.Parameters.Add("requested_token_use", "on_behalf_of");
            var response = await client.RequestTokenAsync(request);
            return AuthResponse.FromTokenResponse(response);
        }

        #endregion

        #region Authorization Code

        public async Task<AuthResponse> HandleAuthorizationCodeResponseAsync(AuthRequestParameters requestParameters, string codeVerifier)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Authorization Code Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Authorization Code Grant.");
            Guard.NotEmpty(requestParameters.AuthorizationCode, "The authorization code must be specified for an OAuth 2.0 Authorization Code Grant.");
            if (requestParameters.RequestType != Constants.RequestTypes.OpenIdConnect && requestParameters.RequestType != Constants.RequestTypes.AuthorizationCode)
            {
                throw new Exception("Invalid request type for Authorization Code grant: " + requestParameters.RequestType);
            }
            var client = this.httpClientFactory.CreateClient();
            if (!string.IsNullOrWhiteSpace(codeVerifier))
            {
                // Add an Origin header in case the request is for a PKCE flow, to emulate the fact that we're
                // sending this call from a browser and avoid "AADSTS9002327: Tokens issued for the 'Single-Page Application'
                // client-type may only be redeemed via cross-origin requests".
                // See https://github.com/AzureAD/microsoft-authentication-library-for-js/issues/2482 and
                // https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow#redirect-uris-for-single-page-apps-spas.
                client.DefaultRequestHeaders.Add("Origin", requestParameters.RedirectUri);
            }
            var response = await client.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Code = requestParameters.AuthorizationCode,
                RedirectUri = requestParameters.RedirectUri,
                CodeVerifier = codeVerifier,
                Parameters = requestParameters.GetAdditionalParameters()
            });
            return AuthResponse.FromTokenResponse(response);
        }

        #endregion

        #region Custom Grant

        public async Task<AuthResponse> HandleCustomGrantRequestAsync(AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 grant.");
            Guard.NotEmpty(requestParameters.GrantType, "The grant type must be specified for an OAuth 2.0 grant.");
            var client = this.httpClientFactory.CreateClient();
            var request = new TokenRequest
            {
                GrantType = requestParameters.GrantType,
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Parameters = requestParameters.GetAdditionalParameters()
            };
            var response = await client.RequestTokenAsync(request);
            return AuthResponse.FromTokenResponse(response);
        }

        #endregion
    }
}