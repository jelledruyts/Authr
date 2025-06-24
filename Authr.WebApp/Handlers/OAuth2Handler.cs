using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Authr.WebApp.Infrastructure;
using Authr.WebApp.Models;
using Duende.AccessTokenManagement;
using Duende.IdentityModel;
using Duende.IdentityModel.Client;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Authr.WebApp.Handlers
{
    public class OAuth2Handler
    {
        #region Fields

        private static string DPoPProofKey = CreateDPoPProofKey();
        private readonly ILogger<OAuth2Handler> logger;
        private readonly IHttpClientFactory httpClientFactory;
        private readonly IDPoPProofService dPoPProofService;

        #endregion

        #region Constructors

        public OAuth2Handler(ILogger<OAuth2Handler> logger, IHttpClientFactory httpClientFactory, IDPoPProofService dPoPProofService)
        {
            this.logger = logger;
            this.httpClientFactory = httpClientFactory;
            this.dPoPProofService = dPoPProofService;
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

        public async Task<AuthRequest> HandleClientCredentialsRequestAsync(AuthFlow flow, AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Client Credentials Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Client Credentials Grant.");
            Guard.NotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 Client Credentials Grant.");
            var request = new ClientCredentialsTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Scope = requestParameters.Scope,
                Parameters = requestParameters.GetAdditionalParameters()
            };
            return await PerformProtocolRequestAsync(flow, requestParameters, request,
                (c, r) => c.RequestClientCredentialsTokenAsync(r),
                r => AuthResponse.FromTokenResponse(r));
        }

        #endregion

        #region Refresh Token

        public async Task<AuthRequest> HandleRefreshTokenRequestAsync(AuthFlow flow, AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Refresh Token Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Refresh Token Grant.");
            Guard.NotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 Refresh Token Grant.");
            Guard.NotEmpty(requestParameters.RefreshToken, "The refresh token must be specified for an OAuth 2.0 Refresh Token Grant.");
            var request = new RefreshTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Scope = requestParameters.Scope,
                RefreshToken = requestParameters.RefreshToken,
                Parameters = requestParameters.GetAdditionalParameters()
            };
            return await PerformProtocolRequestAsync(flow, requestParameters, request,
                (c, r) => c.RequestRefreshTokenAsync(r),
                r => AuthResponse.FromTokenResponse(r));
        }

        #endregion

        #region Device Code

        public async Task<AuthRequest> HandleDeviceCodeRequestAsync(AuthFlow flow, AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.DeviceCodeEndpoint, "The device code endpoint must be specified for an OAuth 2.0 Device Authorization Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Device Authorization Grant.");
            var client = this.httpClientFactory.CreateClient();
            var request = new DeviceAuthorizationRequest
            {
                Address = requestParameters.DeviceCodeEndpoint,
                ClientId = requestParameters.ClientId,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Scope = requestParameters.Scope,
                Parameters = requestParameters.GetAdditionalParameters()
            };
            return await PerformProtocolRequestAsync(flow, requestParameters, request,
                (c, r) => c.RequestDeviceAuthorizationAsync(r),
                r => AuthResponse.FromDeviceCodeResponse(r)
                );
        }

        public async Task<AuthRequest> HandleDeviceTokenRequestAsync(AuthFlow flow, AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Device Authorization Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Device Authorization Grant.");
            Guard.NotEmpty(requestParameters.DeviceCode, "The device code must be specified for an OAuth 2.0 Device Authorization Grant.");
            var request = new DeviceTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                DeviceCode = requestParameters.DeviceCode,
                Parameters = requestParameters.GetAdditionalParameters()
            };
            return await PerformProtocolRequestAsync(flow, requestParameters, request,
                (c, r) => c.RequestDeviceTokenAsync(r),
                r => AuthResponse.FromTokenResponse(r));
        }

        #endregion

        #region Resource Owner Password Credentials

        public async Task<AuthRequest> HandleResourceOwnerPasswordCredentialsRequestAsync(AuthFlow flow, AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            Guard.NotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            Guard.NotEmpty(requestParameters.UserName, "The user name must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            Guard.NotEmpty(requestParameters.Password, "The password must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            var request = new PasswordTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Scope = requestParameters.Scope,
                UserName = requestParameters.UserName,
                Password = requestParameters.Password,
                Parameters = requestParameters.GetAdditionalParameters()
            };
            return await PerformProtocolRequestAsync(flow, requestParameters, request,
                (c, r) => c.RequestPasswordTokenAsync(r),
                r => AuthResponse.FromTokenResponse(r));
        }

        #endregion

        #region On Behalf Of

        public async Task<AuthRequest> HandleOnBehalfOfRequestAsync(AuthFlow flow, AuthRequestParameters requestParameters)
        {
            // This implementation may be specific to Azure Active Directory.
            // https://learn.microsoft.com/entra/identity-platform/v2-oauth2-on-behalf-of-flow
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 On-Behalf-Of Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 On-Behalf-Of Grant.");
            Guard.NotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 On-Behalf-Of Grant.");
            Guard.NotEmpty(requestParameters.Scope, "The scope must be specified for an OAuth 2.0 On-Behalf-Of Grant.");
            Guard.NotEmpty(requestParameters.Assertion, "The assertion must be specified for an OAuth 2.0 On-Behalf-Of Grant.");
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
            return await PerformProtocolRequestAsync(flow, requestParameters, request,
                (c, r) => c.RequestTokenAsync(r),
                r => AuthResponse.FromTokenResponse(r));
        }

        #endregion

        #region Authorization Code

        public async Task<AuthRequest> HandleAuthorizationCodeResponseAsync(AuthFlow flow, AuthRequestParameters requestParameters, string codeVerifier)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Authorization Code Grant.");
            Guard.NotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Authorization Code Grant.");
            Guard.NotEmpty(requestParameters.AuthorizationCode, "The authorization code must be specified for an OAuth 2.0 Authorization Code Grant.");
            if (requestParameters.RequestType != Constants.RequestTypes.OpenIdConnect && requestParameters.RequestType != Constants.RequestTypes.AuthorizationCode)
            {
                throw new Exception("Invalid request type for Authorization Code grant: " + requestParameters.RequestType);
            }
            var request = new AuthorizationCodeTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Code = requestParameters.AuthorizationCode,
                RedirectUri = requestParameters.RedirectUri,
                CodeVerifier = codeVerifier,
                Parameters = requestParameters.GetAdditionalParameters()
            };
            return await PerformProtocolRequestAsync(flow, requestParameters, request,
                (c, r) => c.RequestAuthorizationCodeTokenAsync(r),
                r => AuthResponse.FromTokenResponse(r));
        }

        #endregion

        #region Custom Grant

        public async Task<AuthRequest> HandleCustomGrantRequestAsync(AuthFlow flow, AuthRequestParameters requestParameters)
        {
            Guard.NotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 grant.");
            Guard.NotEmpty(requestParameters.GrantType, "The grant type must be specified for an OAuth 2.0 grant.");
            var request = new TokenRequest
            {
                GrantType = requestParameters.GrantType,
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Parameters = requestParameters.GetAdditionalParameters()
            };
            return await PerformProtocolRequestAsync(flow, requestParameters, request,
                (c, r) => c.RequestTokenAsync(r),
                r => AuthResponse.FromTokenResponse(r));
        }

        #endregion

        #region Helper Methods

        private async Task<AuthRequest> PerformProtocolRequestAsync<TProtocolRequest, TProtocolResponse>(AuthFlow flow, AuthRequestParameters requestParameters, TProtocolRequest request,
            Func<HttpClient, TProtocolRequest, Task<TProtocolResponse>> protocolInvoker,
            Func<TProtocolResponse, AuthResponse> responseMapper)
            where TProtocolRequest : ProtocolRequest
            where TProtocolResponse : ProtocolResponse
        {
            if (requestParameters.UseDPoP)
            {
                request.DPoPProofToken = await GetDPoPProofTokenAsync(requestParameters.TokenEndpoint);
            }

            var client = this.httpClientFactory.CreateClient();
            var authRequest = flow.AddRequest(requestParameters);
            var response = await protocolInvoker(client, request);
            authRequest.Response = responseMapper(response);
            if (authRequest.Response.Error != null)
            {
                if (authRequest.Response.Error.Equals("use_dpop_nonce", StringComparison.OrdinalIgnoreCase)
                    || authRequest.Response.Error.Equals("invalid_dpop_proof", StringComparison.OrdinalIgnoreCase))
                {
                    // A DPoP nonce is required to be sent with the request, create a new request with the nonce
                    // value which should be present in the response headers.
                    var nonce = response.HttpResponse.Headers.TryGetValues("DPoP-Nonce", out var values) ? values.FirstOrDefault() : null;
                    if (!string.IsNullOrWhiteSpace(nonce))
                    {
                        // Clone the parameters to avoid modifying the original request parameters.
                        var nonceRequestParameters = new AuthRequestParameters(requestParameters);
                        var nonceRequest = flow.AddRequest(nonceRequestParameters);
                        nonceRequestParameters.DPoPNonce = nonce;
                        request.DPoPProofToken = await GetDPoPProofTokenAsync(requestParameters.TokenEndpoint, nonceRequestParameters.DPoPNonce);
                        var nonceResponse = await protocolInvoker(client, request);
                        nonceRequest.Response = responseMapper(nonceResponse);
                        return nonceRequest;
                    }
                }
                else if (authRequest.Response.ErrorDescription != null && authRequest.Response.ErrorDescription.Contains("AADSTS9002327", StringComparison.InvariantCultureIgnoreCase))
                {
                    // Add an Origin header in case the request is for a PKCE flow on a "SPA" type app registration,
                    // to emulate the fact that we're sending this call from a browser and avoid this error:
                    // "AADSTS9002327: Tokens issued for the 'Single-Page Application' client-type may only be redeemed via cross-origin requests".
                    // See https://github.com/AzureAD/microsoft-authentication-library-for-js/issues/2482 and
                    // https://learn.microsoft.com/entra/identity-platform/v2-oauth2-auth-code-flow#redirect-uris-for-single-page-apps-spas
                    // We don't know the app registration type up front, and adding the Origin header on a non-SPA
                    // app registration triggers a similar error (AADSTS9002326) so we reactively trigger a new request
                    // with the Origin header only if we encounter this specific error.
                    client.DefaultRequestHeaders.Add("Origin", requestParameters.RedirectUri);
                    var spaRequest = flow.AddRequest(requestParameters);
                    var spaResponse = await protocolInvoker(client, request);
                    spaRequest.Response = responseMapper(spaResponse);
                    return spaRequest;
                }
            }
            return authRequest;
        }

        private static string CreateDPoPProofKey()
        {
            var key = new RsaSecurityKey(RSA.Create(2048));
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            jwk.Alg = "PS256";
            var jwkJson = JsonSerializer.Serialize(jwk);
            return jwkJson;
        }

        private async Task<string> GetDPoPProofTokenAsync(string url, string nonce = null)
        {
            var proofToken = await this.dPoPProofService.CreateProofTokenAsync(new DPoPProofRequest
            {
                Url = url,
                Method = HttpMethod.Post.ToString(),
                DPoPJsonWebKey = DPoPProofKey,
                DPoPNonce = nonce
            });
            return proofToken.ProofToken;
        }

        #endregion
    }
}