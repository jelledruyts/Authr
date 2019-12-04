using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Authr.WebApp.Models;
using Authr.WebApp.Services;
using IdentityModel;
using IdentityModel.Client;

namespace Authr.WebApp.Controllers
{
    public class HomeController : Controller
    {
        // TODO: Use persistent store.
        private static readonly IDictionary<string, AuthRequest> RequestCache = new Dictionary<string, AuthRequest>();
        private readonly ILogger<HomeController> logger;
        private readonly IHttpClientFactory httpClientFactory;
        private readonly IUserConfigurationProvider userConfigurationProvider;

        public HomeController(ILogger<HomeController> logger, IHttpClientFactory httpClientFactory, IUserConfigurationProvider userConfigurationProvider)
        {
            this.logger = logger;
            this.httpClientFactory = httpClientFactory;
            this.userConfigurationProvider = userConfigurationProvider;
        }

        [Route(nameof(Error))]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Route("")]
        public async Task<IActionResult> Index(AuthRequestParameters requestParameters, AuthResponseParameters responseParameters)
        {
            var model = await HandleAsync(requestParameters, responseParameters);
            if (this.User.Identity.IsAuthenticated)
            {
                model.UserConfiguration = await this.userConfigurationProvider.GetUserConfigurationAsync(this.User.GetUserId());
            }
            return View(model);
        }

        [Route("")]
        [HttpPost]
        public async Task<IActionResult> IndexPost(AuthRequestParameters requestParameters, AuthResponseParameters responseParameters)
        {
            var model = await HandleAsync(requestParameters, responseParameters);
            if (!string.IsNullOrWhiteSpace(model.RedirectUrl))
            {
                return Redirect(model.RedirectUrl);
            }
            else
            {
                if (this.User.Identity.IsAuthenticated)
                {
                    model.UserConfiguration = await this.userConfigurationProvider.GetUserConfigurationAsync(this.User.GetUserId());
                }
                return View(nameof(Index), model);
            }
        }

        [Route("api/request")]
        [HttpPost]
        public Task<AuthViewModel> SubmitRequest([FromBody]AuthRequestParameters requestParameters)
        {
            return HandleAsync(requestParameters, null);
        }

        [Route("api/response")]
        [HttpPost]
        public Task<AuthViewModel> SubmitResponse([FromBody]AuthResponseParameters responseParameters)
        {
            return HandleAsync(null, responseParameters);
        }

        #region Helper Methods

        private async Task<AuthViewModel> HandleAsync(AuthRequestParameters requestParameters, AuthResponseParameters responseParameters)
        {
            // TODO: Add validation and throw exceptions with meaningful messages.
            // TODO: Cache complete "AuthFlow" with a single correlation id, and don't remove from cache until IsComplete = true.
            var model = new AuthViewModel();
            try
            {
                if (responseParameters != null && !responseParameters.IsEmpty())
                {
                    // We have a response to a previously initiated request.
                    var originalRequest = default(AuthRequest);
                    if (!string.IsNullOrWhiteSpace(responseParameters.State))
                    {
                        // We have a state correlation id, this a response to an existing request we should have full request details for.
                        // TODO: Check that the request belongs to the current user if signed in.
                        if (RequestCache.ContainsKey(responseParameters.State))
                        {
                            originalRequest = RequestCache[responseParameters.State];
                            model.RequestParameters = originalRequest.Parameters;
                            RequestCache.Remove(responseParameters.State);
                        }
                        else
                        {
                            this.logger.LogWarning($"Original request not found for 'state' \"{responseParameters.State}\"");
                        }
                    }

                    model.Response = AuthResponse.FromAuthResponseParameters(responseParameters);

                    // If there is an authorization code response, redeem it immediately for the access token.
                    if (!string.IsNullOrWhiteSpace(responseParameters.AuthorizationCode) && originalRequest != null)
                    {
                        // TODO: Also track this new auth code request in the auth flow.
                        var authorizationCodeRequest = new AuthRequest(originalRequest.Parameters.Clone());
                        authorizationCodeRequest.Parameters.AuthorizationCode = responseParameters.AuthorizationCode;
                        model.RequestParameters = authorizationCodeRequest.Parameters;
                        model.Response = await HandleAuthorizationCodeResponseAsync(authorizationCodeRequest.Parameters);
                    }
                }
                else if (requestParameters != null && !string.IsNullOrWhiteSpace(requestParameters.RequestType))
                {
                    // This is a new auth request, determine which flow to execute.
                    model.RequestParameters = requestParameters;
                    var request = new AuthRequest(requestParameters);
                    if (requestParameters.RequestType == Constants.RequestTypes.OpenIdConnect || requestParameters.RequestType == Constants.RequestTypes.Implicit || requestParameters.RequestType == Constants.RequestTypes.AuthorizationCode)
                    {
                        var authorizationEndpointRequestUrl = GetAuthorizationEndpointRequestUrl(request);
                        RequestCache[request.State] = request;
                        model.RedirectUrl = authorizationEndpointRequestUrl;
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.ClientCredentials)
                    {
                        model.Response = await HandleClientCredentialsRequestAsync(requestParameters);
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.RefreshToken)
                    {
                        model.Response = await HandleRefreshTokenRequestAsync(requestParameters);
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.DeviceCode)
                    {
                        model.Response = await HandleDeviceCodeRequestAsync(requestParameters);
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.DeviceToken)
                    {
                        model.Response = await HandleDeviceTokenRequestAsync(requestParameters);
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.ResourceOwnerPasswordCredentials)
                    {
                        model.Response = await HandleResourceOwnerPasswordCredentialsRequestAsync(requestParameters);
                    }
                }
                if (model.RequestParameters == null)
                {
                    // Create new request parameters and set sensible defaults if not provided.
                    model.RequestParameters = requestParameters ?? new AuthRequestParameters();
                    model.RequestParameters.RequestType = model.RequestParameters.RequestType ?? Constants.RequestTypes.OpenIdConnect;
                    model.RequestParameters.ResponseType = model.RequestParameters.ResponseType ?? OidcConstants.ResponseTypes.IdToken;
                    model.RequestParameters.Scope = model.RequestParameters.Scope ?? OidcConstants.StandardScopes.OpenId;
                    model.RequestParameters.ResponseMode = model.RequestParameters.ResponseMode ?? OidcConstants.ResponseModes.FormPost;
                    model.RequestParameters.RedirectUri = model.RequestParameters.RedirectUri ?? this.Url.Action(nameof(Index), null, null, this.Request.Scheme);
                }
            }
            catch (Exception exc)
            {
                model.Response = AuthResponse.FromException(exc);
            }
            return model;
        }

        private async Task<AuthResponse> HandleClientCredentialsRequestAsync(AuthRequestParameters requestParameters)
        {
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                Scope = requestParameters.Scope
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private async Task<AuthResponse> HandleRefreshTokenRequestAsync(AuthRequestParameters requestParameters)
        {
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                Scope = requestParameters.Scope,
                RefreshToken = requestParameters.RefreshToken
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private async Task<AuthResponse> HandleDeviceCodeRequestAsync(AuthRequestParameters requestParameters)
        {
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestDeviceAuthorizationAsync(new DeviceAuthorizationRequest
            {
                Address = requestParameters.DeviceCodeEndpoint,
                ClientId = requestParameters.ClientId,
                Scope = requestParameters.Scope
            });
            return AuthResponse.FromDeviceCodeResponse(response);
        }

        private async Task<AuthResponse> HandleDeviceTokenRequestAsync(AuthRequestParameters requestParameters)
        {
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestDeviceTokenAsync(new DeviceTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                DeviceCode = requestParameters.DeviceCode
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private async Task<AuthResponse> HandleResourceOwnerPasswordCredentialsRequestAsync(AuthRequestParameters requestParameters)
        {
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                Scope = requestParameters.Scope,
                UserName = requestParameters.UserName,
                Password = requestParameters.Password
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private string GetAuthorizationEndpointRequestUrl(AuthRequest request)
        {
            var urlBuilder = new RequestUrl(request.Parameters.AuthorizationEndpoint);
            return urlBuilder.CreateAuthorizeUrl(
                clientId: request.Parameters.ClientId,
                responseType: request.Parameters.ResponseType,
                scope: request.Parameters.Scope,
                redirectUri: request.Parameters.RedirectUri,
                responseMode: request.Parameters.ResponseMode,
                nonce: request.Nonce,
                state: request.State
            );
        }

        private async Task<AuthResponse> HandleAuthorizationCodeResponseAsync(AuthRequestParameters requestParameters)
        {
            if (requestParameters.RequestType != Constants.RequestTypes.OpenIdConnect && requestParameters.RequestType != Constants.RequestTypes.AuthorizationCode)
            {
                throw new Exception("Mismatching request type for Authorization Code grant");
            }
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                Code = requestParameters.AuthorizationCode,
                RedirectUri = requestParameters.RedirectUri
            });
            return AuthResponse.FromTokenResponse(response);
        }

        #endregion
    }
}