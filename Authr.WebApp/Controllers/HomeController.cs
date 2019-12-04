using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Authr.WebApp.Models;
using IdentityModel;
using IdentityModel.Client;
using Authr.WebApp.Services;

namespace Authr.WebApp.Controllers
{
    public class HomeController : Controller
    {
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
        public async Task<IActionResult> Index(AuthRequest request, ExternalResponse response)
        {
            var model = await HandleAsync(request, response);
            if (this.User.Identity.IsAuthenticated)
            {
                model.UserConfiguration = await this.userConfigurationProvider.GetUserConfigurationAsync(this.User.GetUserId());
            }
            return View(model);
        }

        [Route("")]
        [HttpPost]
        public async Task<IActionResult> IndexPost(AuthRequest request, ExternalResponse response)
        {
            var model = await HandleAsync(request, response);
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
        public Task<AuthViewModel> SubmitRequest([FromBody]AuthRequest request)
        {
            return HandleAsync(request, null);
        }

        [Route("api/response")]
        [HttpPost]
        public Task<AuthViewModel> SubmitResponse([FromBody]ExternalResponse response)
        {
            return HandleAsync(null, response);
        }

        #region Helper Methods

        private async Task<AuthViewModel> HandleAsync(AuthRequest request, ExternalResponse response)
        {
            // TODO: Add validation and throw exceptions with meaningful messages.
            // TODO: Cache complete "AuthFlow" with a single correlation id, and don't remove from cache until IsComplete = true.
            var model = new AuthViewModel();
            try
            {
                if (response != null && !response.IsEmpty())
                {
                    // We have a response to a previously initiated request.
                    var originalRequest = default(AuthRequest);
                    if (!string.IsNullOrWhiteSpace(response.State))
                    {
                        // We have a state correlation id, this a response to an existing request we should have full request details for.
                        // TODO: Check that the request belongs to the current user if signed in.
                        if (RequestCache.ContainsKey(response.State))
                        {
                            originalRequest = RequestCache[response.State];
                            model.Request = originalRequest.Clone();
                            RequestCache.Remove(response.State);
                        }
                        else
                        {
                            this.logger.LogWarning($"Original request not found for 'state' \"{response.State}\"");
                        }
                    }

                    model.Response = AuthResponse.FromExternalResponse(response);

                    // If there is an authorization code response, redeem it immediately for the access token.
                    if (!string.IsNullOrWhiteSpace(response.AuthorizationCode) && originalRequest != null)
                    {
                        // TODO: Also track this new auth code request in the auth flow.
                        var authorizationCodeRequest = originalRequest.Clone();
                        authorizationCodeRequest.Nonce = Guid.NewGuid().ToString(); // TODO: Move into ctor for AuthRequest(AuthRequestParameters).
                        authorizationCodeRequest.State = Guid.NewGuid().ToString();
                        authorizationCodeRequest.TimeCreated = DateTimeOffset.UtcNow;
                        authorizationCodeRequest.AuthorizationCode = response.AuthorizationCode;
                        model.Request = authorizationCodeRequest.Clone();
                        model.Response = await HandleAuthorizationCodeResponseAsync(authorizationCodeRequest);
                    }
                }
                else if (request != null && !string.IsNullOrWhiteSpace(request.RequestType))
                {
                    // This is a new auth request, determine which flow to execute.
                    model.Request = request.Clone();
                    request.Nonce = Guid.NewGuid().ToString();
                    request.State = Guid.NewGuid().ToString();
                    request.TimeCreated = DateTimeOffset.UtcNow;
                    if (request.RequestType == Constants.RequestTypes.OpenIdConnect || request.RequestType == Constants.RequestTypes.Implicit || request.RequestType == Constants.RequestTypes.AuthorizationCode)
                    {
                        var authorizationEndpointRequestUrl = GetAuthorizationEndpointRequestUrl(request);
                        RequestCache[request.State] = request;
                        model.RedirectUrl = authorizationEndpointRequestUrl;
                    }
                    else if (request.RequestType == Constants.RequestTypes.ClientCredentials)
                    {
                        model.Response = await HandleClientCredentialsRequestAsync(request);
                    }
                    else if (request.RequestType == Constants.RequestTypes.RefreshToken)
                    {
                        model.Response = await HandleRefreshTokenRequestAsync(request);
                    }
                    else if (request.RequestType == Constants.RequestTypes.DeviceCode)
                    {
                        model.Response = await HandleDeviceCodeRequestAsync(request);
                    }
                    else if (request.RequestType == Constants.RequestTypes.DeviceToken)
                    {
                        model.Response = await HandleDeviceTokenRequestAsync(request);
                    }
                    else if (request.RequestType == Constants.RequestTypes.ResourceOwnerPasswordCredentials)
                    {
                        model.Response = await HandleResourceOwnerPasswordCredentialsRequestAsync(request);
                    }
                }
                if (model.Request == null)
                {
                    model.Request = request ?? new AuthRequest();
                    // Set sensible defaults if not provided.
                    model.Request.RequestType = model.Request.RequestType ?? Constants.RequestTypes.OpenIdConnect;
                    model.Request.ResponseType = model.Request.ResponseType ?? OidcConstants.ResponseTypes.IdToken;
                    model.Request.Scope = model.Request.Scope ?? OidcConstants.StandardScopes.OpenId;
                    model.Request.ResponseMode = model.Request.ResponseMode ?? OidcConstants.ResponseModes.FormPost;
                    model.Request.RedirectUri = model.Request.RedirectUri ?? this.Url.Action(nameof(Index), null, null, this.Request.Scheme);
                }
            }
            catch (Exception exc)
            {
                model.Response = AuthResponse.FromException(exc);
            }
            return model;
        }

        private async Task<AuthResponse> HandleClientCredentialsRequestAsync(AuthRequest request)
        {
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = request.TokenEndpoint,
                ClientId = request.ClientId,
                ClientSecret = request.ClientSecret,
                Scope = request.Scope
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private async Task<AuthResponse> HandleRefreshTokenRequestAsync(AuthRequest request)
        {
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = request.TokenEndpoint,
                ClientId = request.ClientId,
                ClientSecret = request.ClientSecret,
                Scope = request.Scope,
                RefreshToken = request.RefreshToken
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private async Task<AuthResponse> HandleDeviceCodeRequestAsync(AuthRequest request)
        {
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestDeviceAuthorizationAsync(new DeviceAuthorizationRequest
            {
                Address = request.DeviceCodeEndpoint,
                ClientId = request.ClientId,
                Scope = request.Scope
            });
            return AuthResponse.FromDeviceCodeResponse(response);
        }

        private async Task<AuthResponse> HandleDeviceTokenRequestAsync(AuthRequest request)
        {
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestDeviceTokenAsync(new DeviceTokenRequest
            {
                Address = request.TokenEndpoint,
                ClientId = request.ClientId,
                DeviceCode = request.DeviceCode
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private async Task<AuthResponse> HandleResourceOwnerPasswordCredentialsRequestAsync(AuthRequest request)
        {
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = request.TokenEndpoint,
                ClientId = request.ClientId,
                ClientSecret = request.ClientSecret,
                Scope = request.Scope,
                UserName = request.UserName,
                Password = request.Password
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private string GetAuthorizationEndpointRequestUrl(AuthRequest request)
        {
            var urlBuilder = new RequestUrl(request.AuthorizationEndpoint);
            return urlBuilder.CreateAuthorizeUrl(
                clientId: request.ClientId,
                responseType: request.ResponseType,
                scope: request.Scope,
                redirectUri: request.RedirectUri,
                responseMode: request.ResponseMode,
                nonce: request.Nonce,
                state: request.State
            );
        }

        private async Task<AuthResponse> HandleAuthorizationCodeResponseAsync(AuthRequest request)
        {
            if (request.RequestType != Constants.RequestTypes.OpenIdConnect && request.RequestType != Constants.RequestTypes.AuthorizationCode)
            {
                throw new Exception("Mismatching request type for Authorization Code grant");
            }
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
            {
                Address = request.TokenEndpoint,
                ClientId = request.ClientId,
                ClientSecret = request.ClientSecret,
                Code = request.AuthorizationCode,
                RedirectUri = request.RedirectUri
            });
            return AuthResponse.FromTokenResponse(response);
        }

        #endregion
    }
}