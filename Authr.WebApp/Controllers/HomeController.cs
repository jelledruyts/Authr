using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
        public async Task<IActionResult> Index(AuthRequest request)
        {
            var model = new AuthViewModel { Request = request };
            model.Request.RequestType = model.Request.RequestType ?? Constants.RequestTypes.AuthorizationCode;
            model.Request.ResponseType = model.Request.ResponseType ?? OidcConstants.ResponseTypes.IdToken;
            model.Request.Scope = model.Request.Scope ?? OidcConstants.StandardScopes.OpenId;
            if (this.User.Identity.IsAuthenticated)
            {
                model.UserConfiguration = await this.userConfigurationProvider.GetUserConfigurationAsync(this.User.GetUserId());
            }
            return View(model);
        }

        [Route("")]
        [HttpPost]
        public async Task<IActionResult> Index(AuthRequest request, ExternalResponse response)
        {
            var model = new AuthViewModel();
            try
            {
                if (!string.IsNullOrWhiteSpace(request.RequestType))
                {
                    // This is a new auth request, determine which flow to execute.
                    model.Request = request;
                    request.RedirectUri = this.Url.Action(nameof(Index), null, null, this.Request.Scheme);
                    request.ResponseMode = OidcConstants.ResponseModes.FormPost;
                    request.Nonce = Guid.NewGuid().ToString();
                    request.State = Guid.NewGuid().ToString();
                    if (request.RequestType == Constants.RequestTypes.AuthorizationCode)
                    {
                        return HandleAuthorizationCodeRequest(request);
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
                else if (!string.IsNullOrWhiteSpace(response.State))
                {
                    // We have a state correlation id, handle a response to an existing request.
                    // TODO: Check that the request belongs to the current user if signed in.
                    if (RequestCache.ContainsKey(response.State))
                    {
                        model.Request = RequestCache[response.State];
                        RequestCache.Remove(response.State);
                    }
                    else
                    {
                        this.logger.LogWarning($"Request not found for 'state' \"{response.State}\"");
                        model.Request = new AuthRequest();
                    }

                    if (!string.IsNullOrWhiteSpace(response.Error))
                    {
                        model.Response = AuthResponse.FromError(response.Error, response.ErrorDescription);
                    }
                    else if (!string.IsNullOrWhiteSpace(response.AuthorizationCode))
                    {
                        model.Request.AuthorizationCode = response.AuthorizationCode;
                        model.Response = await HandleAuthorizationCodeResponseAsync(model.Request);
                    }
                    else
                    {
                        model.Response = new AuthResponse
                        {
                            IdToken = response.IdToken,
                            AccessToken = response.AccessToken,
                            TokenType = response.TokenType,
                            RefreshToken = response.RefreshToken
                        };
                    }
                }
            }
            catch (Exception exc)
            {
                model.Response = AuthResponse.FromException(exc);
            }
            model.Request = model.Request ?? new AuthRequest();
            if (this.User.Identity.IsAuthenticated)
            {
                model.UserConfiguration = await this.userConfigurationProvider.GetUserConfigurationAsync(this.User.GetUserId());
            }
            return View(nameof(Index), model);
        }

        #region Helper Methods

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

        private IActionResult HandleAuthorizationCodeRequest(AuthRequest request)
        {
            var urlBuilder = new RequestUrl(request.AuthorizationEndpoint);
            request.RequestUrl = urlBuilder.CreateAuthorizeUrl(
                clientId: request.ClientId,
                responseType: request.ResponseType,
                scope: request.Scope,
                redirectUri: request.RedirectUri,
                responseMode: request.ResponseMode,
                nonce: request.Nonce,
                state: request.State
            );
            RequestCache[request.State] = request;
            return Redirect(request.RequestUrl);
        }

        private async Task<AuthResponse> HandleAuthorizationCodeResponseAsync(AuthRequest request)
        {
            if (request.RequestType != Constants.RequestTypes.AuthorizationCode)
            {
                throw new Exception("Mismatching request type");
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