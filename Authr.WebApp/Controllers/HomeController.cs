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

namespace Authr.WebApp.Controllers
{
    public class HomeController : Controller
    {
        private static readonly IDictionary<string, AuthRequest> RequestCache = new Dictionary<string, AuthRequest>();
        private readonly ILogger<HomeController> logger;
        private readonly IHttpClientFactory httpClientFactory;

        public HomeController(ILogger<HomeController> logger, IHttpClientFactory httpClientFactory)
        {
            this.logger = logger;
            this.httpClientFactory = httpClientFactory;
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public IActionResult Index()
        {
            var model = new AuthViewModel();
            model.Request = new AuthRequest
            {
                RequestType = Constants.RequestTypes.AuthorizationCode,
                ResponseType = OidcConstants.ResponseTypes.IdToken,
                Scope = OidcConstants.StandardScopes.OpenId
            };
            return View(model);
        }

        [ActionName(nameof(Index))]
        [HttpPost]
        public async Task<IActionResult> IndexPost()
        {
            var model = new AuthViewModel();
            try
            {
                if (this.Request.Form.ContainsKey("state"))
                {
                    // We have a state correlation id, handle a response to an existing request.
                    // TODO: Check that the request belongs to the current user if signed in.
                    var state = this.Request.Form["state"].First();
                    if (RequestCache.ContainsKey(state))
                    {
                        model.Request = RequestCache[state];
                        RequestCache.Remove(state);
                    }
                    else
                    {
                        this.logger.LogInformation($"Request not found for 'state' \"{state}\"");
                        model.Request = new AuthRequest();
                    }

                    if (this.Request.Form.ContainsKey("error"))
                    {
                        model.Response = AuthResponse.FromError(this.Request.Form["error"].First(), this.Request.Form["error_description"].FirstOrDefault());
                    }
                    else if (this.Request.Form.ContainsKey("code"))
                    {
                        model.Request.AuthorizationCode = this.Request.Form["code"].First();
                        model.Response = await HandleAuthorizationCodeResponseAsync(model.Request);
                    }
                    else
                    {
                        model.Response = new AuthResponse
                        {
                            IdToken = this.Request.Form[OidcConstants.AuthorizeResponse.IdentityToken].FirstOrDefault(),
                            AccessToken = this.Request.Form[OidcConstants.AuthorizeResponse.AccessToken].FirstOrDefault(),
                            TokenType = this.Request.Form[OidcConstants.AuthorizeResponse.TokenType].FirstOrDefault(),
                            RefreshToken = this.Request.Form[OidcConstants.AuthorizeResponse.RefreshToken].FirstOrDefault()
                        };
                    }
                }
                else
                {
                    // There is no state correlation id, this is a new request.
                    var request = new AuthRequest();
                    if (await this.TryUpdateModelAsync<AuthRequest>(request))
                    {
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
                }
            }
            catch (Exception exc)
            {
                model.Request = model.Request ?? new AuthRequest();
                model.Response = AuthResponse.FromException(exc);
            }
            return View(model);
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

        private IActionResult HandleAuthorizationCodeRequest(AuthRequest request)
        {
            var urlBuilder = new RequestUrl(request.AuthorizeEndpoint);
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
    }
}