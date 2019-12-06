using System;
using System.Diagnostics;
using System.Linq;
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
    // TODO: Keep full http traces.
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> logger;
        private readonly IHttpClientFactory httpClientFactory;
        private readonly IUserConfigurationProvider userConfigurationProvider;
        private readonly IAuthFlowCacheProvider authFlowCacheProvider;

        public HomeController(ILogger<HomeController> logger, IHttpClientFactory httpClientFactory, IUserConfigurationProvider userConfigurationProvider, IAuthFlowCacheProvider authFlowCacheProvider)
        {
            this.logger = logger;
            this.httpClientFactory = httpClientFactory;
            this.userConfigurationProvider = userConfigurationProvider;
            this.authFlowCacheProvider = authFlowCacheProvider;
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
            if (!string.IsNullOrWhiteSpace(model.RequestedRedirectUrl))
            {
                return Redirect(model.RequestedRedirectUrl);
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
            var model = new AuthViewModel();
            try
            {
                if (responseParameters != null && !responseParameters.IsEmpty())
                {
                    // We have a response to a previously initiated flow, retrieve the flow details from cache.
                    var flow = default(AuthFlow);
                    var shouldRemoveFlowFromCacheWhenComplete = false;
                    if (!string.IsNullOrWhiteSpace(responseParameters.State))
                    {
                        // We have a state correlation id, this a response to an existing request we should have full request details for.
                        // TODO: Check that the request belongs to the current user if signed in.
                        // The flow id should be in the State parameter as passed in during the request original.
                        var flowId = responseParameters.State;
                        flow = await this.authFlowCacheProvider.GetAuthFlowAsync(flowId);
                        if (flow != null)
                        {
                            shouldRemoveFlowFromCacheWhenComplete = true;
                        }
                        else
                        {
                            this.logger.LogWarning($"Flow with original request not found for 'state' \"{responseParameters.State}\"");
                        }
                    }
                    if (flow == null)
                    {
                        // We have a response to a flow that was not originated here (e.g. it could be IdP-initiated).
                        flow = new AuthFlow();
                        flow.AddExternallyInitiatedRequest();
                    }
                    model.Flow = flow;
                    var originalRequest = flow.Requests.Last();
                    model.RequestParameters = originalRequest.Parameters;

                    var response = AuthResponse.FromAuthResponseParameters(responseParameters);
                    originalRequest.Response = response;

                    // If there is an authorization code response, redeem it immediately for the access token.
                    if (!string.IsNullOrWhiteSpace(responseParameters.AuthorizationCode))
                    {
                        if (originalRequest.IsInitiatedExternally)
                        {
                            originalRequest.Response = AuthResponse.FromError("An authorization code was received but the request was initiated externally, cannot redeem it for an access token.", $"Authorization code: \"{responseParameters.AuthorizationCode}\".");
                        }
                        else
                        {
                            var authorizationCodeRequestParameters = originalRequest.Parameters.Clone();
                            authorizationCodeRequestParameters.RequestType = Constants.RequestTypes.AuthorizationCode;
                            authorizationCodeRequestParameters.AuthorizationCode = responseParameters.AuthorizationCode;
                            var authorizationCodeRequest = flow.AddRequest(authorizationCodeRequestParameters);
                            var authorizationCodeResponse = await HandleAuthorizationCodeResponseAsync(authorizationCodeRequest.Parameters);
                            authorizationCodeRequest.Response = authorizationCodeResponse;
                        }
                    }
                    flow.IsComplete = true;
                    if (flow.IsComplete && shouldRemoveFlowFromCacheWhenComplete)
                    {
                        await this.authFlowCacheProvider.RemoveAuthFlowAsync(responseParameters.State);
                    }

                    // Set the response to the last relevant response received.
                    model.Response = flow.Requests.Last().Response;
                }
                else if (requestParameters != null && !string.IsNullOrWhiteSpace(requestParameters.RequestType))
                {
                    // This is a new auth request, determine which flow to execute.
                    var flow = new AuthFlow();
                    model.Flow = flow;
                    model.RequestParameters = requestParameters;
                    var request = flow.AddRequest(requestParameters);
                    if (requestParameters.RequestType == Constants.RequestTypes.OpenIdConnect || requestParameters.RequestType == Constants.RequestTypes.Implicit || requestParameters.RequestType == Constants.RequestTypes.AuthorizationCode)
                    {
                        request.RequestedRedirectUrl = GetAuthorizationEndpointRequestUrl(request);
                        await this.authFlowCacheProvider.SetAuthFlowAsync(flow);
                        model.RequestedRedirectUrl = request.RequestedRedirectUrl;
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.ClientCredentials)
                    {
                        request.Response = await HandleClientCredentialsRequestAsync(requestParameters);
                        flow.IsComplete = true;
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.RefreshToken)
                    {
                        request.Response = await HandleRefreshTokenRequestAsync(requestParameters);
                        flow.IsComplete = true;
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.DeviceCode)
                    {
                        request.Response = await HandleDeviceCodeRequestAsync(requestParameters);
                        flow.IsComplete = true;
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.DeviceToken)
                    {
                        request.Response = await HandleDeviceTokenRequestAsync(requestParameters);
                        flow.IsComplete = true;
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.ResourceOwnerPasswordCredentials)
                    {
                        request.Response = await HandleResourceOwnerPasswordCredentialsRequestAsync(requestParameters);
                        flow.IsComplete = true;
                    }

                    // Set the response to the last relevant response received.
                    model.Response = flow.Requests.Last().Response;
                }
            }
            catch (Exception exc)
            {
                model.Response = AuthResponse.FromException(exc);
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
            return model;
        }

        private async Task<AuthResponse> HandleClientCredentialsRequestAsync(AuthRequestParameters requestParameters)
        {
            GuardNotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified.");
            GuardNotEmpty(requestParameters.ClientSecret, "The client credentials must be specified.");
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
            GuardNotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified.");
            GuardNotEmpty(requestParameters.ClientSecret, "The client credentials must be specified.");
            GuardNotEmpty(requestParameters.RefreshToken, "The refresh token must be specified.");
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
            GuardNotEmpty(requestParameters.DeviceCodeEndpoint, "The device code endpoint must be specified.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified.");
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
            GuardNotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified.");
            GuardNotEmpty(requestParameters.DeviceCode, "The device code must be specified.");
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
            GuardNotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified.");
            GuardNotEmpty(requestParameters.ClientSecret, "The client credentials must be specified.");
            GuardNotEmpty(requestParameters.UserName, "The user name must be specified.");
            GuardNotEmpty(requestParameters.Password, "The password must be specified.");
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
            GuardNotEmpty(request.Parameters.AuthorizationEndpoint, "The authorization endpoint must be specified.");
            GuardNotEmpty(request.Parameters.ClientId, "The client id must be specified.");
            GuardNotEmpty(request.Parameters.RedirectUri, "The redirect uri must be specified.");
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
            GuardNotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified.");
            GuardNotEmpty(requestParameters.ClientSecret, "The client credentials must be specified.");
            GuardNotEmpty(requestParameters.AuthorizationCode, "The authorization code must be specified.");
            if (requestParameters.RequestType != Constants.RequestTypes.OpenIdConnect && requestParameters.RequestType != Constants.RequestTypes.AuthorizationCode)
            {
                throw new Exception("Invalid request type for Authorization Code grant: " + requestParameters.RequestType);
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

        private static void GuardNotEmpty(string value, string message)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException(message);
            }
        }

        #endregion
    }
}