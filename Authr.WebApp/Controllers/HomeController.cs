using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.ApplicationInsights;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Authr.WebApp.Models;
using Authr.WebApp.Services;
using IdentityModel;
using IdentityModel.Client;

namespace Authr.WebApp.Controllers
{
    // TODO: Manage user configuration (edit, delete items).
    // TODO: Keep full http traces.
    // TODO: Make tab pages part of main navbar.
    // TODO: Show interpretation of claims in token decoder tab (and send raw tokens to it from response tab).
    // TODO: Add token service from metadata and auto-detect OIDC/OAuth/SAML/...
    // TODO: Checkboxes for common scopes (openid, offline_access, email, profile, ...).
    // TODO: Checkboxes for common response types (id_token, token, code, <custom>).
    // TODO: Radio buttons for common response modes (form_post, query, fragment, <custom>).
    // TODO: Periodically remove old flows from cache.
    // TODO: Support SAML 2.0.
    // TODO: Support WS-Federation.
    // TODO: Save concrete flow to history.
    // TODO: Migrate to .NET Core 3.1 when App Service supports it.
    public class HomeController : Controller
    {
        #region Fields

        private readonly ILogger<HomeController> logger;
        private readonly IHttpClientFactory httpClientFactory;
        private readonly IUserConfigurationProvider userConfigurationProvider;
        private readonly IAuthFlowCacheProvider authFlowCacheProvider;
        private readonly TelemetryClient telemetryClient;

        #endregion

        #region Constructors

        public HomeController(ILogger<HomeController> logger, IHttpClientFactory httpClientFactory, IUserConfigurationProvider userConfigurationProvider, IAuthFlowCacheProvider authFlowCacheProvider, TelemetryClient telemetryClient)
        {
            this.logger = logger;
            this.httpClientFactory = httpClientFactory;
            this.userConfigurationProvider = userConfigurationProvider;
            this.authFlowCacheProvider = authFlowCacheProvider;
            this.telemetryClient = telemetryClient;
        }

        #endregion

        #region Action Methods

        [Route(nameof(Privacy))]
        public IActionResult Privacy()
        {
            return View();
        }

        [Route(nameof(Terms))]
        public IActionResult Terms()
        {
            return View();
        }

        [Route(nameof(Error))]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Route("")]
        public Task<IActionResult> Index(AuthRequestParameters requestParameters, AuthResponseParameters responseParameters)
        {
            // Whenever a GET comes in, bind the possibly matching parameters to a request or response (done automatically
            // by model binding) and attempt to handle either.
            return HandlePageRequestAsync(requestParameters, responseParameters);
        }

        [Route("")]
        [HttpPost]
        public Task<IActionResult> IndexPost(AuthRequestParameters requestParameters, AuthResponseParameters responseParameters)
        {
            // Whenever a POST comes in, bind the possibly matching parameters to a request or response (done automatically
            // by model binding) and attempt to handle either.
            return HandlePageRequestAsync(requestParameters, responseParameters);
        }

        [Route("api/request")]
        [HttpPost]
        public Task<AuthViewModel> SubmitRequest([FromBody]ApiClientRequest request)
        {
            // This is an API call, do not return a page or redirect the browser but return the data only.
            return HandleApiRequestAsync(request, null);
        }

        [Route("api/response")]
        [HttpPost]
        public Task<AuthViewModel> SubmitResponse([FromBody]AuthResponseParameters responseParameters)
        {
            // This is an API call, do not return a page or redirect the browser but return the data only.
            return HandleApiRequestAsync(null, responseParameters);
        }

        #endregion

        #region Page & API Request Handling

        private async Task<IActionResult> HandlePageRequestAsync(AuthRequestParameters requestParameters, AuthResponseParameters responseParameters)
        {
            var model = await HandleCoreAsync(requestParameters, responseParameters);
            if (!string.IsNullOrWhiteSpace(model.RequestedRedirectUrl))
            {
                // The result of a request was to redirect the browser, send a redirect response.
                return Redirect(model.RequestedRedirectUrl);
            }
            else
            {
                // Render the regular page, optionally with user configuration if the user was signed in.
                if (this.User.Identity.IsAuthenticated)
                {
                    model.UserConfiguration = await this.userConfigurationProvider.GetUserConfigurationAsync(this.User.GetUserId());
                }
                return View(nameof(Index), model);
            }
        }

        private async Task<AuthViewModel> HandleApiRequestAsync(ApiClientRequest request, AuthResponseParameters responseParameters)
        {
            var userConfiguration = default(UserConfiguration);
            if (request != null && request.Options != null)
            {
                if (request.Options.SaveIdentityService || request.Options.SaveClientApplication || request.Options.SaveRequestTemplate)
                {
                    if (!this.User.Identity.IsAuthenticated)
                    {
                        this.logger.LogWarning("A request was made to save certain request options but the user is not authenticated.");
                    }
                    else
                    {
                        // Retrieve user configuration.
                        var userId = this.User.GetUserId();
                        userConfiguration = await this.userConfigurationProvider.GetUserConfigurationAsync(userId);

                        // Save the identity service.
                        if (request.Options.SaveIdentityService && !string.IsNullOrWhiteSpace(request.Options.SaveIdentityServiceAsName))
                        {
                            // Add or update the identity service in user configuration.
                            var identityService = MergeIdentityService(userConfiguration, request.Options.SaveIdentityServiceAsName, request.RequestParameters);

                            // Update the request parameters to refer to the identity service.
                            request.RequestParameters.IdentityServiceId = identityService.Id;
                        }

                        // Save the client app.
                        if (request.Options.SaveClientApplication && !string.IsNullOrWhiteSpace(request.Options.SaveClientApplicationAsName))
                        {
                            var identityService = userConfiguration.IdentityServices.SingleOrDefault(i => string.Equals(i.Id, request.RequestParameters.IdentityServiceId, StringComparison.InvariantCultureIgnoreCase));
                            if (identityService == null)
                            {
                                this.logger.LogWarning("A request was made to save the client app but the related identity service was not defined.");
                            }
                            else
                            {
                                // Add or update the client app in user configuration.
                                var clientApp = MergeClientApplication(userConfiguration, identityService, request.Options.SaveClientApplicationAsName, request.RequestParameters);

                                // Update the request parameters to refer to the client app.
                                request.RequestParameters.ClientApplicationId = clientApp.Id;
                            }
                        }

                        // Save the request template.
                        if (request.Options.SaveRequestTemplate && !string.IsNullOrWhiteSpace(request.Options.SaveRequestTemplateAsName))
                        {
                            // Add or update the client app in user configuration.
                            var requestTemplate = MergeRequestTemplate(userConfiguration, request.Options.SaveRequestTemplateAsName, request.RequestParameters);
                        }

                        await this.userConfigurationProvider.SaveUserConfigurationAsync(userConfiguration);
                        this.telemetryClient.TrackEvent("UserConfiguration.Saved");
                    }
                }
            }
            var model = await HandleCoreAsync(request?.RequestParameters, responseParameters);
            if (userConfiguration != null)
            {
                model.UserConfiguration = userConfiguration;
            }
            return model;
        }

        private IdentityService MergeIdentityService(UserConfiguration userConfiguration, string identityServiceName, AuthRequestParameters requestParameters)
        {
            var identityService = userConfiguration.IdentityServices.SingleOrDefault(i => string.Equals(i.Name, identityServiceName, StringComparison.InvariantCultureIgnoreCase));
            if (identityService != null)
            {
                this.logger.LogInformation($"Updating identity service \"{identityServiceName}\" for user \"{userConfiguration.UserId}\".");
                identityService.Update(requestParameters);
            }
            else
            {
                this.logger.LogInformation($"Adding identity service \"{identityServiceName}\" for user \"{userConfiguration.UserId}\".");
                identityService = IdentityService.FromRequestParameters(identityServiceName, requestParameters);
                userConfiguration.IdentityServices.Add(identityService);
            }
            return identityService;
        }

        private ClientApplication MergeClientApplication(UserConfiguration userConfiguration, IdentityService identityService, string clientApplicationName, AuthRequestParameters requestParameters)
        {
            var clientApplication = identityService.ClientApplications.SingleOrDefault(a => string.Equals(a.Name, clientApplicationName, StringComparison.InvariantCultureIgnoreCase));
            if (clientApplication != null)
            {
                this.logger.LogInformation($"Updating client application \"{clientApplicationName}\" for user \"{userConfiguration.UserId}\".");
                clientApplication.Update(requestParameters);
            }
            else
            {
                this.logger.LogInformation($"Adding client application \"{clientApplicationName}\" for user \"{userConfiguration.UserId}\".");
                clientApplication = ClientApplication.FromRequestParameters(clientApplicationName, requestParameters);
                identityService.ClientApplications.Add(clientApplication);
            }
            return clientApplication;
        }

        private AuthRequestTemplate MergeRequestTemplate(UserConfiguration userConfiguration, string requestTemplateName, AuthRequestParameters requestParameters)
        {
            var requestTemplate = userConfiguration.RequestTemplates.SingleOrDefault(r => string.Equals(r.Name, requestTemplateName, StringComparison.InvariantCultureIgnoreCase));
            if (requestTemplate != null)
            {
                this.logger.LogInformation($"Updating request template \"{requestTemplateName}\" for user \"{userConfiguration.UserId}\".");
                requestTemplate.Update(requestParameters);
            }
            else
            {
                this.logger.LogInformation($"Adding request template \"{requestTemplateName}\" for user \"{userConfiguration.UserId}\".");
                requestTemplate = AuthRequestTemplate.FromRequestParameters(requestTemplateName, requestParameters);
                userConfiguration.RequestTemplates.Add(requestTemplate);
            }
            return requestTemplate;
        }

        #endregion

        #region Core Auth Handling

        private async Task<AuthViewModel> HandleCoreAsync(AuthRequestParameters requestParameters, AuthResponseParameters responseParameters)
        {
            var model = new AuthViewModel();
            try
            {
                if (responseParameters != null && !responseParameters.IsEmpty())
                {
                    // We have a response to a previously initiated flow, retrieve the flow details from cache.
                    var flow = default(AuthFlow);
                    var flowReferenceToRemoveFromCacheWhenComplete = default(string);
                    if (!string.IsNullOrWhiteSpace(responseParameters.State))
                    {
                        // We have a state correlation id, this a response to an existing request we should have full request details for.
                        // The flow id should be in the State parameter as passed in during the request original.
                        var flowId = responseParameters.State;
                        flow = await this.authFlowCacheProvider.GetAuthFlowAsync(flowId);
                        if (flow != null)
                        {
                            flowReferenceToRemoveFromCacheWhenComplete = flow.Id;
                        }
                        else
                        {
                            this.logger.LogWarning($"Flow with original request not found for state \"{responseParameters.State}\".");
                        }
                    }
                    if (flow == null)
                    {
                        // We have a response to a flow that was not originated here (e.g. it could be IdP-initiated).
                        flow = new AuthFlow { UserId = this.User.GetUserId() };
                        this.telemetryClient.TrackEvent("AuthFlow.Initiated", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", flow.RequestType } });
                        flow.AddExternallyInitiatedRequest();
                    }

                    // Check that the request belongs to the current user if signed in.
                    if (!string.IsNullOrWhiteSpace(flow.UserId) && flow.UserId != this.User.GetUserId())
                    {
                        this.logger.LogWarning($"Flow \"{flow.Id}\" was requested by user \"{flow.UserId}\" but a response is now being processed by user \"{this.User.GetUserId()}\".");
                        throw new InvalidOperationException("You don't have permissions to this flow.");
                    }

                    model.Flow = flow;
                    var originalRequest = flow.Requests.Last();
                    model.RequestParameters = originalRequest.Parameters;

                    var response = AuthResponse.FromAuthResponseParameters(responseParameters);
                    originalRequest.Response = response;
                    this.telemetryClient.TrackEvent("AuthResponse.Received", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", originalRequest.Parameters?.RequestType } }, new Dictionary<string, double> { { "TimeTakenMs", (originalRequest.Response.TimeCreated - originalRequest.TimeCreated).TotalMilliseconds } });

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
                            this.telemetryClient.TrackEvent("AuthRequest.Sent", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", authorizationCodeRequest.Parameters?.RequestType } });
                            var authorizationCodeResponse = await HandleAuthorizationCodeResponseAsync(authorizationCodeRequest.Parameters);
                            authorizationCodeRequest.Response = authorizationCodeResponse;
                            this.telemetryClient.TrackEvent("AuthResponse.Received", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", authorizationCodeRequest.Parameters?.RequestType } }, new Dictionary<string, double> { { "TimeTakenMs", (authorizationCodeRequest.Response.TimeCreated - authorizationCodeRequest.TimeCreated).TotalMilliseconds } });
                        }
                    }
                    flow.IsComplete = true;
                    flow.TimeCompleted = DateTimeOffset.UtcNow;
                    this.telemetryClient.TrackEvent("AuthFlow.Completed", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", flow.RequestType } }, new Dictionary<string, double> { { "TimeTakenMs", (flow.TimeCompleted.Value - flow.TimeCreated).TotalMilliseconds } });
                    if (flow.IsComplete && !string.IsNullOrEmpty(flowReferenceToRemoveFromCacheWhenComplete))
                    {
                        await this.authFlowCacheProvider.RemoveAuthFlowAsync(flowReferenceToRemoveFromCacheWhenComplete);
                    }

                    // Set the response to the last relevant response received.
                    model.Response = flow.Requests.Last().Response;
                }
                else if (requestParameters != null && !string.IsNullOrWhiteSpace(requestParameters.RequestType))
                {
                    // Look up an existing flow if possible.
                    var flowReferenceToRemoveFromCacheWhenComplete = default(string);
                    var flow = default(AuthFlow);
                    if (requestParameters.RequestType == Constants.RequestTypes.DeviceToken && !string.IsNullOrWhiteSpace(requestParameters.DeviceCode))
                    {
                        flow = await this.authFlowCacheProvider.GetAuthFlowAsync(requestParameters.DeviceCode);
                        flowReferenceToRemoveFromCacheWhenComplete = (flow == null ? null : requestParameters.DeviceCode);
                    }
                    if (flow == null)
                    {
                        flow = new AuthFlow { UserId = this.User.GetUserId(), RequestType = requestParameters.RequestType };
                        this.telemetryClient.TrackEvent("AuthFlow.Initiated", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", flow.RequestType } });
                    }
                    model.Flow = flow;
                    model.RequestParameters = requestParameters;
                    var request = flow.AddRequest(requestParameters);
                    this.telemetryClient.TrackEvent("AuthRequest.Sent", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", request.Parameters?.RequestType } });

                    // Determine which flow to execute.
                    if (requestParameters.RequestType == Constants.RequestTypes.OpenIdConnect || requestParameters.RequestType == Constants.RequestTypes.Implicit || requestParameters.RequestType == Constants.RequestTypes.AuthorizationCode)
                    {
                        request.RequestedRedirectUrl = GetAuthorizationEndpointRequestUrl(request);
                        await this.authFlowCacheProvider.SetAuthFlowAsync(flow.Id, flow);
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
                        if (string.IsNullOrWhiteSpace(request.Response.DeviceCode))
                        {
                            flow.IsComplete = true;
                        }
                        else
                        {
                            // This is just the first part of the flow, the device token still has to be requested.
                            // Keep the flow in cache until the device code is exchanged for the token.
                            await this.authFlowCacheProvider.SetAuthFlowAsync(request.Response.DeviceCode, flow);
                            flow.IsComplete = false;
                        }
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.DeviceToken)
                    {
                        request.Response = await HandleDeviceTokenRequestAsync(requestParameters);
                        if (string.IsNullOrWhiteSpace(request.Response.Error))
                        {
                            flow.IsComplete = true;
                        }
                        else
                        {
                            // An error occurred so the flow is not complete yet, save changes.
                            await this.authFlowCacheProvider.SetAuthFlowAsync(requestParameters.DeviceCode, flow);
                        }
                    }
                    else if (requestParameters.RequestType == Constants.RequestTypes.ResourceOwnerPasswordCredentials)
                    {
                        request.Response = await HandleResourceOwnerPasswordCredentialsRequestAsync(requestParameters);
                        flow.IsComplete = true;
                    }

                    if (request.Response != null)
                    {
                        this.telemetryClient.TrackEvent("AuthResponse.Received", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", request.Parameters?.RequestType } }, new Dictionary<string, double> { { "TimeTakenMs", (request.Response.TimeCreated - request.TimeCreated).TotalMilliseconds } });
                    }
                    if (flow.IsComplete)
                    {
                        flow.TimeCompleted = DateTimeOffset.UtcNow;
                        this.telemetryClient.TrackEvent("AuthFlow.Completed", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", flow.RequestType } }, new Dictionary<string, double> { { "TimeTakenMs", (flow.TimeCompleted.Value - flow.TimeCreated).TotalMilliseconds } });
                        if (flow.IsComplete && !string.IsNullOrEmpty(flowReferenceToRemoveFromCacheWhenComplete))
                        {
                            await this.authFlowCacheProvider.RemoveAuthFlowAsync(flowReferenceToRemoveFromCacheWhenComplete);
                        }
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
            GuardNotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Client Credentials Grant.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Client Credentials Grant.");
            GuardNotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 Client Credentials Grant.");
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                Scope = requestParameters.Scope,
                Parameters = requestParameters.GetAdditionalParameters()
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private async Task<AuthResponse> HandleRefreshTokenRequestAsync(AuthRequestParameters requestParameters)
        {
            GuardNotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Refresh Token Grant.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Refresh Token Grant.");
            GuardNotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 Refresh Token Grant.");
            GuardNotEmpty(requestParameters.RefreshToken, "The refresh token must be specified for an OAuth 2.0 Refresh Token Grant.");
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                Scope = requestParameters.Scope,
                RefreshToken = requestParameters.RefreshToken,
                Parameters = requestParameters.GetAdditionalParameters()
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private async Task<AuthResponse> HandleDeviceCodeRequestAsync(AuthRequestParameters requestParameters)
        {
            GuardNotEmpty(requestParameters.DeviceCodeEndpoint, "The device code endpoint must be specified for an OAuth 2.0 Device Authorization Grant.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Device Authorization Grant.");
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestDeviceAuthorizationAsync(new DeviceAuthorizationRequest
            {
                Address = requestParameters.DeviceCodeEndpoint,
                ClientId = requestParameters.ClientId,
                Scope = requestParameters.Scope,
                Parameters = requestParameters.GetAdditionalParameters()
            });
            return AuthResponse.FromDeviceCodeResponse(response);
        }

        private async Task<AuthResponse> HandleDeviceTokenRequestAsync(AuthRequestParameters requestParameters)
        {
            GuardNotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Device Authorization Grant.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Device Authorization Grant.");
            GuardNotEmpty(requestParameters.DeviceCode, "The device code must be specified for an OAuth 2.0 Device Authorization Grant.");
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestDeviceTokenAsync(new DeviceTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                DeviceCode = requestParameters.DeviceCode,
                Parameters = requestParameters.GetAdditionalParameters()
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private async Task<AuthResponse> HandleResourceOwnerPasswordCredentialsRequestAsync(AuthRequestParameters requestParameters)
        {
            GuardNotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            GuardNotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            GuardNotEmpty(requestParameters.UserName, "The user name must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            GuardNotEmpty(requestParameters.Password, "The password must be specified for an OAuth 2.0 Resource Owner Password Credentials Grant.");
            var client = this.httpClientFactory.CreateClient();
            var response = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = requestParameters.TokenEndpoint,
                ClientId = requestParameters.ClientId,
                ClientSecret = requestParameters.ClientSecret,
                Scope = requestParameters.Scope,
                UserName = requestParameters.UserName,
                Password = requestParameters.Password,
                Parameters = requestParameters.GetAdditionalParameters()
            });
            return AuthResponse.FromTokenResponse(response);
        }

        private string GetAuthorizationEndpointRequestUrl(AuthRequest request)
        {
            GuardNotEmpty(request.Parameters.AuthorizationEndpoint, "The authorization endpoint must be specified for an authorization endpoint request.");
            GuardNotEmpty(request.Parameters.ClientId, "The client id must be specified for an authorization endpoint request.");
            GuardNotEmpty(request.Parameters.RedirectUri, "The redirect uri must be specified for an authorization endpoint request.");
            var urlBuilder = new RequestUrl(request.Parameters.AuthorizationEndpoint);
            return urlBuilder.CreateAuthorizeUrl(
                clientId: request.Parameters.ClientId,
                responseType: request.Parameters.ResponseType,
                scope: request.Parameters.Scope,
                redirectUri: request.Parameters.RedirectUri,
                responseMode: request.Parameters.ResponseMode,
                nonce: request.Nonce,
                state: request.State,
                extra: request.Parameters.GetAdditionalParameters()
            );
        }

        private async Task<AuthResponse> HandleAuthorizationCodeResponseAsync(AuthRequestParameters requestParameters)
        {
            GuardNotEmpty(requestParameters.TokenEndpoint, "The token endpoint must be specified for an OAuth 2.0 Authorization Code Grant.");
            GuardNotEmpty(requestParameters.ClientId, "The client id must be specified for an OAuth 2.0 Authorization Code Grant.");
            GuardNotEmpty(requestParameters.ClientSecret, "The client credentials must be specified for an OAuth 2.0 Authorization Code Grant.");
            GuardNotEmpty(requestParameters.AuthorizationCode, "The authorization code must be specified for an OAuth 2.0 Authorization Code Grant.");
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
                RedirectUri = requestParameters.RedirectUri,
                Parameters = requestParameters.GetAdditionalParameters()
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